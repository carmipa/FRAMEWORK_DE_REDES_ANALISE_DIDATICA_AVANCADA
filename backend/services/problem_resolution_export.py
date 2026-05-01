import ipaddress
from datetime import datetime
from io import BytesIO
import zipfile

from backend.common import EntradaInvalidaError, log_event
from backend.services.problem_resolution_normalization import normalize_cli_identifier


def router_export_filename(location_name):
    normalized = normalize_cli_identifier(location_name, "ROTEADOR")
    return f"R-{normalized}.txt"


def generate_router_lab_blocks(scenario):
    lan_blocks = scenario.get("lan_blocks") or []
    wan_links = scenario.get("wan_links") or []
    locations_by_key = {item["location_key"]: item for item in lan_blocks}
    blocks = {}

    for location in lan_blocks:
        location_key = location["location_key"]
        location_name = location["location_name"]
        lan_network = ipaddress.ip_network(f"{location['network']}/{location['prefix']}", strict=False)
        gateway_ip = ipaddress.ip_address(location["gateway"])
        reserved_end = gateway_ip + 9
        max_host_for_reserve = lan_network.broadcast_address - 1
        if reserved_end > max_host_for_reserve:
            reserved_end = max_host_for_reserve

        block_lines = [
            "enable",
            "configure terminal",
            f"hostname {location['router_name']}",
            "no ip domain-lookup",
            "!",
            "! Ajuste de console para evitar interrupções de log durante colagem",
            "line con 0",
            " logging synchronous",
            "exit",
            "!",
            "interface GigabitEthernet0/0",
            f" description LAN_{location['cli_id']}",
            f" ip address {location['gateway']} {location['netmask']}",
            " no shutdown",
            "!",
        ]

        serial_idx = 0
        rip_networks = {location["network"]}
        for link in wan_links:
            if location_key not in link.get("ips", {}):
                continue
            endpoint_a, endpoint_b = link["endpoints"]
            neighbor_key = endpoint_b if endpoint_a == location_key else endpoint_a
            neighbor = locations_by_key.get(neighbor_key)
            neighbor_cli = normalize_cli_identifier(
                neighbor.get("location_name") if neighbor else neighbor_key,
                "DESTINO",
            )
            block_lines.extend(
                [
                    f"interface Serial0/3/{serial_idx}",
                    f" description LINK_PARA_{neighbor_cli}",
                    f" ip address {link['ips'][location_key]} {link['netmask']}",
                    " no shutdown",
                    "!",
                ]
            )
            serial_idx += 1
            rip_networks.add(link["network"])

        block_lines.extend(
            [
                "! Configuração de serviço DHCP",
                f"ip dhcp excluded-address {gateway_ip} {reserved_end}",
                f"ip dhcp pool LAN_{location['cli_id']}",
                f" network {location['network']} {location['netmask']}",
                f" default-router {location['gateway']}",
                " dns-server 8.8.8.8",
                "!",
                "! Roteamento RIPv2",
                "router rip",
                " version 2",
                " no auto-summary",
            ]
        )
        for net in sorted(rip_networks, key=lambda value: tuple(int(part) for part in value.split("."))):
            block_lines.append(f" network {net}")

        block_lines.extend(
            [
                "!",
                "end",
                "write memory",
                "!",
                "! Comandos de verificação (executar após aplicar o bloco):",
                "! show ip interface brief",
                "! show ip route rip",
                "! show running-config | section interface",
            ]
        )
        blocks[location_name] = "\n".join(block_lines).strip()
    return blocks


def generate_packet_tracer_script(scenario):
    if not scenario:
        log_event("warning", "problem_export_txt", status="empty_scenario")
        raise EntradaInvalidaError("Cenário vazio para exportação.")

    lan_blocks = scenario.get("lan_blocks") or []
    wan_links = scenario.get("wan_links") or []
    if not lan_blocks:
        log_event("warning", "problem_export_txt", status="empty_locations")
        raise EntradaInvalidaError("Não há localidades no cenário para exportação.")

    lines = [
        "!",
        "! SCRIPT DE PROVISIONAMENTO - FRAMEWORK DE REDES ANALISE DIDATICA AVANCADA",
        "!",
        f"! Rede base: {scenario.get('base_network', '-')}",
        f"! Topologia WAN: {(scenario.get('topology_type') or '-').upper()}",
        f"! Total de localidades: {scenario.get('total_locations', 0)}",
        "!",
        "! MODO DE USO:",
        "! 1) Abra o CLI do roteador alvo no Packet Tracer.",
        "! 2) Cole somente o bloco correspondente a esse roteador.",
        "! 3) Repita para todos os roteadores do cenário.",
        "!",
    ]

    router_blocks = generate_router_lab_blocks(scenario)
    for location in lan_blocks:
        location_name = location["location_name"]
        lines.extend(
            [
                "!" + "=" * 78,
                f"! ROTEADOR: {location_name.upper()}",
                "!" + "=" * 78,
                router_blocks[location_name],
                "!",
            ]
        )

    content = "\n".join(lines).strip() + "\n"
    log_event(
        "info",
        "problem_export_txt",
        status="ok",
        routers_count=len(lan_blocks),
        wan_links_count=len(wan_links),
    )
    return content


def generate_packet_tracer_zip_buffer(scenario):
    if not scenario:
        log_event("warning", "problem_export_zip", status="empty_scenario")
        raise EntradaInvalidaError("Cenário vazio para exportação.")
    lan_blocks = scenario.get("lan_blocks") or []
    if not lan_blocks:
        log_event("warning", "problem_export_zip", status="empty_locations")
        raise EntradaInvalidaError("Não há localidades no cenário para exportação.")

    consolidated_script = generate_packet_tracer_script(scenario)
    router_blocks = generate_router_lab_blocks(scenario)
    topology_mermaid = scenario.get("topology_mermaid", "")
    readme = (
        "INSTRUCOES DE USO DO LABORATORIO\n"
        "===============================\n"
        "1. Abra o Cisco Packet Tracer.\n"
        "2. Monte a topologia física conforme o arquivo LAB_TOPOLOGY.mermaid.\n"
        "3. Para cada roteador, abra o CLI e cole o conteúdo do arquivo em configs_individuais/.\n"
        "4. Aguarde a convergência do RIP (aprox. 30s).\n"
        "5. Valide com: show ip interface brief e show ip route rip.\n"
    )

    memory_file = BytesIO()
    with zipfile.ZipFile(memory_file, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("config_packet_tracer_consolidado.txt", consolidated_script)
        for location_name, block in router_blocks.items():
            filename = router_export_filename(location_name)
            zf.writestr(f"configs_individuais/{filename}", block + "\n")
        zf.writestr("LAB_TOPOLOGY.mermaid", topology_mermaid)
        zf.writestr("README_LAB.txt", readme)

    memory_file.seek(0)
    log_event(
        "info",
        "problem_export_zip",
        status="ok",
        routers_count=len(lan_blocks),
        files_written=len(router_blocks) + 3,
    )
    return memory_file


def generate_entrega_relatorio_txt(scenario):
    """Relatório textual único com resumo, tabelas LAN/WAN, topologia Mermaid e CLI."""
    if not scenario:
        log_event("warning", "problem_export_entrega", status="empty_scenario")
        raise EntradaInvalidaError("Cenário vazio para exportação.")

    lan_blocks = scenario.get("lan_blocks") or []
    if not lan_blocks:
        log_event("warning", "problem_export_entrega", status="empty_locations")
        raise EntradaInvalidaError("Não há localidades no cenário para exportação.")

    wan_links = scenario.get("wan_links") or []
    topology_type = (scenario.get("topology_type") or "-").upper()
    wan_prefix = scenario.get("wan_prefix")
    lines = [
        "=" * 78,
        "DOCUMENTACAO DO CENARIO DE REDE — EXPORTACAO AUTOMATICA",
        "=" * 78,
        f"Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "1) RESUMO DO PLANEJAMENTO",
        "-" * 78,
        f"Rede base:           {scenario.get('base_network', '-')}",
        f"Hosts solicitados:   {scenario.get('total_hosts_requested', '-')}",
        f"Localidades:         {scenario.get('total_locations', '-')}",
        f"Topologia WAN:       {topology_type}",
        f"Prefixo WAN:         /{wan_prefix}" if wan_prefix is not None else "Prefixo WAN:         -",
        "",
        "2) LANs (VLSM)",
        "-" * 78,
        f"{'Local':<18} {'Rede':<22} {'Mascara':<18} {'Wildcard':<14} {'Gateway':<14}",
        f"{'-' * 18} {'-' * 22} {'-' * 18} {'-' * 14} {'-' * 14}",
    ]

    for lan in lan_blocks:
        rede = f"{lan['network']}/{lan['prefix']}"
        lines.append(
            f"{lan['location_name']:<18} {rede:<22} {lan['netmask']:<18} "
            f"{lan['wildcard']:<14} {lan['gateway']:<14}"
        )
        faixa = f"{lan['host_range_start']} - {lan['host_range_end']}"
        neces = f"{lan['hosts_required']} / {lan['hosts_supported']}"
        lines.append(f"    Faixa de hosts: {faixa}")
        lines.append(f"    Necessario / Suportado: {neces}")
        lines.append("")

    lines.extend(
        [
            "3) Links WAN",
            "-" * 78,
        ]
    )
    if not wan_links:
        lines.append("(nenhum link WAN neste cenario)")
        lines.append("")
    else:
        for link in wan_links:
            a, b = link["endpoints"]
            ips = link.get("ips") or {}
            lines.append(
                f"{link['name']}: {link['network']}/{link['prefix']} "
                f"(mascara {link['netmask']})"
            )
            lines.append(f"    {a} -> {ips.get(a, '-')}")
            lines.append(f"    {b} -> {ips.get(b, '-')}")
            lines.append("")

    lines.extend(
        [
            "4) Topologia Mermaid (copiar para editores que renderizam Mermaid)",
            "-" * 78,
            (scenario.get("topology_mermaid") or "").strip(),
            "",
            "5) Sequencia sugerida no Packet Tracer",
            "-" * 78,
        ]
    )
    for index, step in enumerate(scenario.get("packet_tracer_steps") or [], start=1):
        lines.append(f"{index}. {step}")
    lines.append("")

    router_commands = scenario.get("router_commands") or {}
    lines.extend(
        [
            "6) Comandos Cisco CLI por roteador",
            "-" * 78,
        ]
    )
    for router_name in sorted(router_commands.keys()):
        lines.append("")
        lines.append("!" + "=" * 77)
        lines.append(f"! ROTEADOR: {router_name.upper()}")
        lines.append("!" + "=" * 77)
        lines.append((router_commands[router_name] or "").strip())
        lines.append("")

    lines.extend(
        [
            "=" * 78,
            "FIM DO RELATORIO",
            "=" * 78,
            "",
        ]
    )

    content = "\n".join(lines).strip() + "\n"
    log_event(
        "info",
        "problem_export_entrega",
        status="ok",
        routers_count=len(router_commands),
        wan_links_count=len(wan_links),
    )
    return content
