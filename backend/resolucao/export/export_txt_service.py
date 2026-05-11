"""Geração de exportações em texto (CLI consolidado, relatório entrega)."""

import ipaddress
from datetime import datetime

from backend.core.exceptions import EntradaInvalidaError
from backend.core.logging import log_event
from backend.resolucao.vlsm.vlsm_normalization import normalize_cli_identifier

# Padrão didático do laboratório (Cisco Packet Tracer)
PACKET_TRACER_ROUTER_MODEL = "2911"
PACKET_TRACER_SWITCH_MODEL = "2960"


def packet_tracer_hardware_note_cli_lines():
    """Linhas comentadas para o topo dos scripts .txt de CLI."""
    return [
        "! OBSERVACAO — Equipamento no Cisco Packet Tracer (padrao deste laboratorio):",
        f"! Roteadores: Cisco {PACKET_TRACER_ROUTER_MODEL}",
        f"! Switches: Cisco {PACKET_TRACER_SWITCH_MODEL}",
        "! Ajuste apenas se o enunciado da disciplina indicar outro modelo.",
    ]


def packet_tracer_hardware_note_plain_block():
    """Bloco de texto para relatório de entrega e README do ZIP."""
    return (
        "OBSERVACAO — Equipamento no Cisco Packet Tracer\n"
        f"  Padrao deste laboratorio: roteadores Cisco {PACKET_TRACER_ROUTER_MODEL} "
        f"e switches Cisco {PACKET_TRACER_SWITCH_MODEL}.\n"
        "  Os comandos CLI assumem interfaces típicas desses modelos "
        "(ex.: GigabitEthernet0/0, Serial0/3/n no roteador).\n"
        "\n"
    )


def router_export_filename(location_name):
    normalized = normalize_cli_identifier(location_name, "ROTEADOR")
    return f"R-{normalized}.txt"


def _require_export_scenario(scenario, event_name):
    if not scenario:
        log_event("warning", event_name, status="empty_scenario")
        raise EntradaInvalidaError("Cenário vazio para exportação.")
    lan_blocks = scenario.get("lan_blocks") or []
    if not lan_blocks:
        log_event("warning", event_name, status="empty_locations")
        raise EntradaInvalidaError(
            "Não há localidades no cenário para exportação."
        )
    wan_links = scenario.get("wan_links") or []
    return lan_blocks, wan_links


def build_pt_router_tables(scenario):
    """
    Tabela de interfaces por roteador (IP + máscara) para montagem no Packet Tracer.
    Espelha a mesma ordem de interfaces do script CLI (Gi0/0 + Serial0/3/n).
    Retorna lista ordenada: um item por localidade com hostname e linhas da tabela.
    """
    lan_blocks = scenario.get("lan_blocks") or []
    wan_links = scenario.get("wan_links") or []
    locations_by_key = {item["location_key"]: item for item in lan_blocks}
    tables: list[dict[str, object]] = []

    for location in lan_blocks:
        location_key = location["location_key"]
        location_name = location["location_name"]
        rows: list[dict[str, str]] = []
        rows.append(
            {
                "interface": "GigabitEthernet0/0",
                "ip": location["gateway"],
                "mask": location["netmask"],
                "cidr": f"/{location['prefix']}",
                "role": "LAN",
                "description": f"Gateway da LAN {location_name}",
            }
        )
        serial_idx = 0
        for link in wan_links:
            if location_key not in link.get("ips", {}):
                continue
            endpoint_a, endpoint_b = link["endpoints"]
            neighbor_key = (
                endpoint_b if endpoint_a == location_key else endpoint_a
            )
            neighbor = locations_by_key.get(neighbor_key)
            neighbor_name = (
                neighbor["location_name"] if neighbor else neighbor_key
            )
            rows.append(
                {
                    "interface": f"Serial0/3/{serial_idx}",
                    "ip": link["ips"][location_key],
                    "mask": link["netmask"],
                    "cidr": f"/{link['prefix']}",
                    "role": "WAN",
                    "description": f"{link['name']} → vizinho {neighbor_name}",
                }
            )
            serial_idx += 1
        tables.append(
            {
                "router_name": location["router_name"],
                "location_name": location_name,
                "rows": rows,
            }
        )
    return tables


def generate_router_lab_blocks(scenario):
    lan_blocks = scenario.get("lan_blocks") or []
    wan_links = scenario.get("wan_links") or []
    eigrp_as = scenario.get("eigrp_as")
    try:
        eigrp_as_i = int(eigrp_as) if eigrp_as is not None else 71
    except (TypeError, ValueError):
        eigrp_as_i = 71
    if not (1 <= eigrp_as_i <= 65535):
        eigrp_as_i = 71
    locations_by_key = {item["location_key"]: item for item in lan_blocks}
    blocks = {}

    for location in lan_blocks:
        location_key = location["location_key"]
        location_name = location["location_name"]
        lan_network = ipaddress.ip_network(
            f"{location['network']}/{location['prefix']}", strict=False
        )
        gateway_ip = ipaddress.ip_address(location["gateway"])
        reserved_end = gateway_ip + 9
        max_host_for_reserve = lan_network.broadcast_address - 1
        if reserved_end > max_host_for_reserve:
            reserved_end = max_host_for_reserve

        block_lines = [
            *packet_tracer_hardware_note_cli_lines(),
            "!",
            "enable",
            "configure terminal",
            f"hostname {location['router_name']}",
            "no ip domain-lookup",
            "!",
            (
                "! Ajuste de console para evitar interrupções de log "
                "durante colagem"
            ),
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
        eigrp_pairs = [(location["network"], location["wildcard"])]
        for link in wan_links:
            if location_key not in link.get("ips", {}):
                continue
            endpoint_a, endpoint_b = link["endpoints"]
            neighbor_key = (
                endpoint_b if endpoint_a == location_key else endpoint_a
            )
            neighbor = locations_by_key.get(neighbor_key)
            neighbor_cli = normalize_cli_identifier(
                neighbor.get("location_name") if neighbor else neighbor_key,
                "DESTINO",
            )
            block_lines.extend(
                [
                    f"interface Serial0/3/{serial_idx}",
                    f" description LINK_PARA_{neighbor_cli}",
                    (
                        f" ip address {link['ips'][location_key]} "
                        f"{link['netmask']}"
                    ),
                    " no shutdown",
                    "!",
                ]
            )
            serial_idx += 1
            eigrp_pairs.append((link["network"], link["wildcard"]))

        block_lines.extend(
            [
                "! Configuração de serviço DHCP",
                f"ip dhcp excluded-address {gateway_ip} {reserved_end}",
                f"ip dhcp pool LAN_{location['cli_id']}",
                f" network {location['network']} {location['netmask']}",
                f" default-router {location['gateway']}",
                " dns-server 8.8.8.8",
                "!",
                "! Roteamento EIGRP",
                f"router eigrp {eigrp_as_i}",
                " no auto-summary",
            ]
        )

        def _pair_sort_key(pair):
            net, _wild = pair
            return tuple(int(part) for part in net.split("."))

        seen_pairs = set()
        for net, wild in sorted(eigrp_pairs, key=_pair_sort_key):
            key = (net, wild)
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            block_lines.append(f" network {net} {wild}")

        block_lines.extend(
            [
                "!",
                "end",
                "write memory",
                "!",
                "! Comandos de verificação (executar após aplicar o bloco):",
                "! show ip interface brief",
                "! show ip eigrp neighbors",
                "! show ip route eigrp",
                "! show running-config | section interface",
            ]
        )
        blocks[location_name] = "\n".join(block_lines).strip()
    return blocks


def generate_packet_tracer_script(scenario):
    lan_blocks, wan_links = _require_export_scenario(scenario, "problem_export_txt")

    lines = [
        "!",
        (
            "! SCRIPT DE PROVISIONAMENTO - FRAMEWORK DE REDES "
            "ANALISE DIDATICA AVANCADA"
        ),
        "!",
        *packet_tracer_hardware_note_cli_lines(),
        "!",
        f"! Rede base: {scenario.get('base_network', '-')}",
        f"! Topologia WAN: {(scenario.get('topology_type') or '-').upper()}",
        f"! Prefixo WAN: /{scenario.get('wan_prefix', '-')}",
        f"! AS EIGRP: {scenario.get('eigrp_as', '-')}",
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


def generate_entrega_relatorio_txt(scenario):
    """Relatório textual único com resumo, tabelas LAN/WAN, Mermaid e CLI."""
    lan_blocks, wan_links = _require_export_scenario(
        scenario, "problem_export_entrega"
    )
    topology_type = (scenario.get("topology_type") or "-").upper()
    wan_prefix = scenario.get("wan_prefix")
    lines = [
        "=" * 78,
        "DOCUMENTACAO DO CENARIO DE REDE — EXPORTACAO AUTOMATICA",
        "=" * 78,
        f"Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        packet_tracer_hardware_note_plain_block(),
        "1) RESUMO DO PLANEJAMENTO",
        "-" * 78,
        f"Rede base:           {scenario.get('base_network', '-')}",
        f"Hosts solicitados:   {scenario.get('total_hosts_requested', '-')}",
        f"Hosts suportados:    {scenario.get('total_hosts_supported', '-')}",
        f"Eficiencia geral:    {scenario.get('overall_efficiency_pct', '-')}%",
        f"Uso da rede base:    {scenario.get('used_address_pct', '-')}% (livre: {scenario.get('free_address_pct', '-')}%)",
        f"Endereco livre:      {scenario.get('free_addresses', '-')}",
        f"Prefixo base atual:  /{scenario.get('base_network_prefix', '-')}",
        f"Prefixo sugerido:    /{scenario.get('suggested_base_prefix', '-')}",
        f"Localidades:         {scenario.get('total_locations', '-')}",
        f"Topologia WAN:       {topology_type}",
        (
            f"Prefixo WAN:         /{wan_prefix}"
            if wan_prefix is not None
            else "Prefixo WAN:         -"
        ),
        f"AS EIGRP:            {scenario.get('eigrp_as', '-')}",
        "",
        "2) LANs (VLSM)",
        "-" * 78,
        (
            f"{'Local':<18} {'Rede':<22} {'Mascara':<18} "
            f"{'Wildcard':<14} {'Gateway':<14} {'Ef(%)':<8}"
        ),
        (
            f"{'-' * 18} {'-' * 22} {'-' * 18} "
            f"{'-' * 14} {'-' * 14} {'-' * 8}"
        ),
    ]

    for lan in lan_blocks:
        rede = f"{lan['network']}/{lan['prefix']}"
        lines.append(
            f"{lan['location_name']:<18} {rede:<22} {lan['netmask']:<18} "
            f"{lan['wildcard']:<14} {lan['gateway']:<14} {str(lan.get('efficiency_pct', 0)):<8}"
        )
        faixa = f"{lan['host_range_start']} - {lan['host_range_end']}"
        neces = f"{lan['hosts_required']} / {lan['hosts_supported']}"
        lines.append(f"    Faixa de hosts: {faixa}")
        lines.append(f"    Necessario / Suportado: {neces}")
        lines.append("")

    lines.extend(
        [
            "",
            "2.1) EXPLICACAO DIDATICA DO CALCULO VLSM",
            "-" * 78,
        ]
    )
    for lan in lan_blocks:
        lines.append(
            f"{lan['location_name']}: {lan['hosts_required']} hosts -> /{lan.get('calculated_prefix', lan['prefix'])}"
        )
        lines.append(
            f"    Necessarios c/ rede+broadcast: {lan.get('hosts_needed_total', '-')}"
        )
        lines.append(f"    Bits de host: {lan.get('host_bits', '-')}")
        lines.append(
            f"    Alocacao: {lan['network']}/{lan['prefix']} ({lan['hosts_supported']} hosts suportados)"
        )
        lines.append(f"    Eficiencia: {lan.get('efficiency_pct', 0)}%")
        lines.append("")

    lines.extend(
        [
            "2.2) COMPARACAO DE TOPOLOGIA (RING vs MESH)",
            "-" * 78,
        ]
    )
    top = scenario.get("topology_insights") or {}
    lines.extend(
        [
            f"Recomendacao: {str(top.get('recommended', '-')).upper()}",
            f"Justificativa: {top.get('recommended_reason', '-')}",
            f"Selecionada pelo usuario: {str(scenario.get('topology_type', '-')).upper()}",
            f"Nota: {top.get('selected_note', '-')}",
            "",
            f"Ring -> links: {top.get('ring_links', '-')} | custo estimado: {top.get('ring_cost', '-')}",
            f"Mesh -> links: {top.get('mesh_links', '-')} | custo estimado: {top.get('mesh_cost', '-')}",
            "",
            "2.3) PROJECAO DE CRESCIMENTO",
            "-" * 78,
        ]
    )
    for item in scenario.get("growth_forecast") or []:
        lines.append(f"{item.get('location_name', '-')}: atual /{item.get('current_prefix', '-')}")
        for g in item.get("scenarios") or []:
            status = "OK" if g.get("fits_current") else "AJUSTAR"
            lines.append(
                f"    +{g.get('factor_label', '-')} -> {g.get('future_hosts', '-')} hosts, /{g.get('required_prefix', '-')} ({status})"
            )
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
            "",
            "3.1) Interfaces por roteador (Packet Tracer)",
            "-" * 78,
            (
                "Valores para configurar em cada roteador: LAN em GigabitEthernet0/0; "
                "WAN em Serial0/3/n na mesma ordem do script CLI."
            ),
            "",
        ]
    )
    for block in build_pt_router_tables(scenario):
        lines.append(f"{block['router_name']} — {block['location_name']}")
        lines.append(
            f"{'Interface':<22} {'IP':<16} {'Mascara':<16} {'CIDR':<8} {'Papel':<6} Descricao"
        )
        lines.append("-" * 78)
        for row in block["rows"]:
            lines.append(
                f"{row['interface']:<22} {row['ip']:<16} {row['mask']:<16} "
                f"{row['cidr']:<8} {row['role']:<6} {row['description']}"
            )
        lines.append("")
    lines.append(
        "Hosts (PCs): DHCP no roteador; gateway = IP da linha LAN (coluna IP em GigabitEthernet0/0)."
    )
    lines.append("")

    lines.extend(
        [
            (
                "4) Topologia Mermaid "
                "(copiar para editores que renderizam Mermaid)"
            ),
            "-" * 78,
            (scenario.get("topology_mermaid") or "").strip(),
            "",
            "5) Sequencia sugerida no Packet Tracer",
            "-" * 78,
        ]
    )
    steps = scenario.get("packet_tracer_steps") or []
    for index, step in enumerate(steps, start=1):
        lines.append(f"{index}. {step}")
    lines.append("")
    lines.append("5.1) Checklist final de validacao")
    lines.append("-" * 78)
    for item in scenario.get("packet_tracer_checklist") or []:
        lines.append(f"[ ] {item}")
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
