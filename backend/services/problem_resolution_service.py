import ipaddress
from io import BytesIO
import zipfile

from backend.common import EntradaInvalidaError


DEFAULT_LOCATIONS = [
    {"name": "Matriz", "hosts": 420},
    {"name": "Filial I", "hosts": 400},
    {"name": "Filial II", "hosts": 380},
]


def _parse_positive_int(value, field_label):
    txt = (value or "").strip()
    if not txt:
        raise EntradaInvalidaError(f"{field_label} deve ser informado.")
    if not txt.isdigit():
        raise EntradaInvalidaError(f"{field_label} deve ser um numero inteiro positivo.")
    number = int(txt)
    if number <= 0:
        raise EntradaInvalidaError(f"{field_label} deve ser maior que zero.")
    return number


def _normalize_cli_identifier(value, fallback="SITE"):
    txt = (value or "").strip().upper()
    clean = "".join(ch if ch.isalnum() else "_" for ch in txt)
    clean = "_".join(part for part in clean.split("_") if part)
    return clean or fallback


def normalize_locations_input(locations_input):
    normalized = []
    for index, raw in enumerate(locations_input, start=1):
        name = (raw.get("name") or "").strip()
        if not name:
            raise EntradaInvalidaError(f"Nome da localidade #{index} deve ser informado.")
        hosts = _parse_positive_int(raw.get("hosts"), f"Hosts de {name}")
        normalized.append(
            {
                "location_key": f"loc_{index}",
                "location_name": name,
                "hosts_required": hosts,
                "router_name": f"R-{_normalize_cli_identifier(name, f'SITE{index}')}",
                "cli_id": _normalize_cli_identifier(name, f"SITE{index}"),
            }
        )
    if not normalized:
        raise EntradaInvalidaError("Informe ao menos uma localidade.")
    return normalized


def _required_prefix_for_hosts(host_count):
    needed = host_count + 2
    host_bits = (needed - 1).bit_length()
    return 32 - host_bits


def _iter_free_subnets(base_network, prefix):
    for subnet in base_network.subnets(new_prefix=prefix):
        yield subnet


def _find_next_available_subnet(base_network, prefix, used_subnets):
    for candidate in _iter_free_subnets(base_network, prefix):
        if all(not candidate.overlaps(used) for used in used_subnets):
            return candidate
    raise EntradaInvalidaError(
        "Nao ha espaco suficiente na rede base para acomodar todas as LANs e links WAN."
    )


def _hosts_range(network):
    if network.num_addresses <= 2:
        return (str(network.network_address), str(network.broadcast_address))
    first_host = network.network_address + 1
    last_host = network.broadcast_address - 1
    return (str(first_host), str(last_host))


def _build_lan_blocks(base_network, locations):
    ordered = sorted(locations, key=lambda item: item["hosts_required"], reverse=True)
    used = []
    for location in ordered:
        hosts = location["hosts_required"]
        prefix = _required_prefix_for_hosts(hosts)
        if prefix < base_network.prefixlen:
            raise EntradaInvalidaError(
                f"A LAN {location['location_name']} exige /{prefix}, menor que a rede base /{base_network.prefixlen}."
            )
        subnet = _find_next_available_subnet(base_network, prefix, used)
        used.append(subnet)
        first_host, last_host = _hosts_range(subnet)
        location["hosts_supported"] = max(subnet.num_addresses - 2, 0)
        location["network"] = str(subnet.network_address)
        location["prefix"] = subnet.prefixlen
        location["netmask"] = str(subnet.netmask)
        location["wildcard"] = str(subnet.hostmask)
        location["gateway"] = str(subnet.network_address + 1)
        location["host_range_start"] = first_host
        location["host_range_end"] = last_host
        location["_network_obj"] = subnet
    return locations, used


def _build_wan_pairs(location_keys, topology_type):
    total = len(location_keys)
    if total <= 1:
        return []
    if topology_type == "ring":
        if total == 2:
            return [(location_keys[0], location_keys[1])]
        return [
            (location_keys[index], location_keys[(index + 1) % total])
            for index in range(total)
        ]
    if topology_type == "mesh":
        pairs = []
        for left_index in range(total):
            for right_index in range(left_index + 1, total):
                pairs.append((location_keys[left_index], location_keys[right_index]))
        return pairs
    raise EntradaInvalidaError("Topologia WAN invalida. Use 'ring' ou 'mesh'.")


def _build_wan_links(base_network, used_subnets, location_keys, topology_type):
    wan_pairs = _build_wan_pairs(location_keys, topology_type)
    links = []
    for index, pair in enumerate(wan_pairs, start=1):
        subnet = _find_next_available_subnet(base_network, 30, used_subnets)
        used_subnets.append(subnet)
        hosts = list(subnet.hosts())
        links.append(
            {
                "name": f"WAN-{index}",
                "endpoints": pair,
                "network": str(subnet.network_address),
                "prefix": subnet.prefixlen,
                "netmask": str(subnet.netmask),
                "wildcard": str(subnet.hostmask),
                "ips": {
                    pair[0]: str(hosts[0]),
                    pair[1]: str(hosts[1]),
                },
            }
        )
    return links


def _router_commands(location, wan_links):
    location_key = location["location_key"]
    lines = [
        f"hostname {location['router_name']}",
        "no ip domain-lookup",
        "!",
        "interface GigabitEthernet0/0",
        f" ip address {location['gateway']} {location['netmask']}",
        " no shutdown",
        "!",
    ]

    serial_idx = 0
    for link in wan_links:
        if location_key not in link["ips"]:
            continue
        lines.extend(
            [
                f"interface Serial0/3/{serial_idx}",
                f" ip address {link['ips'][location_key]} {link['netmask']}",
                " no shutdown",
                "!",
            ]
        )
        serial_idx += 1

    lines.extend(
        [
            f"ip dhcp excluded-address {location['gateway']} {location['gateway']}",
            f"ip dhcp pool LAN_{location['cli_id']}",
            f" network {location['network']} {location['netmask']}",
            f" default-router {location['gateway']}",
            " dns-server 8.8.8.8",
            "!",
            "router rip",
            " version 2",
            " no auto-summary",
            f" network {location['network']}",
        ]
    )
    for link in wan_links:
        if location_key in link["ips"]:
            lines.append(f" network {link['network']}")
    lines.extend(["!", "end", "write memory"])
    return "\n".join(lines)


def _mermaid_topology(locations, wan_links):
    lines = ["graph LR"]
    name_map = {}
    for index, location in enumerate(locations, start=1):
        node_id = f"R_{index}"
        name_map[location["location_key"]] = node_id
        lines.append(
            f'    {node_id}["{location["router_name"]}\\nLAN: {location["network"]}/{location["prefix"]}"]'
        )
    for link in wan_links:
        left = name_map[link["endpoints"][0]]
        right = name_map[link["endpoints"][1]]
        lines.append(f'    {left} ---|"{link["network"]}/{link["prefix"]}"| {right}')
    return "\n".join(lines)


def _cleanup_lan_blocks(locations):
    cleaned = []
    for location in locations:
        item = dict(location)
        item.pop("_network_obj", None)
        cleaned.append(item)
    return cleaned


def solve_network_problem(base_network_input, locations_input, topology_type="ring"):
    try:
        base_network = ipaddress.ip_network((base_network_input or "").strip(), strict=False)
    except ValueError as exc:
        raise EntradaInvalidaError(f"Rede base invalida: {exc}") from exc

    if base_network.version != 4:
        raise EntradaInvalidaError("A rede base deve ser IPv4.")

    locations = normalize_locations_input(locations_input)
    topology_type = (topology_type or "ring").strip().lower()

    lan_blocks, used_subnets = _build_lan_blocks(base_network, locations)
    location_keys = [location["location_key"] for location in lan_blocks]
    wan_links = _build_wan_links(base_network, used_subnets, location_keys, topology_type)
    cleaned_lans = _cleanup_lan_blocks(lan_blocks)

    result = {
        "base_network": str(base_network.with_prefixlen),
        "total_hosts_requested": sum(location["hosts_required"] for location in lan_blocks),
        "total_locations": len(cleaned_lans),
        "topology_type": topology_type,
        "lan_blocks": cleaned_lans,
        "wan_links": wan_links,
        "router_commands": {
            location["location_name"]: _router_commands(location, wan_links)
            for location in lan_blocks
        },
        "packet_tracer_steps": [
            f"Adicionar {len(cleaned_lans)} roteadores e {len(cleaned_lans)} switches (uma LAN por localidade).",
            f"Conectar os roteadores conforme topologia WAN '{topology_type}' com links seriais /30.",
            "Aplicar os comandos CLI gerados em cada roteador, validando interfaces up/up.",
            "Configurar PCs em DHCP e validar gateway automatico por localidade.",
            "Executar ping entre LANs distintas e checar a tabela RIP com show ip route.",
        ],
    }
    result["topology_mermaid"] = _mermaid_topology(lan_blocks, wan_links)
    return result


def generate_packet_tracer_script(scenario):
    """
    Gera um script consolidado (.txt) para colar no CLI dos roteadores no Packet Tracer.
    O arquivo e organizado em blocos por roteador com separadores visuais.
    """
    if not scenario:
        raise EntradaInvalidaError("Cenario vazio para exportacao.")

    lan_blocks = scenario.get("lan_blocks") or []
    wan_links = scenario.get("wan_links") or []
    if not lan_blocks:
        raise EntradaInvalidaError("Nao ha localidades no cenario para exportacao.")

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
        "! 3) Repita para todos os roteadores do cenario.",
        "!",
    ]

    router_blocks = _generate_router_lab_blocks(scenario)
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

    return "\n".join(lines).strip() + "\n"


def _router_export_filename(location_name):
    normalized = _normalize_cli_identifier(location_name, "ROTEADOR")
    return f"R-{normalized}.txt"


def _generate_router_lab_blocks(scenario):
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
        # Protecao: reserva DHCP sempre limitada ao ultimo host util da LAN local.
        if reserved_end > max_host_for_reserve:
            reserved_end = max_host_for_reserve

        block_lines = [
            "enable",
            "configure terminal",
            f"hostname {location['router_name']}",
            "no ip domain-lookup",
            "!",
            "! Ajuste de console para evitar interrupcoes de log durante colagem",
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
            neighbor_cli = _normalize_cli_identifier(neighbor.get("location_name") if neighbor else neighbor_key, "DESTINO")
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
                "! Configuracao de servico DHCP",
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
                "! Comandos de verificacao (executar apos aplicar o bloco):",
                "! show ip interface brief",
                "! show ip route rip",
                "! show running-config | section interface",
            ]
        )
        blocks[location_name] = "\n".join(block_lines).strip()
    return blocks


def generate_packet_tracer_zip_buffer(scenario):
    if not scenario:
        raise EntradaInvalidaError("Cenario vazio para exportacao.")
    lan_blocks = scenario.get("lan_blocks") or []
    if not lan_blocks:
        raise EntradaInvalidaError("Nao ha localidades no cenario para exportacao.")

    consolidated_script = generate_packet_tracer_script(scenario)
    router_blocks = _generate_router_lab_blocks(scenario)
    topology_mermaid = scenario.get("topology_mermaid", "")
    readme = (
        "INSTRUCOES DE USO DO LABORATORIO\n"
        "===============================\n"
        "1. Abra o Cisco Packet Tracer.\n"
        "2. Monte a topologia fisica conforme o arquivo LAB_TOPOLOGY.mermaid.\n"
        "3. Para cada roteador, abra o CLI e cole o conteudo do arquivo em configs_individuais/.\n"
        "4. Aguarde a convergencia do RIP (aprox. 30s).\n"
        "5. Valide com: show ip interface brief e show ip route rip.\n"
    )

    memory_file = BytesIO()
    with zipfile.ZipFile(memory_file, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("config_packet_tracer_consolidado.txt", consolidated_script)
        for location_name, block in router_blocks.items():
            filename = _router_export_filename(location_name)
            zf.writestr(f"configs_individuais/{filename}", block + "\n")
        zf.writestr("LAB_TOPOLOGY.mermaid", topology_mermaid)
        zf.writestr("README_LAB.txt", readme)

    memory_file.seek(0)
    return memory_file
