from backend.core.exceptions import EntradaInvalidaError
from backend.core.logging import log_event


def _mermaid_escape(text: str) -> str:
    """Evita quebras de sintaxe em rótulos Mermaid (subgrafos e nós)."""
    return (text or "").replace('"', "'").replace("\n", " ").strip()


def required_prefix_for_hosts(host_count):
    needed = host_count + 2
    host_bits = (needed - 1).bit_length()
    return 32 - host_bits


def iter_free_subnets(base_network, prefix):
    for subnet in base_network.subnets(new_prefix=prefix):
        yield subnet


def find_next_available_subnet(base_network, prefix, used_subnets):
    for candidate in iter_free_subnets(base_network, prefix):
        if all(not candidate.overlaps(used) for used in used_subnets):
            return candidate
    raise EntradaInvalidaError(
        "Não há espaço suficiente na rede base para acomodar todas as LANs e links WAN."
    )


def hosts_range(network):
    if network.num_addresses <= 2:
        return (str(network.network_address), str(network.broadcast_address))
    first_host = network.network_address + 1
    last_host = network.broadcast_address - 1
    return (str(first_host), str(last_host))


def build_lan_blocks(base_network, locations):
    ordered = sorted(locations, key=lambda item: item["hosts_required"], reverse=True)
    used = []
    log_event(
        "info",
        "problem_lan_planning",
        status="start",
        locations_count=len(ordered),
        base_network=str(base_network.with_prefixlen),
    )
    for location in ordered:
        hosts = location["hosts_required"]
        needed = hosts + 2
        host_bits = (needed - 1).bit_length()
        prefix = required_prefix_for_hosts(hosts)
        if prefix < base_network.prefixlen:
            log_event(
                "warning",
                "problem_lan_planning",
                status="invalid_prefix",
                location=location["location_name"],
                required_prefix=prefix,
                base_prefix=base_network.prefixlen,
            )
            raise EntradaInvalidaError(
                f"A LAN {location['location_name']} exige /{prefix}, "
                f"menor que a rede base /{base_network.prefixlen}."
            )
        subnet = find_next_available_subnet(base_network, prefix, used)
        used.append(subnet)
        first_host, last_host = hosts_range(subnet)
        location["hosts_supported"] = max(subnet.num_addresses - 2, 0)
        location["hosts_needed_total"] = needed
        location["host_bits"] = host_bits
        location["calculated_prefix"] = prefix
        if location["hosts_supported"] > 0:
            location["efficiency_pct"] = round(
                (location["hosts_required"] / location["hosts_supported"]) * 100, 2
            )
        else:
            location["efficiency_pct"] = 0.0
        location["network"] = str(subnet.network_address)
        location["prefix"] = subnet.prefixlen
        location["netmask"] = str(subnet.netmask)
        location["wildcard"] = str(subnet.hostmask)
        location["gateway"] = str(subnet.network_address + 1)
        location["host_range_start"] = first_host
        location["host_range_end"] = last_host
        location["_network_obj"] = subnet
        location["calculation_breakdown"] = {
            "hosts_requested": hosts,
            "overhead_hosts": 2,
            "total_needed": needed,
            "next_power_of_2": 2 ** host_bits,
            "host_bits_required": host_bits,
            "formula_used": f"2^{host_bits} = {2 ** host_bits} > {needed} ✓",
            "prefix_calculation": f"32 - {host_bits} = /{prefix}",
            "explanation_steps": [
                f"1. Hosts solicitados: {hosts}",
                f"2. Adicionar network + broadcast: {hosts} + 2 = {needed}",
                f"3. Próxima potência de 2: 2^{host_bits} = {2 ** host_bits}",
                f"4. Bits de host necessários: {host_bits}",
                f"5. Prefix resultante: 32 - {host_bits} = /{prefix}",
                f"6. Rede alocada: {subnet.with_prefixlen}",
                f"7. Hosts disponíveis: {location['hosts_supported']}",
                f"8. Eficiência: {location['hosts_required']}/{location['hosts_supported']} = {location['efficiency_pct']}%"
            ]
        }
        log_event(
            "info",
            "problem_lan_allocated",
            location=location["location_name"],
            network=f"{location['network']}/{location['prefix']}",
            hosts_required=location["hosts_required"],
            hosts_supported=location["hosts_supported"],
        )
    log_event("info", "problem_lan_planning", status="end", used_subnets=len(used))
    return locations, used


def build_wan_pairs(location_keys, topology_type):
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
    raise EntradaInvalidaError("Topologia WAN inválida. Use 'ring' ou 'mesh'.")


def build_wan_links(base_network, used_subnets, location_keys, topology_type, wan_prefix=30):
    wan_pairs = build_wan_pairs(location_keys, topology_type)
    try:
        wan_prefix = int(wan_prefix)
    except (TypeError, ValueError) as exc:
        raise EntradaInvalidaError(
            "Prefixo WAN invalido. Informe um inteiro entre 0 e 30."
        ) from exc
    if wan_prefix < 0 or wan_prefix > 30:
        raise EntradaInvalidaError("Prefixo WAN invalido. Informe um inteiro entre 0 e 30.")
    log_event(
        "info",
        "problem_wan_planning",
        status="start",
        topology_type=topology_type,
        wan_prefix=wan_prefix,
        links_expected=len(wan_pairs),
    )
    links = []
    for index, pair in enumerate(wan_pairs, start=1):
        subnet = find_next_available_subnet(base_network, wan_prefix, used_subnets)
        used_subnets.append(subnet)
        hosts = list(subnet.hosts())
        if len(hosts) < 2:
            raise EntradaInvalidaError(
                f"A sub-rede WAN /{wan_prefix} nao oferece dois IPs utilizaveis "
                f"para o link {pair[0]} <-> {pair[1]}."
            )
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
        log_event(
            "info",
            "problem_wan_allocated",
            link_name=f"WAN-{index}",
            network=f"{subnet.network_address}/{subnet.prefixlen}",
            endpoint_a=pair[0],
            endpoint_b=pair[1],
        )
    log_event("info", "problem_wan_planning", status="end", links_created=len(links))
    return links


def mermaid_topology(locations, wan_links):
    lines = ["graph LR"]
    name_map = {}
    details_map = {}
    for index, location in enumerate(locations, start=1):
        node_id = f"R_{index}"
        sw_id = f"SW_{index}"
        pc_a = f"PC_{index}A"
        pc_b = f"PC_{index}B"
        name_map[location["location_key"]] = node_id
        loc_label = _mermaid_escape(location["location_name"]) or f"Local {index}"
        lines.append(f'    subgraph LAN_{index}["{loc_label}"]')
        lines.append(
            f'        {node_id}["{location["router_name"]}\\nLAN: '
            f'{location["network"]}/{location["prefix"]}"]'
        )
        lines.append(f'        {sw_id}["Switch\\nLAN local"]')
        lines.append(f'        {pc_a}["PC teste 1\\nDHCP"]')
        lines.append(f'        {pc_b}["PC teste 2\\nDHCP"]')
        lines.append(f"        {node_id} --- {sw_id}")
        lines.append(f"        {sw_id} --- {pc_a}")
        lines.append(f"        {sw_id} --- {pc_b}")
        lines.append("    end")
        lines.append(f'    click {node_id} showTopologyDetail "{node_id}"')
        lines.append(f'    click {sw_id} showTopologyDetail "{sw_id}"')
        lines.append(f'    click {pc_a} showTopologyDetail "{pc_a}"')
        lines.append(f'    click {pc_b} showTopologyDetail "{pc_b}"')
        details_map[node_id] = {
            "type": "router",
            "title": location["router_name"],
            "network": f'{location["network"]}/{location["prefix"]}',
            "gateway": location["gateway"],
            "host_range": f'{location["host_range_start"]} - {location["host_range_end"]}',
            "mask": location["netmask"],
            "wildcard": location["wildcard"],
            "hosts_required": location["hosts_required"],
            "hosts_supported": location["hosts_supported"],
        }
        details_map[sw_id] = {
            "type": "switch",
            "title": f"Switch · {location['location_name']}",
            "network": f'{location["network"]}/{location["prefix"]}',
            "gateway": location["gateway"],
        }
        details_map[pc_a] = {
            "type": "host",
            "title": f"PC teste 1 · {location['location_name']}",
            "gateway": location["gateway"],
            "network": f'{location["network"]}/{location["prefix"]}',
        }
        details_map[pc_b] = {
            "type": "host",
            "title": f"PC teste 2 · {location['location_name']}",
            "gateway": location["gateway"],
            "network": f'{location["network"]}/{location["prefix"]}',
        }
    for index, link in enumerate(wan_links, start=1):
        left = name_map[link["endpoints"][0]]
        right = name_map[link["endpoints"][1]]
        wan_id = f"W_{index}"
        lines.append(f'    {wan_id}{{"WAN {index}\\n{link["network"]}/{link["prefix"]}"}}')
        lines.append(f"    {left} --- {wan_id}")
        lines.append(f"    {wan_id} --- {right}")
        lines.append(f'    click {wan_id} showTopologyDetail "{wan_id}"')
        details_map[wan_id] = {
            "type": "wan",
            "title": link["name"],
            "network": f'{link["network"]}/{link["prefix"]}',
            "mask": link["netmask"],
            "wildcard": link["wildcard"],
            "endpoint_a": f'{link["endpoints"][0]} - {link["ips"][link["endpoints"][0]]}',
            "endpoint_b": f'{link["endpoints"][1]} - {link["ips"][link["endpoints"][1]]}',
        }
    return "\n".join(lines), details_map


def cleanup_lan_blocks(locations):
    cleaned = []
    for location in locations:
        item = dict(location)
        item.pop("_network_obj", None)
        cleaned.append(item)
    return cleaned
