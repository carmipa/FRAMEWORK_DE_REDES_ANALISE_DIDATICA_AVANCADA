from backend.common import EntradaInvalidaError, log_event


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
                f"A LAN {location['location_name']} exige /{prefix}, menor que a rede base /{base_network.prefixlen}."
            )
        subnet = find_next_available_subnet(base_network, prefix, used)
        used.append(subnet)
        first_host, last_host = hosts_range(subnet)
        location["hosts_supported"] = max(subnet.num_addresses - 2, 0)
        location["network"] = str(subnet.network_address)
        location["prefix"] = subnet.prefixlen
        location["netmask"] = str(subnet.netmask)
        location["wildcard"] = str(subnet.hostmask)
        location["gateway"] = str(subnet.network_address + 1)
        location["host_range_start"] = first_host
        location["host_range_end"] = last_host
        location["_network_obj"] = subnet
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
        raise EntradaInvalidaError("Prefixo WAN invalido. Informe um inteiro entre 0 e 30.") from exc
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
                f"A sub-rede WAN /{wan_prefix} nao oferece dois IPs utilizaveis para o link {pair[0]} <-> {pair[1]}."
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


def cleanup_lan_blocks(locations):
    cleaned = []
    for location in locations:
        item = dict(location)
        item.pop("_network_obj", None)
        cleaned.append(item)
    return cleaned
