import ipaddress

from backend.common import EntradaInvalidaError, log_event
from backend.services.problem_resolution_export import (
    generate_entrega_relatorio_txt,
    generate_packet_tracer_script,
    generate_packet_tracer_zip_buffer,
    generate_router_lab_blocks,
)
from backend.services.problem_resolution_normalization import (
    DEFAULT_LOCATIONS,
    normalize_locations_input,
)
from backend.services.problem_resolution_planning import (
    build_lan_blocks,
    build_wan_links,
    cleanup_lan_blocks,
    mermaid_topology,
)


def solve_network_problem(base_network_input, locations_input, topology_type="ring", wan_prefix=30):
    log_event(
        "info",
        "problem_solve",
        status="start",
        base_network_input=(base_network_input or "").strip(),
        locations_received=len(locations_input or []),
        topology_type=topology_type,
    )
    try:
        base_network = ipaddress.ip_network((base_network_input or "").strip(), strict=False)
    except ValueError as exc:
        log_event("warning", "problem_solve", status="invalid_base_network", erro=str(exc))
        raise EntradaInvalidaError(f"Rede base invalida: {exc}") from exc

    if base_network.version != 4:
        log_event("warning", "problem_solve", status="invalid_ip_version", version=base_network.version)
        raise EntradaInvalidaError("A rede base deve ser IPv4.")

    locations = normalize_locations_input(locations_input)
    topology_type = (topology_type or "ring").strip().lower()

    lan_blocks, used_subnets = build_lan_blocks(base_network, locations)
    location_keys = [location["location_key"] for location in lan_blocks]
    wan_links = build_wan_links(
        base_network, used_subnets, location_keys, topology_type, wan_prefix=wan_prefix
    )
    cleaned_lans = cleanup_lan_blocks(lan_blocks)

    result = {
        "base_network": str(base_network.with_prefixlen),
        "total_hosts_requested": sum(location["hosts_required"] for location in lan_blocks),
        "total_locations": len(cleaned_lans),
        "topology_type": topology_type,
        "wan_prefix": int(wan_prefix),
        "lan_blocks": cleaned_lans,
        "wan_links": wan_links,
        "router_commands": generate_router_lab_blocks(
            {"lan_blocks": lan_blocks, "wan_links": wan_links}
        ),
        "packet_tracer_steps": [
            f"Adicionar {len(cleaned_lans)} roteadores e {len(cleaned_lans)} switches (uma LAN por localidade).",
            f"Conectar os roteadores conforme topologia WAN '{topology_type}' com links seriais /{int(wan_prefix)}.",
            "Aplicar os comandos CLI gerados em cada roteador, validando interfaces up/up.",
            "Configurar PCs em DHCP e validar gateway automático por localidade.",
            "Executar ping entre LANs distintas e checar a tabela RIP com show ip route.",
        ],
    }
    result["topology_mermaid"] = mermaid_topology(lan_blocks, wan_links)
    log_event(
        "info",
        "problem_solve",
        status="ok",
        total_locations=result["total_locations"],
        total_hosts_requested=result["total_hosts_requested"],
        wan_links=len(wan_links),
    )
    return result
