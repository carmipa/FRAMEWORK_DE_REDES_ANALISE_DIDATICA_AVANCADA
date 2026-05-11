import ipaddress
import math

from backend.core.exceptions import EntradaInvalidaError
from backend.core.logging import log_event
from backend.resolucao.export.export_txt_service import (
    build_pt_router_tables,
    generate_entrega_relatorio_txt,
    generate_packet_tracer_script,
    generate_router_lab_blocks,
)
from backend.resolucao.export.export_zip_service import generate_packet_tracer_zip_buffer
from backend.resolucao.vlsm.vlsm_normalization import DEFAULT_LOCATIONS, normalize_locations_input
from backend.resolucao.vlsm.vlsm_planning import (
    build_lan_blocks,
    build_wan_links,
    cleanup_lan_blocks,
    mermaid_topology,
)


def _classificacao_ipv4(primeiro_octeto: int) -> tuple[str, str, str]:
    if 1 <= primeiro_octeto <= 126:
        return "A", "1-126", "255.0.0.0"
    if 128 <= primeiro_octeto <= 191:
        return "B", "128-191", "255.255.0.0"
    if 192 <= primeiro_octeto <= 223:
        return "C", "192-223", "255.255.255.0"
    if 224 <= primeiro_octeto <= 239:
        return "D", "224-239", "Multicast (sem máscara padrão)"
    return "E", "240-255", "Reservada/Experimental"


def _build_cli_explanations(
    lan_blocks: list[dict], wan_links: list[dict], eigrp_as: int = 71
) -> dict[str, list[str]]:
    links_por_local: dict[str, int] = {}
    for link in wan_links:
        for endpoint in link.get("endpoints", []):
            links_por_local[endpoint] = links_por_local.get(endpoint, 0) + 1

    explicacoes: dict[str, list[str]] = {}
    for lan in lan_blocks:
        key = lan["location_key"]
        count_links = links_por_local.get(key, 0)
        explicacoes[lan["location_name"]] = [
            "enable / configure terminal: entra no modo privilegiado e configuração global.",
            f"interface GigabitEthernet0/0 + ip address {lan['gateway']} {lan['netmask']}: define gateway da LAN.",
            "no shutdown: ativa a interface para sair de estado administrativamente down.",
            f"ip dhcp pool LAN_{lan['cli_id']} + network {lan['network']} {lan['netmask']}: distribui IPs da sub-rede.",
            (
                f"router eigrp {eigrp_as} + network <rede> <wildcard>: habilita EIGRP "
                f"(AS {eigrp_as}) e associa interfaces por wildcard."
            ),
            f"network {lan['network']} {lan['wildcard']}: anuncia a LAN no processo EIGRP.",
            f"Este roteador possui {count_links} link(s) WAN serial no cenário atual.",
        ]
    return explicacoes


def _topology_insights(total_locations: int, selected: str) -> dict:
    ring_links = max(total_locations, 0) if total_locations > 2 else max(total_locations - 1, 0)
    mesh_links = (total_locations * (total_locations - 1)) // 2 if total_locations > 1 else 0
    link_unit_cost = 100
    ring_cost = ring_links * link_unit_cost
    mesh_cost = mesh_links * link_unit_cost
    if total_locations <= 4:
        recommendation = "ring"
        reason = "Para até 4 localidades, ring tende a equilibrar simplicidade e custo."
    else:
        recommendation = "mesh"
        reason = "Para mais de 4 localidades, mesh traz redundância superior para tráfego crítico."
    selected_note = "A topologia escolhida está alinhada com a recomendação." if selected == recommendation else "A topologia escolhida difere da recomendação automática; valide custo x redundância."
    return {
        "ring_links": ring_links,
        "mesh_links": mesh_links,
        "ring_cost": ring_cost,
        "mesh_cost": mesh_cost,
        "recommended": recommendation,
        "recommended_reason": reason,
        "selected_note": selected_note,
    }


def _growth_forecast(lan_blocks: list[dict]) -> list[dict]:
    fatores = [1.25, 1.5, 2.0]
    previsoes = []
    for lan in lan_blocks:
        cenarios = []
        for fator in fatores:
            futuros_hosts = math.ceil(lan["hosts_required"] * fator)
            needed = futuros_hosts + 2
            host_bits = (needed - 1).bit_length()
            required_prefix = 32 - host_bits
            fits_current = lan["prefix"] <= required_prefix
            cenarios.append(
                {
                    "factor_label": f"{int((fator - 1) * 100)}%",
                    "future_hosts": futuros_hosts,
                    "required_prefix": required_prefix,
                    "fits_current": fits_current,
                }
            )
        previsoes.append(
            {
                "location_name": lan["location_name"],
                "current_prefix": lan["prefix"],
                "scenarios": cenarios,
            }
        )
    return previsoes


def _suggested_base_prefix(total_consumed_addresses: int, current_prefix: int) -> int:
    if total_consumed_addresses <= 0:
        return current_prefix
    bits_host = (total_consumed_addresses - 1).bit_length()
    required_prefix = 32 - bits_host
    return max(required_prefix, current_prefix)


def solve_network_problem(
    base_network_input,
    locations_input,
    topology_type="ring",
    wan_prefix=30,
    eigrp_as=71,
):
    log_event(
        "info",
        "problem_solve",
        status="start",
        base_network_input=(base_network_input or "").strip(),
        locations_received=len(locations_input or []),
        topology_type=topology_type,
    )
    try:
        base_network = ipaddress.ip_network(
            (base_network_input or "").strip(), strict=False
        )
    except ValueError as exc:
        log_event("warning", "problem_solve", status="invalid_base_network", erro=str(exc))
        raise EntradaInvalidaError(f"Rede base invalida: {exc}") from exc

    if base_network.version != 4:
        log_event(
            "warning",
            "problem_solve",
            status="invalid_ip_version",
            version=base_network.version,
        )
        raise EntradaInvalidaError("A rede base deve ser IPv4.")

    locations = normalize_locations_input(locations_input)
    topology_type = (topology_type or "ring").strip().lower()

    try:
        eigrp_as_i = int(eigrp_as)
    except (TypeError, ValueError) as exc:
        raise EntradaInvalidaError(
            "AS EIGRP invalido. Informe um inteiro entre 1 e 65535."
        ) from exc
    if not (1 <= eigrp_as_i <= 65535):
        raise EntradaInvalidaError("AS EIGRP deve estar entre 1 e 65535.")

    lan_blocks, used_subnets = build_lan_blocks(base_network, locations)
    location_keys = [location["location_key"] for location in lan_blocks]
    wan_links = build_wan_links(
        base_network, used_subnets, location_keys, topology_type, wan_prefix=wan_prefix
    )
    cleaned_lans = cleanup_lan_blocks(lan_blocks)
    base_ip = str(base_network.network_address)
    primeiro_octeto = int(base_ip.split(".")[0])
    classe, faixa, mascara_padrao = _classificacao_ipv4(primeiro_octeto)

    total_hosts_supported = sum(item["hosts_supported"] for item in cleaned_lans)
    total_hosts_requested = sum(item["hosts_required"] for item in lan_blocks)
    total_lan_addresses = sum((2 ** (32 - item["prefix"])) for item in cleaned_lans)
    total_wan_addresses = sum((2 ** (32 - item["prefix"])) for item in wan_links)
    base_total_addresses = base_network.num_addresses
    total_consumed_addresses = total_lan_addresses + total_wan_addresses
    free_addresses = max(base_total_addresses - total_consumed_addresses, 0)
    used_pct = round((total_consumed_addresses / base_total_addresses) * 100, 2) if base_total_addresses else 0.0
    free_pct = round((free_addresses / base_total_addresses) * 100, 2) if base_total_addresses else 0.0
    overall_efficiency = (
        round((total_hosts_requested / total_hosts_supported) * 100, 2)
        if total_hosts_supported > 0
        else 0.0
    )
    topology_insights = _topology_insights(len(cleaned_lans), topology_type)
    growth_forecast = _growth_forecast(cleaned_lans)
    suggested_prefix = _suggested_base_prefix(total_consumed_addresses, base_network.prefixlen)
    scenario_stub = {
        "lan_blocks": lan_blocks,
        "wan_links": wan_links,
        "eigrp_as": eigrp_as_i,
    }
    router_commands = generate_router_lab_blocks(scenario_stub)
    pt_router_tables = build_pt_router_tables(scenario_stub)

    dhcp_lan_gateways_ref = " | ".join(
        f"{loc['location_name']}: {loc['gateway']} ({loc['netmask']})"
        for loc in cleaned_lans
    )

    result = {
        "base_network": str(base_network.with_prefixlen),
        "base_network_ip": base_ip,
        "base_network_prefix": int(base_network.prefixlen),
        "base_network_mask": str(base_network.netmask),
        "base_primeiro_octeto": primeiro_octeto,
        "base_classe": classe,
        "base_faixa_octeto": faixa,
        "base_mascara_padrao": mascara_padrao,
        "total_hosts_requested": total_hosts_requested,
        "total_hosts_supported": total_hosts_supported,
        "overall_efficiency_pct": overall_efficiency,
        "base_total_addresses": base_total_addresses,
        "total_consumed_addresses": total_consumed_addresses,
        "free_addresses": free_addresses,
        "used_address_pct": used_pct,
        "free_address_pct": free_pct,
        "suggested_base_prefix": suggested_prefix,
        "total_locations": len(cleaned_lans),
        "topology_type": topology_type,
        "wan_prefix": int(wan_prefix),
        "eigrp_as": eigrp_as_i,
        "lan_blocks": cleaned_lans,
        "wan_links": wan_links,
        "topology_insights": topology_insights,
        "growth_forecast": growth_forecast,
        "router_commands": router_commands,
        "pt_router_tables": pt_router_tables,
        "router_cli_explanations": _build_cli_explanations(
            cleaned_lans, wan_links, eigrp_as_i
        ),
        "packet_tracer_steps": [
            f"Adicionar {len(cleaned_lans)} roteadores e {len(cleaned_lans)} switches (uma LAN por localidade).",
            f"Conectar os roteadores conforme topologia WAN '{topology_type}' com links seriais /{int(wan_prefix)}.",
            "Aplicar os comandos CLI gerados em cada roteador, validando interfaces up/up.",
            (
                "No Cisco Packet Tracer, o DHCP integrado no roteador só passa a atender os PCs "
                "quando a interface LAN (GigabitEthernet0/0) já tiver o IP do gateway e estiver up/up. "
                "Aplique o script na ordem gerada (LAN antes do bloco ip dhcp pool) ou confira isso "
                "se «Obter endereço automaticamente» nos PCs falhar. "
                f"Neste cenário, Gi0/0 (gateway LAN) por localidade: {dhcp_lan_gateways_ref}."
            ),
            (
                "Em cada LAN, ligar pelo menos 2 PCs ao switch da localidade (prática usual na prova): "
                "com isso você testa ping entre todas as filiais com mais de uma origem e mais de um "
                "destino, como o enunciado costuma exigir («todos os equipamentos alcançáveis entre si»)."
            ),
            "Validar pools DHCP nos roteadores (já no script CLI) e IP/gateway automático em cada PC.",
            (
                f"A partir de vários PCs, executar ping entre LANs distintas (ex.: Matriz→Filial e "
                f"Filial→CPD) e validar adjacências EIGRP (AS {eigrp_as_i}) com show ip eigrp neighbors."
            ),
        ],
        "packet_tracer_checklist": [
            "Todas as interfaces estão up/up (show ip interface brief).",
            (
                f"EIGRP AS {eigrp_as_i} ativo, sem auto-summary, com statements "
                "network para LAN e WAN."
            ),
            "Todas as redes LAN/WAN aparecem em show ip route eigrp (ou show ip route).",
            "Em cada localidade há pelo menos 2 PCs na LAN para repetir testes de ping com credibilidade.",
            "Ping entre PCs de localidades diferentes funciona em várias combinações (origem↔destino).",
            "DHCP entrega IP/gateway correto para os hosts.",
            (
                "Packet Tracer: Gi0/0 com IP de gateway e up/up antes de testar DHCP nos PCs "
                f"(sem IP na LAN o roteador não atende DHCP). Gateways: {dhcp_lan_gateways_ref}."
            ),
        ],
    }
    topology_mermaid, topology_details = mermaid_topology(lan_blocks, wan_links)
    result["topology_mermaid"] = topology_mermaid
    result["topology_details"] = topology_details
    log_event(
        "info",
        "problem_solve",
        status="ok",
        total_locations=result["total_locations"],
        total_hosts_requested=result["total_hosts_requested"],
        wan_links=len(wan_links),
    )
    return result


__all__ = [
    "DEFAULT_LOCATIONS",
    "generate_entrega_relatorio_txt",
    "generate_packet_tracer_script",
    "generate_packet_tracer_zip_buffer",
    "solve_network_problem",
]
