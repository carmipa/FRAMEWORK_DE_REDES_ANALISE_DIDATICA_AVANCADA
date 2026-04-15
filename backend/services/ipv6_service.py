import ipaddress

from backend.common import EntradaInvalidaError


def classificar_ipv6(addr):
    if addr.is_loopback:
        return "Loopback"
    if addr.is_link_local:
        return "Link-local"
    if addr.is_private:
        return "ULA/Privado"
    if addr.is_multicast:
        return "Multicast"
    if addr.is_global:
        return "Global unicast"
    return "Outro/Reservado"


def escopo_ipv6(addr):
    if addr.is_loopback:
        return "Host local"
    if addr.is_link_local:
        return "Enlace local (não roteável)"
    if addr.is_private:
        return "Site local/ULA (rede privada IPv6)"
    if addr.is_global:
        return "Global (roteável na Internet)"
    if addr.is_multicast:
        return "Multicast (grupo)"
    if addr.is_unspecified:
        return "Não especificado"
    return "Reservado/Especial"


def sinais_ipv6(addr):
    sinais = []
    if addr.is_loopback:
        sinais.append("Loopback")
    if addr.is_link_local:
        sinais.append("Link-local")
    if addr.is_private:
        sinais.append("ULA")
    if addr.is_global:
        sinais.append("Global")
    if addr.is_multicast:
        sinais.append("Multicast")
    if addr.is_reserved:
        sinais.append("Reservado")
    if addr.is_unspecified:
        sinais.append("Não especificado")
    if addr.ipv4_mapped:
        sinais.append(f"IPv4-mapped ({addr.ipv4_mapped})")
    if addr.sixtofour:
        sinais.append(f"6to4 ({addr.sixtofour})")
    if addr.teredo:
        sinais.append(f"Teredo ({addr.teredo[0]} -> {addr.teredo[1]})")
    return sinais or ["Sem sinais especiais"]


def grc_ipv6(addr):
    if addr.is_link_local:
        return "Endereço de enlace local: válido para segmento local e troubleshooting, sem roteamento externo."
    if addr.is_private:
        return "ULA: adequado para ambientes internos; manter ACL e segmentação de tráfego leste-oeste."
    if addr.is_global:
        return "Global unicast: requer hardening de borda, filtros e monitoramento contínuo de exposição."
    if addr.is_multicast:
        return "Multicast: revisar escopo e assinaturas de grupo para evitar tráfego excessivo."
    return "Revisar contexto operacional para validar uso e escopo deste endereço IPv6."


def processar_ipv6(ipv6_s):
    raw = (ipv6_s or "").strip().strip('"').strip("'")
    if not raw:
        raise EntradaInvalidaError("IPv6 vazio.")

    zone = ""
    base = raw
    if "%" in raw:
        base, zone = raw.split("%", 1)
        base = base.strip()
        zone = zone.strip()
        if not zone:
            raise EntradaInvalidaError("IPv6 com zone index inválido (sufixo após % está vazio).")

    try:
        addr = ipaddress.IPv6Address(base)
    except Exception as exc:
        raise EntradaInvalidaError(f"IPv6 inválido: {exc}") from exc

    bits = bin(int(addr))[2:].zfill(128)
    blocos_16 = [bits[i:i + 16] for i in range(0, 128, 16)]
    hextetos = addr.exploded.split(":")
    primeiros_64 = ":".join(hextetos[:4])
    ultimos_64 = ":".join(hextetos[4:])
    rede_64 = str(ipaddress.IPv6Network(f"{addr}/64", strict=False).network_address)
    sinais = sinais_ipv6(addr)
    comprimido = addr.compressed + (f"%{zone}" if zone else "")
    itens_exibicao = [
        {"icone": "📥", "campo": "IPv6 informado", "valor": raw},
        {"icone": "🗜️", "campo": "Comprimido", "valor": comprimido},
        {"icone": "🧱", "campo": "Expandido", "valor": addr.exploded},
        {"icone": "🏷️", "campo": "Classificação", "valor": classificar_ipv6(addr)},
        {"icone": "🧭", "campo": "Escopo", "valor": escopo_ipv6(addr)},
        {"icone": "📌", "campo": "Prefixo sugerido", "valor": "/64 (didático para LAN IPv6)"},
        {"icone": "🌐", "campo": "Rede /64 estimada", "valor": f"{rede_64}/64"},
        {"icone": "🆔", "campo": "Zone index", "valor": zone or "—"},
        {"icone": "🧠", "campo": "Primeiros 64 bits", "valor": primeiros_64},
        {"icone": "🔚", "campo": "Últimos 64 bits", "valor": ultimos_64},
        {"icone": "🔢", "campo": "Total de bits", "valor": "128"},
        {"icone": "🧾", "campo": "Reverse DNS (PTR)", "valor": addr.reverse_pointer},
        {"icone": "🛡️", "campo": "Sinais especiais", "valor": ", ".join(sinais)},
        {"icone": "✅", "campo": "Resumo GRC", "valor": grc_ipv6(addr)},
    ]
    return {
        "entrada": raw,
        "comprimido": comprimido,
        "expandido": addr.exploded,
        "tipo": classificar_ipv6(addr),
        "escopo": escopo_ipv6(addr),
        "prefixo_sugerido": "/64 (didático para LAN IPv6)",
        "blocos_16": blocos_16,
        "hextetos": hextetos,
        "primeiros_64": primeiros_64,
        "ultimos_64": ultimos_64,
        "rede_64": rede_64,
        "reverse_pointer": addr.reverse_pointer,
        "sinais_especiais": sinais,
        "grc_ipv6": grc_ipv6(addr),
        "itens_exibicao": itens_exibicao,
        "zone_index": zone or "—",
    }

