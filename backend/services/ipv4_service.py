from backend.common import EntradaInvalidaError


def classe_ipv4_didatica(o1):
    """Classificação didática pelo 1º octeto (IPv4 classful); CIDR tornou isso só referência histórica."""
    if o1 == 0:
        return "Reservado", "(0.0.0.0/8 — não roteável na Internet)"
    if o1 == 127:
        return "Loopback", "(127.0.0.0/8)"
    if 1 <= o1 <= 126:
        return "A", "faixa clássica 1–126 no 1º octeto"
    if 128 <= o1 <= 191:
        return "B", "faixa clássica 128–191 no 1º octeto"
    if 192 <= o1 <= 223:
        return "C", "faixa clássica 192–223 no 1º octeto"
    if 224 <= o1 <= 239:
        return "D", "multicast (224–239)"
    if 240 <= o1 <= 255:
        return "E", "experimental / reservado (240–255)"
    return "—", ""


def classe_variant_css(classe):
    """Slug estável para classes CSS do banner de destaque."""
    return {
        "A": "a",
        "B": "b",
        "C": "c",
        "D": "d",
        "E": "e",
        "Reservado": "reservado",
        "Loopback": "loopback",
        "—": "outros",
    }.get(classe, "outros")


def privacidade_rfc1918(parts):
    """Identifica tipo de IP para cenários comuns de prova."""
    o1, o2 = parts[0], parts[1]
    if o1 == 127:
        return "Loopback", "Faixa 127.0.0.0/8 (localhost, teste local)"
    if o1 == 169 and o2 == 254:
        return "APIPA", "Faixa 169.254.0.0/16 (auto-configuração sem DHCP)"
    if o1 == 10:
        return "Privado (RFC 1918)", "Faixa privada 10.0.0.0 - 10.255.255.255"
    if o1 == 172 and 16 <= o2 <= 31:
        return "Privado (RFC 1918)", "Faixa privada 172.16.0.0 - 172.31.255.255"
    if o1 == 192 and o2 == 168:
        return "Privado (RFC 1918)", "Faixa privada 192.168.0.0 - 192.168.255.255"
    if 224 <= o1 <= 239:
        return "Multicast", "Faixa 224.0.0.0 - 239.255.255.255 (não host unicast)"
    if 240 <= o1 <= 255:
        return "Reservado/Experimental", "Faixa 240.0.0.0 - 255.255.255.255"
    return "Público", "Fora das faixas privadas/locais (roteável conforme políticas)"


def fmt_ip(n):
    return f"{(n >> 24) & 255}.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255}"


def parse_ipv4_parts(ip_s, nome_campo="IP"):
    txt = (ip_s or "").strip()
    if not txt:
        raise EntradaInvalidaError(f"{nome_campo} vazio.")
    raw_parts = txt.split(".")
    if len(raw_parts) != 4:
        raise EntradaInvalidaError(f"{nome_campo} inválido. Use formato x.x.x.x.")
    parts = []
    for idx, raw in enumerate(raw_parts, start=1):
        raw = raw.strip()
        if raw == "":
            raise EntradaInvalidaError(f"{nome_campo} inválido: octeto {idx} está vazio.")
        if not raw.isdigit():
            raise EntradaInvalidaError(f"{nome_campo} inválido: octeto {idx} não é numérico.")
        octeto = int(raw)
        if not (0 <= octeto <= 255):
            raise EntradaInvalidaError(f"{nome_campo} inválido: octeto {idx} fora de 0-255.")
        parts.append(octeto)
    return parts


def inferir_cidr_por_ip(ip_s):
    """
    Inferência didática (classful) para provas quando CIDR não é informado.
    Retorna (cidr, descricao_origem).
    """
    parts = parse_ipv4_parts(ip_s, "IP")
    o1 = parts[0]
    if o1 == 0:
        return 8, "Inferido por classe: reservado 0.x.x.x => /8"
    if 1 <= o1 <= 126:
        return 8, "Inferido por classe A => /8"
    if o1 == 127:
        return 8, "Inferido por loopback 127.x.x.x => /8"
    if 128 <= o1 <= 191:
        return 16, "Inferido por classe B => /16"
    if 192 <= o1 <= 223:
        return 24, "Inferido por classe C => /24"
    if 224 <= o1 <= 239:
        return 4, "Inferido por classe D (multicast) => /4"
    return 4, "Inferido por classe E (experimental/reservado) => /4"


def mascara_dotted_para_cidr(mask_s):
    """Converte máscara IPv4 pontuada (bits de rede contíguos) em prefixo /0–/32."""
    try:
        parts = parse_ipv4_parts(mask_s, "Máscara decimal")
    except EntradaInvalidaError:
        return None
    val = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
    val &= 0xFFFFFFFF
    inv = (~val) & 0xFFFFFFFF
    if inv != 0 and (inv & (inv + 1)) != 0:
        return None
    return val.bit_count()


def wildcard_dotted_para_cidr(wild_s):
    """Converte wildcard pontuada para CIDR via máscara inversa."""
    try:
        parts = parse_ipv4_parts(wild_s, "Wildcard mask")
    except EntradaInvalidaError:
        return None
    mask_equivalente = ".".join(str(255 - o) for o in parts)
    return mascara_dotted_para_cidr(mask_equivalente)


def core_mascara(cidr):
    """Dados derivados só do CIDR (máscara, bitmap, capacidade, pulo)."""
    if not isinstance(cidr, int) or not (0 <= cidr <= 32):
        return None
    m_i = (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF
    if cidr >= 24:
        pulo = 2 ** (32 - cidr)
    elif cidr >= 16:
        pulo = 2 ** (24 - cidr)
    else:
        pulo = 2 ** (16 - cidr)

    tamanho = 2 ** (32 - cidr)
    if cidr == 32:
        uteis = 1
    elif cidr == 31:
        uteis = 2
    elif tamanho > 2:
        uteis = tamanho - 2
    else:
        uteis = 0

    return {
        "mask": fmt_ip(m_i),
        "wildcard": fmt_ip((~m_i) & 0xFFFFFFFF),
        "bin_raw": bin(m_i)[2:].zfill(32),
        "zeros": 32 - cidr,
        "total": tamanho,
        "uteis": uteis,
        "pulo": pulo,
        "cidr": cidr,
        "_m_i": m_i,
    }


def tema_dinamico(cidr, total_ips):
    """
    Define paleta dinâmica para tabelas com base no prefixo e tamanho da rede.
    Quanto maior a rede (CIDR menor), mais quente o alerta visual.
    """
    if cidr >= 24:
        return {
            "cor_bit1": "#238636",
            "cor_resultado_and": "#3fb950",
            "cor_pulo": "#2ea043",
            "cor_borda_resumo": "#2ea043",
            "cor_acento": "#3fb950",
            "cor_borda_tabela": "#2d6a4f",
            "cor_cabecalho_tabela_bg": "#14261c",
            "cor_cabecalho_tabela_texto": "#8be9a8",
            "cor_linha_destaque": "rgba(63, 185, 80, 0.16)",
            "nivel_tema": "Baixo risco operacional",
            "nivel_tema_descricao": "Prefixo mais específico: bloco menor, varredura e governança mais simples.",
        }
    if cidr >= 17:
        return {
            "cor_bit1": "#1f6feb",
            "cor_resultado_and": "#79c0ff",
            "cor_pulo": "#58a6ff",
            "cor_borda_resumo": "#1f6feb",
            "cor_acento": "#79c0ff",
            "cor_borda_tabela": "#1f4f87",
            "cor_cabecalho_tabela_bg": "#101c2f",
            "cor_cabecalho_tabela_texto": "#9fd0ff",
            "cor_linha_destaque": "rgba(121, 192, 255, 0.16)",
            "nivel_tema": "Risco moderado",
            "nivel_tema_descricao": "Rede intermediária: atenção à segmentação e aos controles de acesso.",
        }
    if cidr >= 9:
        return {
            "cor_bit1": "#d29922",
            "cor_resultado_and": "#e3b341",
            "cor_pulo": "#f2cc60",
            "cor_borda_resumo": "#d29922",
            "cor_acento": "#e3b341",
            "cor_borda_tabela": "#7a611f",
            "cor_cabecalho_tabela_bg": "#2b2310",
            "cor_cabecalho_tabela_texto": "#f2d487",
            "cor_linha_destaque": "rgba(227, 179, 65, 0.16)",
            "nivel_tema": "Risco elevado",
            "nivel_tema_descricao": "Bloco amplo: recomenda-se dividir sub-redes e restringir superfície.",
        }
    return {
        "cor_bit1": "#f85149",
        "cor_resultado_and": "#ff7b72",
        "cor_pulo": "#ff7b72",
        "cor_borda_resumo": "#f85149",
        "cor_acento": "#ff7b72",
        "cor_borda_tabela": "#8b2f2a",
        "cor_cabecalho_tabela_bg": "#2f1414",
        "cor_cabecalho_tabela_texto": "#ffb3ad",
        "cor_linha_destaque": "rgba(248, 81, 73, 0.18)",
        "nivel_tema": "Risco crítico",
        "nivel_tema_descricao": "Rede muito extensa: alto impacto operacional e maior exposição para varredura.",
    }


def tabela_referencia_subredes(cidr):
    """
    Gera tabela de referência dinâmica para o octeto relevante do CIDR.
    Ex.: /20 => octeto 3 => linhas /17 a /23.
    """
    if not isinstance(cidr, int) or not (0 <= cidr <= 32):
        return 4, []

    if cidr <= 8:
        octeto = 1
    elif cidr <= 16:
        octeto = 2
    elif cidr <= 24:
        octeto = 3
    else:
        octeto = 4

    start = (octeto - 1) * 8 + 1
    end = octeto * 8
    pesos = [128, 64, 32, 16, 8, 4, 2, 1]
    rows = []

    for barra in range(start, end + 1):
        bits_on = barra - ((octeto - 1) * 8)
        bits = [1 if i < bits_on else 0 for i in range(8)]
        mascara_octeto = sum(pesos[i] for i in range(bits_on))
        rows.append(
            {
                "barra": barra,
                "bits": bits,
                "intervalos": 2 ** bits_on,
                "variacao": 2 ** (8 - bits_on),
                "ips": 2 ** (32 - barra),
                "mascara_octeto": mascara_octeto,
                "is_current": barra == cidr,
            }
        )
    return octeto, rows


def tabela_conversao_bits(cidr):
    """Tabela de estudo precisa para conversão entre bits e bytes."""
    linhas = [
        {"referencia": "1 bit", "bits": "1", "bytes": "0.125", "binario": "1", "decimal": "1"},
        {"referencia": "1 nibble", "bits": "4", "bytes": "0.5", "binario": "1111", "decimal": "15"},
        {"referencia": "1 byte (octeto)", "bits": "8", "bytes": "1", "binario": "11111111", "decimal": "255"},
        {
            "referencia": "1 word",
            "bits": "16",
            "bytes": "2",
            "binario": "11111111 11111111",
            "decimal": "65535",
        },
        {
            "referencia": "1 dword (IPv4)",
            "bits": "32",
            "bytes": "4",
            "binario": "32 bits em 1",
            "decimal": "4294967295",
        },
        {"referencia": "1 KiB", "bits": "8192", "bytes": "1024", "binario": "2^10 bytes", "decimal": "1024"},
        {"referencia": "1 MiB", "bits": "8388608", "bytes": "1048576", "binario": "2^20 bytes", "decimal": "1048576"},
    ]

    host_bits = 32 - cidr
    rede_bits = cidr
    conversao_atual = [
        {"chave": "Bits de rede", "valor": rede_bits},
        {"chave": "Bits de host", "valor": host_bits},
        {"chave": "Bits totais IPv4", "valor": 32},
        {"chave": "Bytes totais IPv4", "valor": "4"},
        {"chave": "Capacidade do bloco", "valor": f"2^{host_bits} = {2 ** host_bits} IPs"},
        {"chave": "Conversão útil", "valor": "1 byte = 8 bits | 1 nibble = 4 bits"},
    ]
    return linhas, conversao_atual


def processar_somente_mascara(cidr):
    """Exercício com máscara/CIDR sem endereço IP: sem rede/broadcast/hosts específicos."""
    c = core_mascara(cidr)
    if c is None:
        return None
    out = {k: v for k, v in c.items() if k != "_m_i"}
    octeto_ref, tabela_ref = tabela_referencia_subredes(cidr)
    tabela_conv, conv_atual = tabela_conversao_bits(cidr)
    tema = tema_dinamico(cidr, c["total"])
    out["somente_mascara"] = True
    out["cidr_origem"] = ""
    out["octeto_referencia"] = octeto_ref
    out["tabela_referencia"] = tabela_ref
    out["tabela_conversao_bits"] = tabela_conv
    out["conversao_atual"] = conv_atual
    out.update(tema)
    out["rede"] = out["broad"] = out["primeiro_host"] = out["ultimo_host"] = "—"
    return out


def hosts_da_subrede(rede_i, broad_i, cidr):
    """Retorna primeiro e último host conforme regra do prefixo."""
    if cidr == 32:
        host = fmt_ip(rede_i)
        return host, host
    if cidr == 31:
        return fmt_ip(rede_i), fmt_ip(rede_i + 1)
    if broad_i - rede_i >= 2:
        return fmt_ip(rede_i + 1), fmt_ip(broad_i - 1)
    return "—", "—"


def papel_ip_no_bloco(ip_i, rede_i, broad_i, cidr):
    if cidr == 32:
        return "Host único (/32)", ""
    if cidr == 31:
        return "Host válido em /31 (enlace P2P)", "Em /31 os dois endereços são utilizáveis (RFC 3021)."
    if ip_i == rede_i:
        return "Endereço de rede", "Este IP identifica a sub-rede e não deve ser atribuído a host."
    if ip_i == broad_i:
        return "Endereço de broadcast", "Este IP é reservado para broadcast e não deve ser atribuído a host."
    return "Host válido", ""


def processar(ip_s, cidr, regua_count=5):
    c = core_mascara(cidr)
    if c is None:
        raise EntradaInvalidaError("CIDR inválido para cálculo de rede.")

    parts = parse_ipv4_parts(ip_s, "IP")
    m_i = c["_m_i"]
    ip_i = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
    r_i = ip_i & m_i
    b_i = r_i | (0xFFFFFFFF ^ m_i)
    tamanho = c["total"]
    primeiro_host, ultimo_host = hosts_da_subrede(r_i, b_i, cidr)

    classe, classe_faixa = classe_ipv4_didatica(parts[0])
    ip_tipo_privacidade, ip_faixa_privacidade = privacidade_rfc1918(parts)
    hosts_recomendados = ip_tipo_privacidade not in {"Multicast", "Reservado/Experimental"}

    and_table = []
    for oct_idx in range(4):
        shift = 24 - (oct_idx * 8)
        ip_oct = (ip_i >> shift) & 255
        mask_oct = (m_i >> shift) & 255
        and_oct = ip_oct & mask_oct
        and_table.append(
            {
                "ip_oct": ip_oct,
                "mask_oct": mask_oct,
                "and_oct": and_oct,
                "wild_oct": 255 - mask_oct,
                "ip_bin": bin(ip_oct)[2:].zfill(8),
                "mask_bin": bin(mask_oct)[2:].zfill(8),
                "and_bin": bin(and_oct)[2:].zfill(8),
            }
        )

    proximas_subredes = []
    for i in range(regua_count):
        prox = r_i + (i * tamanho)
        if prox > 0xFFFFFFFF:
            break
        broad_prox = min(prox + tamanho - 1, 0xFFFFFFFF)
        p_host, u_host = hosts_da_subrede(prox, broad_prox, cidr)
        proximas_subredes.append(
            {
                "nome": f"Subnet {i + 1}",
                "rede": fmt_ip(prox),
                "primeiro_host": p_host,
                "ultimo_host": u_host,
                "broadcast": fmt_ip(broad_prox),
            }
        )

    ip_papel, ip_papel_alerta = papel_ip_no_bloco(ip_i, r_i, b_i, cidr)
    octeto_ref, tabela_ref = tabela_referencia_subredes(cidr)
    tabela_conv, conv_atual = tabela_conversao_bits(cidr)
    tema = tema_dinamico(cidr, c["total"])
    out = {k: v for k, v in c.items() if k != "_m_i"}
    gateway_sugerido = primeiro_host if hosts_recomendados else "N/A para este tipo de IP"
    gateway_alternativo = ultimo_host if hosts_recomendados else "N/A para este tipo de IP"
    resumo_prova = (
        f"IP informado: {fmt_ip(ip_i)}\n"
        f"Máscara/CIDR: {c['mask']} /{cidr}\n"
        f"Rede: {fmt_ip(r_i)}\n"
        f"Broadcast: {fmt_ip(b_i)}\n"
        f"Wildcard: {c['wildcard']}\n"
        f"Hosts úteis: {c['uteis']}\n"
        f"Tipo de IP: {ip_tipo_privacidade}\n"
        f"Papel do IP: {ip_papel}\n"
        f"Gateway sugerido: {gateway_sugerido}"
    )
    resumo_prova_itens = [
        {"campo": "🌐 IP informado", "valor": fmt_ip(ip_i)},
        {"campo": "📏 Máscara/CIDR", "valor": f"{c['mask']} /{cidr}"},
        {"campo": "🧭 Rede", "valor": fmt_ip(r_i)},
        {"campo": "📣 Broadcast", "valor": fmt_ip(b_i)},
        {"campo": "🧩 Wildcard", "valor": c["wildcard"]},
        {"campo": "✅ Hosts úteis", "valor": c["uteis"]},
        {"campo": "🔐 Tipo de IP", "valor": ip_tipo_privacidade},
        {"campo": "📌 Papel do IP", "valor": ip_papel},
        {"campo": "🚪 Gateway sugerido", "valor": gateway_sugerido},
    ]

    seguranca_dicas = []
    if c["uteis"] > 0:
        if cidr <= 16:
            seguranca_dicas.append(
                {
                    "tipo": "warning",
                    "icon": "⚠️",
                    "texto": (
                        f"Aviso de Scan Nmap: Um scan completo de todas as portas para {c['total']} IPs "
                        "exigiria um tempo excessivo. É recomendado particionar essa rede para varreduras mais eficientes."
                    ),
                }
            )
        elif cidr >= 24:
            seguranca_dicas.append(
                {
                    "tipo": "success",
                    "icon": "✅",
                    "texto": (
                        f"Superfície de Ataque: Uma rede /{cidr} ({c['total']} IPs) possui superfície reduzida "
                        "e varreduras com Nmap são rápidas e controladas."
                    ),
                }
            )

    if ip_papel == "Endereço de broadcast":
        seguranca_dicas.append(
            {
                "tipo": "danger",
                "icon": "🚨",
                "texto": (
                    "Aviso Smurf Attack: IPs de broadcast não devem responder a pacotes ICMP Request "
                    "(ping), para evitar amplificação em ataques DDoS."
                ),
            }
        )
    elif "Privado" not in ip_tipo_privacidade and ip_tipo_privacidade not in [
        "Loopback",
        "APIPA",
        "Multicast",
        "Reservado/Experimental",
        "—",
    ]:
        seguranca_dicas.append(
            {
                "tipo": "primary",
                "icon": "🌍",
                "texto": (
                    "Aviso de Borda: Este é um IP Público. Pode estar voltado à internet. "
                    "Garanta que o Firewall esteja setado como Inbound Deny All por padrão."
                ),
            }
        )
    elif ip_papel == "Endereço de rede":
        seguranca_dicas.append(
            {
                "tipo": "info",
                "icon": "ℹ️",
                "texto": (
                    "Network ID: Usado nas tabelas de roteamento. Scans direcionados para este IP "
                    "não mapeiam hosts internos ativos diretamente."
                ),
            }
        )

    out.update(
        {
            "seguranca_dicas": seguranca_dicas,
            "somente_mascara": False,
            "cidr_origem": "",
            "rede": fmt_ip(r_i),
            "broad": fmt_ip(b_i),
            "primeiro_host": primeiro_host,
            "ultimo_host": ultimo_host,
            "classe": classe,
            "classe_faixa": classe_faixa,
            "classe_variant": classe_variant_css(classe),
            "primeiro_octeto": parts[0],
            "ip_tipo_privacidade": ip_tipo_privacidade,
            "ip_faixa_privacidade": ip_faixa_privacidade,
            "and_table": and_table,
            "proximas_subredes": proximas_subredes,
            "dns_info": "Servidor de nomes (ex.: 8.8.8.8, 1.1.1.1 ou DNS interno)",
            "dhcp_info": f"Faixa dinâmica sugerida: {primeiro_host} até {ultimo_host}",
            "vlan_info": "Segmentação lógica de rede (o ID da VLAN não vem do IP/máscara)",
            "wan_info": "Conexão de longa distância/Internet; normalmente usa IP público",
            "gateway_sugerido": gateway_sugerido,
            "gateway_alternativo": gateway_alternativo,
            "hosts_recomendados": hosts_recomendados,
            "ip_binario_completo": ".".join(bin(p)[2:].zfill(8) for p in parts),
            "ip_papel": ip_papel,
            "ip_papel_alerta": ip_papel_alerta,
            "regua_count": regua_count,
            "resumo_prova": resumo_prova,
            "resumo_prova_itens": resumo_prova_itens,
            "octeto_referencia": octeto_ref,
            "tabela_referencia": tabela_ref,
            "tabela_conversao_bits": tabela_conv,
            "conversao_atual": conv_atual,
            "cisco_cli": (
                "conf t\n"
                "interface g0/0\n"
                f"ip address {primeiro_host} {c['mask']}\n"
                "no shutdown"
            ),
        }
    )
    out.update(tema)
    return out

