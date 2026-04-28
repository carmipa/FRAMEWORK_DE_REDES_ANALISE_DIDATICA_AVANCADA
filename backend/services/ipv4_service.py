from backend.common import EntradaInvalidaError


def banner_contexto_analise_com_ip(ip_txt, cidr, mask_s, wildcard_s, rede_s, broad_s, total, uties, pulo):
    """Painel inicial didático: deixa explícito para qual /cidr e qual sub-rede vale o restante da página."""
    return {
        "titulo": "Contexto desta análise",
        "subtitulo": (
            "Todos os quadros abaixo (bits, régua, tabela dinâmica, ACL Cisco etc.) "
            "referem-se apenas a este cenário."
        ),
        "itens": [
            {"rotulo": "Prefixo e máscara utilizados", "valor": f"/{cidr} · {mask_s} · wildcard {wildcard_s}"},
            {
                "rotulo": "Cada máscara → um / específico",
                "valor": (
                    f"O /{cidr} vem diretamente desta máscara ({mask_s}): é o número de bits 1 consecutivos a "
                    "contar da esquerda. Se a aula usar outra máscara, o / muda e o tamanho de bloco muda — "
                    "não existe o mesmo / com duas máscaras pontuadas diferentes."
                ),
            },
            {
                "rotulo": "Sub-rede que contém este IP",
                "valor": (
                    f"Rede {rede_s}, broadcast {broad_s}. "
                    f"O IP informado ({ip_txt}) está dentro deste bloco /{cidr}."
                ),
            },
            {
                "rotulo": "Para que serve este / (o que ele “corta” na prática)",
                "valor": (
                    f"Cada rede /{cidr} tem até {total} endereços IPv4 no bloco "
                    f"({uties} em geral atribuíveis a hosts). "
                    f"O “pulo” entre sub-redes vizinhas, no desenho que você estiver vendo, costuma ser {pulo} "
                    f"no octeto em que a rede muda — isso explica de quanto em quanto a rede “destrava”."
                ),
            },
            {
                "rotulo": "Na disciplina aparecem vários / — aqui só este cenário",
                "valor": (
                    "Na mesma disciplina há exercícios com granulometrias diferentes: enlaces podem aparecer como "
                    "/30 ou /31; redes maiores como /18 ou /20; LANs típicas como /24; etc. Isso depende sempre "
                    f"do IP e da máscara da questão (ou só da máscara). Esta análise fixa apenas o seu caso atual: "
                    f"/{cidr} para este conjunto informado."
                ),
            },
        ],
    }


def banner_contexto_analise_so_mascara(cidr, mask_s, wildcard_s, total, uties, pulo):
    """Contexto quando o aluno colocou só a máscara: ainda não há uma rede fixa."""
    return {
        "titulo": "Contexto desta análise (só máscara, sem IP)",
        "subtitulo": (
            "Você definiu o tamanho de bloco (/ e máscara). Os números abaixo valem para qualquer rede com "
            "este prefixo; ainda não há um endereço de rede/broadcast concreto."
        ),
        "itens": [
            {"rotulo": "Prefixo e máscara", "valor": f"/{cidr} · {mask_s} · wildcard {wildcard_s}"},
            {
                "rotulo": "Cada máscara → um / específico",
                "valor": (
                    f"Para {mask_s} o CIDR só pode ser /{cidr} (conta de bits 1 da máscara = {cidr}). "
                    "Não se escolhe o / separado da máscara: ele depende dela. Outro desenho de máscara, outro / e outra tabela de intervalos."
                ),
            },
            {
                "rotulo": "Sub-rede concreta (rede + broadcast)",
                "valor": "Ainda não: informe um endereço IP (modo Máscara ou CIDR) para o framework fechar a sub-rede de exemplo.",
            },
            {
                "rotulo": "Para que serve este /",
                "valor": (
                    f"Indica o tamanho de cada pedaço: {total} endereços por rede (típicos {uties} hosts úteis). "
                    f"O salto entre sub-redes consecutivas, nessa granulometria, costuma ser múltiplo de {pulo} no octeto de variação."
                ),
            },
            {
                "rotulo": "Vários / na aula — um / por máscara de cada vez",
                "valor": (
                    "O material percorre muitos prefixos: /30 em ponto a ponto, /18 ou /19 em blocos maiores, /28 em "
                    "sub-redes pequenas, etc. Cada máscara gera o seu /; esta tela mostra só o "
                    f"que resulta da máscara que acabou de usar: /{cidr}. "
                    "Troque a máscara (ou o IP com outra máscara) e o / e toda a tabela acompanham o novo exercício."
                ),
            },
        ],
    }


def nota_cidr_cisco(cidr):
    """
    Alinhamento didático: no CCNA a ênfase em *endereçamento unicast* é classes A, B e C;
    sub-redes reais usam CIDR/VLSM (ex.: /18) e não precisam ser /8, /16 ou /24.
    """
    if cidr in (8, 16, 24):
        return (
            "Máscara padrão classful: /8 (A), /16 (B) ou /24 (C) — o que o material Cisco costuma associar "
            "a cada classe de rede base."
        )
    return (
        f"Prefixo /{cidr} (CIDR/VLSM): no material Cisco, o estudo de *rede* e *sub-rede* foca nas classes A, B e C; "
        "máscaras como 255.255.192.0 segmentam blocos com qualquer prefixo válido, sem ser a 'classe' de 8, 16 ou 24 sozinha."
    )


def referencia_fixa_classes_abc(o1):
    """
    Referência visual fixa: sempre A, B e C com destaque na que corresponde ao 1º octeto (se houver).
    """
    sel_a = 1 <= o1 <= 126
    sel_b = 128 <= o1 <= 191
    sel_c = 192 <= o1 <= 223
    return [
        {
            "letra": "A",
            "faixa_octeto": "1 – 126",
            "mascara_padrao": "/8 · 255.0.0.0",
            "ativo": sel_a,
        },
        {
            "letra": "B",
            "faixa_octeto": "128 – 191",
            "mascara_padrao": "/16 · 255.255.0.0",
            "ativo": sel_b,
        },
        {
            "letra": "C",
            "faixa_octeto": "192 – 223",
            "mascara_padrao": "/24 · 255.255.255.0",
            "ativo": sel_c,
        },
    ]


def referencia_cartao_unico_abc(letra):
    """
    Um único cartão (A, B ou C) para aula: o aluno foca no / (barra) e na faixa alvo, sem comparar
    as três de uma vez. `letra` deve ser 'A', 'B' ou 'C'; outro valor retorna lista vazia.
    """
    if letra == "E":
        return [{
            "letra": "Classe E teórica",
            "faixa_octeto": "240 – 255",
            "mascara_padrao": "/4 · 240.0.0.0",
            "ativo": True,
        }]
    if letra not in {"A", "B", "C"}:
        return []
    ref = referencia_fixa_classes_abc(1 if letra == "A" else (128 if letra == "B" else 192))
    for c in ref:
        if c["letra"] == letra:
            return [{**c, "ativo": True}]
    return []


def classe_referencia_por_prefixo(cidr):
    """
    Em exercícios só de máscara (VLSM), um único cartão A/B/C alinhado ao “/ (barra)” que está no quadro:
    /1–/8 → A; /9–/23 → B (inclui /16 padrão B e /18 com 255.255.192.0); /24–/32 → C (4.º octeto).
    """
    if not isinstance(cidr, int) or not (0 <= cidr <= 32):
        return None
    if cidr == 4:
        return "E"
    if cidr == 0:
        return "A"
    if 1 <= cidr <= 8:
        return "A"
    if 9 <= cidr <= 23:
        return "B"
    return "C"  # 24-32


def classe_ipv4_didatica(o1):
    """
    Foco didático: o destaque principal é sempre A, B ou C (unicast). Fora disso, a letra exibida
    no painel central fica neutra e o detalhe (D, E, 0, 127) vai para `classe_observacao`.
    Retorno: (classe, classe_faixa, classe_observacao) — observacao pode ser None.
    """
    if 1 <= o1 <= 126:
        return "A", "1º octeto 1–126 — máscara padrão /8 (255.0.0.0)", None
    if 128 <= o1 <= 191:
        return "B", "1º octeto 128–191 — máscara padrão /16 (255.255.0.0)", None
    if 192 <= o1 <= 223:
        return "C", "1º octeto 192–223 — máscara padrão /24 (255.255.255.0)", None

    if o1 == 0:
        return "—", "Fora das faixas A, B e C (unicast do 1º octeto).", (
            "Observação: faixa 0.0.0.0/8 é reservada (não usada como host de produção na Internet)."
        )
    if o1 == 127:
        return "—", "Fora das faixas A, B e C (unicast do 1º octeto).", (
            "Observação: 127.0.0.0/8 é loopback (localhost); não é tratada como classe A/B/C aplicável."
        )
    if 224 <= o1 <= 239:
        return "—", "Fora das faixas A, B e C (unicast do 1º octeto).", (
            "Observação (modelo classful completo): 1º octeto 224–239 = faixa D, "
            "endereçamento multicast (não é host unicast)."
        )
    if 240 <= o1 <= 255:
        return "—", "Fora das faixas A, B e C (unicast do 1º octeto).", (
            "Observação (modelo classful completo): 1º octeto 240–255 = faixa E, "
            "reservada / experimental (não atribuível a host comum)."
        )
    return "—", "Indefinido para o 1º octeto.", None


def classe_variant_css(classe):
    """Slug estável para classes CSS do banner de destaque."""
    return {
        "A": "a",
        "B": "b",
        "C": "c",
        "—": "outros",
    }.get(classe, "outros")


def privacidade_rfc1918(parts):
    """Identifica tipo de IP para cenários comuns de prova."""
    o1, o2, o3, o4 = parts[0], parts[1], parts[2], parts[3]
    if o1 == 0:
        return "Especial", "Faixa 0.0.0.0/8 (Rede atual / especial)"
    if o1 == 255 and o2 == 255 and o3 == 255 and o4 == 255:
        return "Broadcast Limitado", "Endereço 255.255.255.255"
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
        return 8, "Inferido (classful): 0.x.x.x => /8"
    if 1 <= o1 <= 126:
        return 8, "Inferido (classful): classe A => /8"
    if o1 == 127:
        return 8, "Inferido (classful): loopback 127.x.x.x => /8"
    if 128 <= o1 <= 191:
        return 16, "Inferido (classful): classe B => /16"
    if 192 <= o1 <= 223:
        return 24, "Inferido (classful): classe C => /24"
    if 224 <= o1 <= 239:
        return 4, "Inferido (classful): classe D (multicast) => /4"
    return 4, "Inferido (classful): classe E (reservada) => /4"


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
    if cidr > 24:
        pulo = 2 ** (32 - cidr)
    elif cidr > 16:
        pulo = 2 ** (24 - cidr)
    elif cidr > 8:
        pulo = 2 ** (16 - cidr)
    else:
        pulo = 2 ** (8 - cidr)

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
    """
    Lógica didática **só de sub-rede / prefixo** (máscara, /, intervalos, tamanho de bloco).
    Não usa endereço de host: `enunciado_prova` e tabelas valem para o tamanho de rede, não para “um IP na mesa”.
    """
    c = core_mascara(cidr)
    if c is None:
        return None
    out = {k: v for k, v in c.items() if k != "_m_i"}
    octeto_ref, tabela_ref = tabela_referencia_subredes(cidr)
    tabela_conv, conv_atual = tabela_conversao_bits(cidr)
    tema = tema_dinamico(cidr, c["total"])
    out["somente_mascara"] = True
    out["contexto_didatico"] = "prefixo_subrede"
    out["cidr_origem"] = ""
    out["octeto_referencia"] = octeto_ref
    out["tabela_referencia"] = tabela_ref
    out["tabela_conversao_bits"] = tabela_conv
    out["conversao_atual"] = conv_atual
    out.update(tema)
    out["rede"] = out["broad"] = out["primeiro_host"] = out["ultimo_host"] = "—"
    out["nota_cidr_cisco"] = nota_cidr_cisco(cidr)
    letra_ref = classe_referencia_por_prefixo(cidr)
    out["classes_abc_fixas"] = referencia_cartao_unico_abc(letra_ref) if letra_ref else []
    
    if cidr == 4:
        out["classe_observacao"] = (
            "Representa teoricamente o bloco 240.0.0.0/4, associado à faixa Classe E/reservada: "
            "240.0.0.0 até 255.255.255.255. Não é usado como máscara comum em redes locais."
        )
    else:
        out["classe_observacao"] = (
            "Foco em aula: o que importa é o / (barra) e a máscara no quadro; o cartão mostra só a referência A/B/C "
            "que costuma acompanhar esse prefixo no material (ex.: /18 → B)."
        )
    out["classe"] = letra_ref or "—"
    out["classe_faixa"] = (
        f"Prefixo em estudo: /{cidr} com máscara {out['mask']} — acompanhe só essa barra na conversão binária e na tabela."
    )
    out["classe_variant"] = classe_variant_css(letra_ref) if letra_ref else "outros"
    out["primeiro_octeto"] = None
    out["banner_contexto"] = banner_contexto_analise_so_mascara(
        cidr,
        out["mask"],
        out["wildcard"],
        c["total"],
        c["uteis"],
        c["pulo"],
    )
    out["ip_informado"] = None
    out["enunciado_prova"] = enunciado_prova_intervalos(
        cidr, c["pulo"], c["total"], c["uteis"], octeto_ref
    )
    out["texto_copia"] = (
        f"Máscara: {c['mask']}\n"
        f"CIDR: /{cidr}\n"
        f"Wildcard: {c['wildcard']}\n"
        f"Total de hosts (bloco): {c['total']}\n"
        f"Hosts úteis: {c['uteis']}"
    )
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


def _potencia_de_2_expoente(n):
    """Se n é potência de 2 (>0), retorna o expoente k tal que n = 2^k; senão None."""
    if not isinstance(n, int) or n <= 0:
        return None
    if n & (n - 1):
        return None
    return n.bit_length() - 1


def enunciado_prova_intervalos(cidr, pulo, total, uteis, octeto_referencia):
    """
    Itens comuns em provas BR, dada a máscara/CIDR: quantidade de intervalos no octeto
    de variação, passo (variação) e capacidade por sub-rede (total e hosts úteis).
    Alinhado a `resumo_abertura_intervalos` (256 // pulo no octeto de referência).
    """
    if pulo > 0:
        qtde_intervalos = max(1, 256 // pulo)
    else:
        qtde_intervalos = 1
    nota = ""
    if cidr == 31:
        nota = (
            "Em /31 (RFC 3021) os dois endereços do bloco costumam ser usáveis em enlace ponto a ponto; "
            "a regra clássica 2^n−2 de “rede + broadcast” não se aplica do mesmo modo."
        )
    elif cidr == 32:
        nota = "Em /32 há um único endereço; não há subtração de rede e broadcast em sub-rede com 1 IP."
    # Frase no estilo de quadro/slide (prova BR), alinhada ao material didático comum.
    end_cli = "endereço" if total == 1 else "endereços"
    frase_estilo_quadro = (
        f"{qtde_intervalos} intervalos que variam de {pulo} em {pulo} no {octeto_referencia}º octeto; "
        f"cada intervalo comporta {total} {end_cli} no bloco"
    )
    if uteis != total:
        frase_estilo_quadro += f" ({uteis} em geral atribuíveis a hosts, descontando rede e broadcast)."
    else:
        frase_estilo_quadro += "."
    eq_q = _potencia_de_2_expoente(qtde_intervalos)
    eq_p = _potencia_de_2_expoente(pulo)
    eq_ips = _potencia_de_2_expoente(total)
    partes_quadro = []
    if eq_q is not None and eq_p is not None:
        partes_quadro.append(
            f"Potências (estilo quadro / slide): 2^{eq_q} = {qtde_intervalos} (intervalos no {octeto_referencia}º octeto); "
            f"2^{eq_p} = {pulo} (variação / salto entre redes consecutivas nesse octeto)."
        )
    if eq_ips is not None and total > 0:
        partes_quadro.append(
            f" Cada intervalo: 2^{eq_ips} = {total} endereços no bloco (como no enunciado “IPs disponíveis” no total do bloco)."
        )
    linha_potencias_quadro = "".join(partes_quadro).strip()
    return {
        "qtde_intervalos": qtde_intervalos,
        "variacao": pulo,
        "ips_total_por_subrede": total,
        "ips_uteis_por_subrede": uteis,
        "octeto_referencia": octeto_referencia,
        "nota": nota,
        "frase_estilo_quadro": frase_estilo_quadro,
        "linha_potencias_quadro": linha_potencias_quadro,
    }


def resumo_abertura_intervalos(cidr, pulo, total, uteis, rede, broad, octeto_referencia, proximas_subredes):
    intervalos_no_octeto = max(1, 256 // pulo) if pulo > 0 else 1
    exemplos = [
        {"nome": s["nome"], "faixa": f"{s['rede']} até {s['broadcast']}"}
        for s in proximas_subredes[:4]
    ]
    return {
        "intervalos_no_octeto": intervalos_no_octeto,
        "pulo": pulo,
        "ips_por_bloco": total,
        "uteis_por_bloco": uteis,
        "rede_atual": rede,
        "broadcast_atual": broad,
        "octeto_referencia": octeto_referencia,
        "titulo": (
            f"{intervalos_no_octeto} intervalos variam de {pulo} em {pulo} "
            f"no octeto {octeto_referencia}"
        ),
        "faixa_atual": f"{rede} até {broad}/{cidr}",
        "exemplos": exemplos,
    }


def processar(ip_s, cidr, regua_count=5):
    """
    Lógica didática **com endereço IP (host)**: classe/1.º octeto, AND, rede, broadcast, hosts, papel do IP.
    Não mistura o bloco “resposta tipo prova (máscara pura)” — esse fica em `processar_somente_mascara`.
    """
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

    classe, classe_faixa, classe_observacao = classe_ipv4_didatica(parts[0])
    if classe in {"A", "B", "C"}:
        classes_abc_fixas = referencia_cartao_unico_abc(classe)
    else:
        classes_abc_fixas = []
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
    abertura_intervalos = resumo_abertura_intervalos(
        cidr=cidr,
        pulo=c["pulo"],
        total=c["total"],
        uteis=c["uteis"],
        rede=fmt_ip(r_i),
        broad=fmt_ip(b_i),
        octeto_referencia=octeto_ref,
        proximas_subredes=proximas_subredes,
    )
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
        
    # Detecção de IPs Especiais para fins didáticos/segurança
    if ip_tipo_privacidade == "Reservado/Experimental":
        seguranca_dicas.append({
            "tipo": "danger",
            "icon": "🚫",
            "texto": "Endereço Classe E / Reservado. Não deve ser usado para hosts comuns em LAN ou WAN."
        })
    elif ip_tipo_privacidade == "Multicast":
        seguranca_dicas.append({
            "tipo": "info",
            "icon": "📡",
            "texto": "Endereço Classe D / Multicast. Usado para transmitir tráfego para múltiplos hosts simultaneamente (ex: OSPF, IPTV)."
        })
    elif ip_tipo_privacidade == "Loopback":
        seguranca_dicas.append({
            "tipo": "info",
            "icon": "🔁",
            "texto": "Endereço de Loopback. Usado para testar a pilha TCP/IP local no próprio dispositivo."
        })
    elif ip_tipo_privacidade == "APIPA":
        seguranca_dicas.append({
            "tipo": "warning",
            "icon": "⚠️",
            "texto": "Link-Local / APIPA. Ocorre quando o dispositivo falha em obter IP via DHCP."
        })
    elif ip_tipo_privacidade == "Especial":
        seguranca_dicas.append({
            "tipo": "warning",
            "icon": "🔍",
            "texto": "Rede Especial (0.x.x.x). Usado como rede atual ou default route (0.0.0.0), não aplicável como host normal."
        })
    elif ip_tipo_privacidade == "Broadcast Limitado":
        seguranca_dicas.append({
            "tipo": "danger",
            "icon": "📣",
            "texto": "Broadcast Limitado (255.255.255.255). Envia pacotes a todos os hosts da mesma rede local, não é roteado além do roteador."
        })
        
    if "Privado" not in ip_tipo_privacidade and ip_tipo_privacidade not in [
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
            "contexto_didatico": "ip_host",
            "cidr_origem": "",
            "rede": fmt_ip(r_i),
            "broad": fmt_ip(b_i),
            "primeiro_host": primeiro_host,
            "ultimo_host": ultimo_host,
            "classe": classe,
            "classe_faixa": classe_faixa,
            "classe_observacao": classe_observacao,
            "classes_abc_fixas": classes_abc_fixas,
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
            "abertura_intervalos": abertura_intervalos,
            "tabela_referencia": tabela_ref,
            "tabela_conversao_bits": tabela_conv,
            "conversao_atual": conv_atual,
            "cisco_cli": (
                "conf t\n"
                "interface g0/0\n"
                f"ip address {primeiro_host} {c['mask']}\n"
                "no shutdown"
            ),
            "nota_cidr_cisco": nota_cidr_cisco(cidr),
            "banner_contexto": banner_contexto_analise_com_ip(
                fmt_ip(ip_i),
                cidr,
                c["mask"],
                c["wildcard"],
                fmt_ip(r_i),
                fmt_ip(b_i),
                c["total"],
                c["uteis"],
                c["pulo"],
            ),
            "ip_informado": fmt_ip(ip_i),
            "texto_copia": (
                f"IP analisado: {fmt_ip(ip_i)}\n"
                f"CIDR: /{cidr}\n"
                f"Máscara: {c['mask']}\n"
                f"Wildcard: {c['wildcard']}\n"
                f"Rede: {fmt_ip(r_i)}\n"
                f"Broadcast: {fmt_ip(b_i)}\n"
                f"Hosts válidos: {primeiro_host} até {ultimo_host}\n"
                f"Total de hosts: {c['total']}\n"
                f"RFC1918: {'Sim' if 'Privado' in ip_tipo_privacidade else 'Não'}"
            ),
        }
    )
    out.update(tema)
    return out

