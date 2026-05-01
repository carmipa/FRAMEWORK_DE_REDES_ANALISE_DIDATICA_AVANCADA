from urllib.parse import urlparse


def normalizar_hostname_entrada(entrada: str) -> str:
    bruto = (entrada or "").strip()
    if not bruto:
        return ""
    parece_url = "://" in bruto or bruto.startswith("//") or any(
        sep in bruto for sep in ["/", "?", "#", ":"]
    )
    if not parece_url:
        return bruto.strip(".")
    alvo_parse = bruto if "://" in bruto else f"//{bruto}"
    parsed = urlparse(alvo_parse, scheme="http")
    if parsed.hostname:
        return parsed.hostname.strip().strip(".")
    return bruto.strip(".")


def montar_wizard_calculo(res):
    if not res or res.get("somente_mascara"):
        return []
    texto_classe = f"Classe {res.get('classe')} ({res.get('classe_faixa')})."
    if res.get("classe_observacao"):
        texto_classe += f" {res.get('classe_observacao')}"
    return [
        {
            "icone": "🧭",
            "etapa": "Classe/faixa",
            "acao": f"Identificar o 1º octeto ({res.get('primeiro_octeto')})",
            "resultado": texto_classe,
        },
        {
            "icone": "📏",
            "etapa": "Máscara",
            "acao": f"Converter /{res.get('cidr')} para máscara",
            "resultado": f"{res.get('mask')} (wildcard {res.get('wildcard')}).",
        },
        {
            "icone": "🧠",
            "etapa": "Rede (AND)",
            "acao": "Aplicar IP & máscara",
            "resultado": f"Rede calculada: {res.get('rede')}.",
        },
        {
            "icone": "📣",
            "etapa": "Hosts/Broadcast",
            "acao": "Calcular intervalo de hosts",
            "resultado": (
                f"1º útil {res.get('primeiro_host')} | "
                f"último útil {res.get('ultimo_host')} | "
                f"broadcast {res.get('broad')}."
            ),
        },
    ]


def montar_timeline_bloco(res):
    if not res or res.get("somente_mascara"):
        return None
    papel = (res.get("ip_papel") or "").lower()
    if "rede" in papel:
        posicao = "rede"
    elif "broadcast" in papel:
        posicao = "broadcast"
    else:
        posicao = "hosts"
    return {
        "rede": res.get("rede"),
        "primeiro_host": res.get("primeiro_host"),
        "ultimo_host": res.get("ultimo_host"),
        "broadcast": res.get("broad"),
        "ip": res.get("resumo_prova_itens", [{}])[0].get("valor", ""),
        "posicao": posicao,
    }


def explicar_erro_didatico(erro):
    txt = (erro or "").strip()
    if not txt:
        return None
    rules = [
        (
            "IP inválido",
            "O campo IP deve estar em IPv4 com 4 octetos numéricos.",
            "Use formato x.x.x.x (ex.: 172.19.0.10).",
        ),
        (
            "CIDR",
            "O prefixo precisa ser inteiro entre 0 e 32.",
            "Exemplos válidos: 8, 16, 20, 24, 30.",
        ),
        (
            "Máscara decimal inválida",
            "A máscara precisa ter bits contíguos de rede.",
            "Use máscara contínua, como 255.255.255.0.",
        ),
        (
            "Wildcard inválida",
            "A wildcard deve ser o inverso de uma máscara contígua.",
            "Ex.: 0.0.15.255 corresponde a /20.",
        ),
        (
            "domínio",
            "O domínio/hostname não pôde ser resolvido no DNS.",
            "Teste com google.com e confira conectividade DNS.",
        ),
    ]
    lower = txt.lower()
    for marker, causa, como in rules:
        if marker.lower() in lower:
            return {"causa": causa, "como_corrigir": como}
    return {
        "causa": "A entrada não passou nas validações do modo selecionado.",
        "como_corrigir": "Revise os campos obrigatórios do modo e tente novamente.",
    }


def motivo_analise(modo: str) -> str:
    mapa = {
        "cidr": "Usuário pediu cálculo de sub-rede CIDR para validar rede/hosts.",
        "mask": "Usuário pediu decomposição didática de máscara decimal e barra.",
        "wildcard": "Usuário pediu conversão wildcard para uso em ACL/OSPF.",
        "autoip": "Usuário pediu descoberta automática de CIDR a partir do IP.",
        "dominio": "Usuário pediu resolução DNS e decomposição técnica do destino.",
        "ipv6": "Usuário pediu análise didática de endereço IPv6.",
        "comparador": "Usuário pediu comparação lado a lado entre dois prefixos CIDR.",
        "portas": "Usuário consultou catálogo de portas para estudo/auditoria.",
        "protocolos": "Usuário consultou catálogo de protocolos para estudo/auditoria.",
    }
    return mapa.get(modo, "Usuário executou análise técnica no framework.")
