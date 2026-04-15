def grc_resumo(res):
    if not res or res.get("somente_mascara"):
        return []
    cidr = int(res.get("cidr", 0))
    total = int(res.get("total", 0))
    tipo = res.get("ip_tipo_privacidade", "N/A")
    risco = res.get("nivel_tema", "N/A")
    superficie = "Alta" if total >= 65536 else "Média" if total >= 256 else "Baixa"
    recomendacao = (
        "Segmentar sub-redes e aplicar ACL por zona."
        if cidr <= 16
        else "Manter hardening e revisão periódica de regras."
    )
    return [
        f"Risco atual: {risco} ({tipo}).",
        f"Superfície estimada: {superficie} ({total} IPs no bloco).",
        f"Recomendação objetiva: {recomendacao}",
    ]

