from backend.analise.cidr_service import inferir_cidr_por_ip, mascara_dotted_para_cidr, parse_ipv4_parts
from backend.core.exceptions import EntradaInvalidaError
from backend.core.logging import log_event


def processar_modo_mascara(ip_p: str, mask_dec_p: str) -> dict:
    invalid_fields = set()
    cidr_val = None
    cidr_origem = ""
    erro = None
    forcar_somente_mascara = False

    cidr_i = mascara_dotted_para_cidr(ip_p) if ip_p else None
    cidr_m = mascara_dotted_para_cidr(mask_dec_p) if mask_dec_p else None

    if not mask_dec_p and not ip_p:
        erro = (
            "No modo Máscara Decimal, informe a máscara contígua (ex.: 255.255.255.240). "
            "Esta aba é só para análise da máscara/prefixo; com IP + máscara use a aba CIDR."
        )
        invalid_fields.add("mask_decimal")
        invalid_fields.add("ip")
    elif mask_dec_p and cidr_m is None:
        try:
            parse_ipv4_parts(mask_dec_p, "Máscara decimal")
            erro = (
                "Máscara decimal inválida. Use máscara contígua "
                "(ex.: 255.255.255.0), não valores como 255.0.255.0."
            )
        except EntradaInvalidaError as exc:
            log_event("warning", "calc", status="invalid_input", modo="mask", campo="mask_decimal", erro=exc)
            erro = str(exc)
            invalid_fields.add("mask_decimal")
    elif not mask_dec_p and ip_p:
        if cidr_i is not None:
            cidr_val = cidr_i
            cidr_origem = (
                f"O valor no campo “Endereço IPv4” é uma máscara contígua (→ /{cidr_val}). "
                "Dica: coloque a máscara no campo Máscara ou deixe o IP vazio — o / (barra) da aula é o do exercício."
            )
            forcar_somente_mascara = True
        else:
            try:
                cidr_val, origem_inferida = inferir_cidr_por_ip(ip_p)
                cidr_origem = f"CIDR inferido automaticamente pelo IP informado. {origem_inferida}."
            except EntradaInvalidaError as exc:
                log_event("warning", "calc", status="invalid_input", modo="mask", campo="ip", erro=exc)
                erro = str(exc)
                invalid_fields.add("ip")
    elif mask_dec_p and not ip_p:
        cidr_val = cidr_m
        cidr_origem = f"Máscara {mask_dec_p} convertida para /{cidr_val}."
    else:
        if cidr_i is not None and cidr_m is not None and cidr_i != cidr_m:
            if ip_p.strip().startswith("255."):
                cidr_val = cidr_i
                cidr_origem = (
                    f"Conflito: o / (barra) usado na aula é /{cidr_val} (máscara 255.x no campo IP, p. ex. /18). "
                    f"O campo Máscara decimal apontava para /{cidr_m} — deixe só um conjunto coerente."
                )
                forcar_somente_mascara = True
            else:
                cidr_val = cidr_m
                cidr_origem = (
                    f"Usando /{cidr_val} a partir do campo Máscara decimal. "
                    f"O endereço {ip_p} também se lê como máscara (→ /{cidr_i}) — use um host (ex.: 10.0.0.1) "
                    "se o exercício for o AND com a máscara do outro campo."
                )
        elif cidr_i is not None and cidr_m is not None and cidr_i == cidr_m:
            cidr_val = cidr_m
            cidr_origem = f"Máscara {mask_dec_p} (e o valor no IP) → /{cidr_val}."
        else:
            cidr_val = cidr_m
            cidr_origem = f"Máscara {mask_dec_p} → /{cidr_val} (rede calculada com o IP {ip_p})."

    return {
        "erro": erro,
        "cidr_val": cidr_val,
        "cidr_origem": cidr_origem,
        "forcar_somente_mascara": forcar_somente_mascara,
        "invalid_fields": invalid_fields,
    }
