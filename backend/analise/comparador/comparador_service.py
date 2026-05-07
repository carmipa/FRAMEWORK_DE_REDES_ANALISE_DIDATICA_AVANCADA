"""Modo comparador de dois prefixos CIDR para o mesmo host."""

from backend.analise.cidr_service import processar
from backend.core.exceptions import EntradaInvalidaError


def processar_modo_comparador(
    ip_p: str,
    comparador_cidr_a: str,
    comparador_cidr_b: str,
) -> dict:
    invalid_fields: set[str] = set()
    comparador_cards: list[dict] = []
    comparador_ip = ""
    erro = None

    if not ip_p:
        erro = "No modo Comparador CIDR, informe um endereço IP."
        invalid_fields.add("ip")
        return {
            "erro": erro,
            "comparador_cards": comparador_cards,
            "comparador_ip": comparador_ip,
            "invalid_fields": invalid_fields,
        }

    cidrs_txt = [comparador_cidr_a, comparador_cidr_b]
    for idx, cidr_txt in enumerate(cidrs_txt, start=1):
        if not cidr_txt.isdigit():
            erro = f"CIDR {idx} do comparador deve ser número inteiro entre 0 e 32."
            break
        cidr_cmp = int(cidr_txt)
        if not (0 <= cidr_cmp <= 32):
            erro = f"CIDR {idx} do comparador deve estar entre 0 e 32."
            break

    if erro:
        return {
            "erro": erro,
            "comparador_cards": comparador_cards,
            "comparador_ip": comparador_ip,
            "invalid_fields": invalid_fields,
        }

    try:
        comparador_ip = ip_p
        for cidr_txt in cidrs_txt:
            cidr_cmp = int(cidr_txt)
            cmp_res = processar(ip_p, cidr_cmp, regua_count=5)
            comparador_cards.append(
                {
                    "cidr": cidr_cmp,
                    "mask": cmp_res["mask"],
                    "pulo": cmp_res["pulo"],
                    "uteis": cmp_res["uteis"],
                    "rede": cmp_res["rede"],
                    "broadcast": cmp_res["broad"],
                    "nivel_tema": cmp_res["nivel_tema"],
                }
            )
    except EntradaInvalidaError as exc:
        erro = str(exc)
        invalid_fields.add("ip")

    return {
        "erro": erro,
        "comparador_cards": comparador_cards,
        "comparador_ip": comparador_ip,
        "invalid_fields": invalid_fields,
    }
