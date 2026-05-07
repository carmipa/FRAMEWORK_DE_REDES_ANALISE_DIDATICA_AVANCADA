from backend.analise.cidr_service import parse_ipv4_parts, wildcard_dotted_para_cidr
from backend.core.exceptions import EntradaInvalidaError
from backend.core.logging import logger


def processar_modo_wildcard(ip_p: str, wildcard_p: str) -> dict:
    invalid_fields = set()
    cidr_val = None
    erro = None

    if not ip_p and not wildcard_p:
        erro = "No modo Wildcard, informe os dois campos: IP e wildcard mask."
        invalid_fields.add("ip")
        invalid_fields.add("wildcard_mask")
    elif not ip_p:
        erro = "No modo Wildcard, informe também o endereço IP."
        invalid_fields.add("ip")
    elif not wildcard_p:
        erro = "No modo Wildcard, preencha também a wildcard mask (ex.: 0.0.15.255)."
        invalid_fields.add("wildcard_mask")
    else:
        cidr_val = wildcard_dotted_para_cidr(wildcard_p)
        if cidr_val is None:
            try:
                parse_ipv4_parts(wildcard_p, "Wildcard mask")
                erro = (
                    "Wildcard inválida. Use formato x.x.x.x com inverso de máscara contígua "
                    "(ex.: 0.0.15.255)."
                )
            except EntradaInvalidaError as exc:
                logger.warning("evento=calc status=invalid_input modo=wildcard campo=wildcard_mask erro=%s", exc)
                erro = str(exc)
                invalid_fields.add("wildcard_mask")

    return {
        "erro": erro,
        "cidr_val": cidr_val,
        "invalid_fields": invalid_fields,
    }
