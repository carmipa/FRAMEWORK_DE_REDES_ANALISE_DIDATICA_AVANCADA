"""Modo IPv6 na página de análise."""

from backend.analise.ipv6_service import processar_ipv6 as calcular_ipv6
from backend.core.exceptions import EntradaInvalidaError
from backend.core.logging import logger


def processar_modo_ipv6(ipv6_p: str) -> dict:
    invalid_fields: set[str] = set()
    ipv6_res = None
    erro = None

    if not ipv6_p:
        erro = "No modo IPv6, informe um endereço IPv6 válido."
        invalid_fields.add("ipv6")
    else:
        try:
            ipv6_res = calcular_ipv6(ipv6_p)
        except EntradaInvalidaError as exc:
            logger.warning(
                "evento=calc status=invalid_input modo=ipv6 erro=%s", exc
            )
            erro = str(exc)
            invalid_fields.add("ipv6")

    return {
        "erro": erro,
        "ipv6_res": ipv6_res,
        "invalid_fields": invalid_fields,
    }
