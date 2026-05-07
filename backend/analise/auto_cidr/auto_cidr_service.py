"""Modo autoip — inferência de CIDR a partir do endereço IPv4."""

from backend.analise.cidr_service import inferir_cidr_por_ip
from backend.core.exceptions import EntradaInvalidaError
from backend.core.logging import logger


def processar_modo_auto_cidr(ip_p: str) -> dict:
    invalid_fields: set[str] = set()
    cidr_val = None
    cidr_origem = ""
    erro = None

    if not ip_p:
        erro = "No modo Descobrir CIDR do IP, informe um endereço IP."
        invalid_fields.add("ip")
    else:
        try:
            cidr_val, cidr_origem = inferir_cidr_por_ip(ip_p)
        except EntradaInvalidaError as exc:
            logger.warning(
                "evento=calc status=invalid_input modo=autoip campo=ip erro=%s",
                exc,
            )
            erro = str(exc)
            invalid_fields.add("ip")

    return {
        "erro": erro,
        "cidr_val": cidr_val,
        "cidr_origem": cidr_origem,
        "invalid_fields": invalid_fields,
    }
