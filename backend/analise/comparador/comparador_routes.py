from flask import Blueprint

from backend.analise.comparador.comparador_service import processar_modo_comparador

comparador_bp = Blueprint("comparador", __name__)


def processar_payload_comparador(
    ip_p: str,
    comparador_cidr_a: str,
    comparador_cidr_b: str,
) -> dict:
    return processar_modo_comparador(ip_p, comparador_cidr_a, comparador_cidr_b)
