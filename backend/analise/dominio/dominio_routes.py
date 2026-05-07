from flask import Blueprint

from backend.analise.dominio.dominio_service import processar_modo_dominio

dominio_bp = Blueprint("dominio", __name__)


def processar_payload_dominio(ip_entrada_bruta: str, cidr_raw: str) -> dict:
    return processar_modo_dominio(ip_entrada_bruta, cidr_raw)
