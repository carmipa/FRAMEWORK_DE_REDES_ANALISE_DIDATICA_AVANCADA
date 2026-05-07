from flask import Blueprint

from backend.analise.cidr.cidr_service import processar_modo_cidr

cidr_bp = Blueprint("cidr", __name__)


def processar_payload_cidr(ip_p: str, cidr_raw: str) -> dict:
    return processar_modo_cidr(ip_p, cidr_raw)
