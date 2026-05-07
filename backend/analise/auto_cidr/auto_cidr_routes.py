from flask import Blueprint

from backend.analise.auto_cidr.auto_cidr_service import processar_modo_auto_cidr

auto_cidr_bp = Blueprint("auto_cidr", __name__)


def processar_payload_auto_cidr(ip_p: str) -> dict:
    return processar_modo_auto_cidr(ip_p)
