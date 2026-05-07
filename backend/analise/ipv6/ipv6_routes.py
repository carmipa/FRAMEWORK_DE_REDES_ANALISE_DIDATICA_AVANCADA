from flask import Blueprint

from backend.analise.ipv6.ipv6_service import processar_modo_ipv6

ipv6_bp = Blueprint("ipv6", __name__)


def processar_payload_ipv6(ipv6_p: str) -> dict:
    return processar_modo_ipv6(ipv6_p)
