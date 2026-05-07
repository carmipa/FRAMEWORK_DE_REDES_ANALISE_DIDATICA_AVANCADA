from flask import Blueprint

from backend.analise.wildcard.wildcard_service import processar_modo_wildcard

wildcard_bp = Blueprint("wildcard", __name__)


def processar_payload_wildcard(ip_p: str, wildcard_p: str) -> dict:
    return processar_modo_wildcard(ip_p=ip_p, wildcard_p=wildcard_p)
