from flask import Blueprint

from backend.analise.mascara.mascara_service import processar_modo_mascara

mascara_bp = Blueprint("mascara", __name__)


def processar_payload_mascara(ip_p: str, mask_dec_p: str) -> dict:
    return processar_modo_mascara(ip_p=ip_p, mask_dec_p=mask_dec_p)
