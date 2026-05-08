from flask import Blueprint, jsonify
from backend.analise.mascara.mascara_service import processar_modo_mascara
from backend.analise.mascara.mascara_reference import get_reference_table

mascara_bp = Blueprint("mascara", __name__)

def processar_payload_mascara(ip_p, mask_dec_p):
    return processar_modo_mascara(ip_p=ip_p, mask_dec_p=mask_dec_p)

@mascara_bp.route("/mascara-referencia", methods=["GET"])
def mascara_referencia_api():
    return jsonify(get_reference_table())
