from flask import Blueprint

from backend.analise.geo.geo_service import executar_api_informacoes_geo

geo_bp = Blueprint("geo", __name__)


def processar_payload_api_geo(cliente_ip: str, raw_digitado: str) -> dict:
    return executar_api_informacoes_geo(cliente_ip, raw_digitado)
