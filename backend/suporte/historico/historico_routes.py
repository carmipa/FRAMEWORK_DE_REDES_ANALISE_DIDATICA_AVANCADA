from flask import Blueprint, jsonify, request

from backend.core.exceptions import HistoricoPersistenciaError
from backend.core.logging import logger
from backend.suporte.historico.historico_service import (
    list_history,
    registrar_consulta,
)

historico_bp = Blueprint("historico", __name__)


@historico_bp.route("/history", methods=["GET"])
def history_api():
    return jsonify({"items": list_history()})


@historico_bp.route("/history/catalog", methods=["POST"])
def history_catalog():
    payload = request.get_json(silent=True) or {}
    modo = (payload.get("modo") or "").strip().lower()
    if modo not in {"portas", "protocolos"}:
        return jsonify({"ok": False, "erro": "modo inválido"}), 400
    entrada = payload.get("entrada") or ""
    try:
        registrar_consulta(
            {
                "modo": modo,
                "ip": entrada,
                "ipv6": "",
                "cidr": "",
                "mask_decimal": "",
                "wildcard_mask": "",
            },
            {
                "rede": "N/A",
                "broad": "N/A",
                "mask": "N/A",
                "cidr": "",
                "nivel_tema": f"Consulta de catálogo: {modo}",
            },
        )
    except HistoricoPersistenciaError as exc:
        logger.warning(
            "evento=history_catalog status=warn modo=%s erro=%s",
            modo,
            exc,
        )
        return jsonify({"ok": False, "erro": "persistencia_indisponivel"}), 503
    return jsonify({"ok": True})
