from flask import Blueprint, g, jsonify, redirect, send_file, url_for

from backend.resolucao.export.pdf_service import gerar_pdf_simples
from backend.suporte.historico.historico_service import list_history, utc_now_iso

export_bp = Blueprint("export", __name__)


@export_bp.route("/export/json", methods=["GET"])
def export_json():
    payload = {
        "generated_at": utc_now_iso(),
        "history": list_history(),
        "last_request_id": getattr(g, "request_id", "-"),
    }
    return jsonify(payload)


@export_bp.route("/export/pdf", methods=["GET"])
def export_pdf():
    history = list_history()
    if not history:
        return redirect(url_for("home"))
    last = history[0]
    lines = [
        "Relatório Didático de Rede (GRC)",
        f"Gerado em: {utc_now_iso()}",
        f"Consulta ID: {last.get('id', '-')}",
        f"Modo: {last.get('modo', '-')}",
        f"Entrada: {last.get('ipv6_entrada') or last.get('ip_entrada', '-')}",
        f"CIDR entrada: {last.get('cidr_entrada', '-')}",
        f"Máscara: {last.get('mask', '-')}",
        f"CIDR final: /{last.get('cidr', '-')}",
        f"Rede: {last.get('rede', '-')}",
        f"Broadcast: {last.get('broadcast', '-')}",
        f"Tema/Risco: {last.get('tema', '-')}",
        "",
        "Objetivo: evidência de cálculo e contexto GRC para aula/auditoria.",
    ]
    pdf_io = gerar_pdf_simples("\n".join(lines))
    return send_file(
        pdf_io,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="relatorio_rede_grc.pdf",
    )
