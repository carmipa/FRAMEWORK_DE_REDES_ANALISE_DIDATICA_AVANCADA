"""Factory da aplicação Flask — ponto central de blueprints e middleware."""

import threading
import time
import uuid
import webbrowser

from flask import Flask, g, render_template, request
from werkzeug.exceptions import HTTPException

from backend.analise.auto_cidr.auto_cidr_routes import auto_cidr_bp
from backend.analise.cidr.cidr_routes import cidr_bp
from backend.analise.comparador.comparador_routes import comparador_bp
from backend.analise.dominio.dominio_routes import dominio_bp
from backend.analise.geo.geo_routes import geo_bp
from backend.analise.ipv6.ipv6_routes import ipv6_bp
from backend.analise.mascara.mascara_routes import mascara_bp
from backend.analise.portas.portas_routes import portas_bp
from backend.analise.protocolos.protocolos_routes import protocolos_bp
from backend.analise.wildcard.wildcard_routes import wildcard_bp
from backend.config import APP_DEBUG, APP_HOST, APP_OPEN_BROWSER, APP_PORT_RAW
from backend.core.exceptions import HistoricoPersistenciaError
from backend.core.logging import log_event, logger
from backend.resolucao.export.export_routes import export_bp
from backend.resolucao.vlsm.vlsm_routes import resolucao_bp
from backend.suporte.historico.historico_routes import historico_bp
from backend.suporte.historico.historico_service import carregar_historico
from backend.web.app_routes import register_views


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")

    blueprints = (
        cidr_bp,
        mascara_bp,
        wildcard_bp,
        auto_cidr_bp,
        dominio_bp,
        ipv6_bp,
        comparador_bp,
        geo_bp,
        portas_bp,
        protocolos_bp,
        export_bp,
        resolucao_bp,
        historico_bp,
    )
    for bp in blueprints:
        app.register_blueprint(bp)

    register_views(app)

    @app.before_request
    def _before_request_log_context():
        g.request_id = str(uuid.uuid4())[:8]
        g.started_at = time.time()
        log_event(
            "info",
            "request",
            status="start",
            method=request.method,
            path=request.path,
        )

    @app.after_request
    def _after_request_log(response):
        elapsed_ms = int((time.time() - getattr(g, "started_at", time.time())) * 1000)
        log_event(
            "info",
            "request",
            status="end",
            code=response.status_code,
            elapsed_ms=elapsed_ms,
            path=request.path,
        )
        return response

    @app.errorhandler(Exception)
    def _handle_unexpected_error(exc):
        if isinstance(exc, HTTPException):
            return exc
        logger.exception(
            "evento=global_exception status=error tipo=%s",
            exc.__class__.__name__,
        )
        return (
            render_template(
                "analise/index.html",
                res=None,
                erro=(
                    "Erro interno inesperado. O evento foi registrado em log "
                    "para auditoria."
                ),
                ip_pre="",
                cidr_pre="",
                mask_dec_pre="",
                wildcard_pre="",
                regua_count_pre="5",
            ),
            500,
        )

    return app


def run_dev(flask_app: Flask | None = None) -> None:
    """Executa o servidor de desenvolvimento (histórico + browser opcional)."""
    try:
        carregar_historico()
    except HistoricoPersistenciaError as exc:
        logger.warning("evento=app_boot status=history_unavailable erro=%s", exc)
    try:
        app_port = int(APP_PORT_RAW)
    except ValueError:
        logger.warning(
            "evento=app_boot status=invalid_port app_port_raw=%s fallback=5000",
            APP_PORT_RAW,
        )
        app_port = 5000
    app = flask_app if flask_app is not None else create_app()
    log_event(
        "info",
        "app_boot",
        status="start",
        host=APP_HOST,
        port=app_port,
        debug=APP_DEBUG,
        open_browser=APP_OPEN_BROWSER,
    )
    if APP_OPEN_BROWSER and APP_HOST in {"127.0.0.1", "localhost"}:
        threading.Timer(
            1.0,
            lambda: webbrowser.open(f"http://{APP_HOST}:{app_port}"),
        ).start()
    app.run(host=APP_HOST, port=app_port, debug=APP_DEBUG)


if __name__ == "__main__":
    run_dev()
