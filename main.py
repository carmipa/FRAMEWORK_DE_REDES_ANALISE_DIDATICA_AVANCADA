import os
import threading
import time
import uuid
import webbrowser
from urllib.parse import urlparse

from flask import Flask, abort, g, jsonify, redirect, render_template, request, send_file, url_for
from werkzeug.exceptions import HTTPException

from backend.common import BASE_DIR, EntradaInvalidaError, MAX_HISTORY, logger
from backend.services.dns_service import resolver_dns_com_cache
from backend.services.grc_service import grc_resumo
from backend.services.history_service import (
    carregar_historico,
    list_history,
    paginate_history,
    registrar_consulta,
    utc_now_iso,
)
from backend.services.ipv4_service import (
    inferir_cidr_por_ip,
    mascara_dotted_para_cidr,
    parse_ipv4_parts,
    processar,
    processar_somente_mascara,
    wildcard_dotted_para_cidr,
)
from backend.services.ipv6_service import processar_ipv6
from backend.services.pdf_service import gerar_pdf_simples

app = Flask(__name__)


def normalizar_hostname_entrada(entrada: str) -> str:
    bruto = (entrada or "").strip()
    if not bruto:
        return ""
    parece_url = "://" in bruto or bruto.startswith("//") or any(sep in bruto for sep in ["/", "?", "#", ":"])
    if not parece_url:
        return bruto.strip(".")
    alvo_parse = bruto if "://" in bruto else f"//{bruto}"
    parsed = urlparse(alvo_parse, scheme="http")
    if parsed.hostname:
        return parsed.hostname.strip().strip(".")
    return bruto.strip(".")


@app.route("/", methods=["GET", "POST"])
def home():
    res, erro = None, None
    ip_p, cidr_p, mask_dec_p, wildcard_p, ipv6_p = "", "", "", "", ""
    regua_count_pre = "5"
    history_limit_pre = "1"
    history_page_pre = "1"
    cidr_origem = ""
    ipv6_res = None
    invalid_fields = set()

    replay_id = request.args.get("replay", "").strip()
    history_limit_qs = request.args.get("history_limit", "").strip()
    history_page_qs = request.args.get("history_page", "").strip()
    if history_limit_qs.isdigit():
        history_limit_pre = history_limit_qs
    if history_page_qs.isdigit():
        history_page_pre = history_page_qs
    if request.method == "GET" and replay_id:
        selected = next((item for item in list_history() if item.get("id") == replay_id), None)
        if selected:
            if selected.get("modo") == "ipv6":
                ipv6_p = selected.get("ipv6_entrada") or selected.get("ip_entrada", "")
                ip_p = ""
            else:
                ip_p = selected.get("ip_entrada", "")
                ipv6_p = selected.get("ipv6_entrada", "")
            cidr_p = selected.get("cidr_entrada", "")
            mask_dec_p = selected.get("mask_entrada", "")
            wildcard_p = selected.get("wildcard_entrada", "")

    if request.method == "POST":
        logger.info("Iniciando processamento de POST na rota principal")
        ip_p = request.form.get("ip", "").strip()
        ip_entrada_original = ip_p
        ipv6_p = request.form.get("ipv6", "").strip()
        cidr_raw = request.form.get("cidr", "").strip()
        mask_dec_p = request.form.get("mask_decimal", "").strip()
        wildcard_p = request.form.get("wildcard_mask", "").strip()
        regua_count_pre = request.form.get("regua_count", "5").strip() or "5"
        history_limit_pre = request.form.get("history_limit", history_limit_pre).strip() or history_limit_pre
        history_page_pre = request.form.get("history_page", history_page_pre).strip() or history_page_pre
        modo = request.form.get("modo", "").strip().lower()

        if modo != "dominio" and ip_p and not all(c.isdigit() or c == "." for c in ip_p):
            try:
                logger.info("Tentando resolver DNS automaticamente para entrada não numérica")
                ip_p = resolver_dns_com_cache(ip_p)
            except Exception:
                logger.exception("Falha na resolução DNS automática")
                erro = f"Não foi possível resolver o domínio informado: {ip_p}"

        try:
            regua_count = int(regua_count_pre)
        except ValueError:
            regua_count = 5
        if regua_count not in {5, 10, 15}:
            regua_count = 5
        regua_count_pre = str(regua_count)

        cidr_val = None
        if modo not in {"cidr", "mask", "wildcard", "autoip", "dominio", "ipv6"}:
            if cidr_raw:
                modo = "cidr"
            elif mask_dec_p:
                modo = "mask"
            elif wildcard_p:
                modo = "wildcard"
            elif ipv6_p:
                modo = "ipv6"
            elif ip_p:
                modo = "autoip"
            else:
                erro = "Selecione um modo e preencha o campo correspondente."
                invalid_fields.add("modo")

        if erro is None and modo == "ipv6":
            if not ipv6_p:
                erro = "No modo IPv6, informe um endereço IPv6 válido."
                invalid_fields.add("ipv6")
            else:
                try:
                    ipv6_res = processar_ipv6(ipv6_p)
                    registrar_consulta(
                        {
                            "modo": modo,
                            "ip": "",
                            "ipv6": ipv6_p,
                            "cidr": "",
                            "mask_decimal": "",
                            "wildcard_mask": "",
                        },
                        {
                            "rede": ipv6_res.get("primeiros_64", ""),
                            "broad": "N/A em IPv6",
                            "mask": ipv6_res.get("prefixo_sugerido", ""),
                            "cidr": "64",
                            "nivel_tema": "IPv6 didático",
                        },
                    )
                except EntradaInvalidaError as exc:
                    logger.warning("IPv6 inválido: %s", exc)
                    erro = str(exc)
                    invalid_fields.add("ipv6")

        if erro is None and modo == "dominio":
            dominio_digitado = normalizar_hostname_entrada(ip_entrada_original)
            if not dominio_digitado:
                erro = "No modo Decompor Domínio para IP, informe um domínio/hostname (ex.: google.com)."
                invalid_fields.add("ip")
            elif "." not in dominio_digitado and not dominio_digitado.replace("-", "").isalnum():
                erro = "Domínio/hostname inválido. Use algo como google.com ou servidor.local."
                invalid_fields.add("ip")
            else:
                try:
                    logger.info("Modo domínio acionado para hostname informado")
                    ip_p = resolver_dns_com_cache(dominio_digitado)
                    if cidr_raw:
                        cidr_val = int(cidr_raw)
                        cidr_origem = (
                            f"Domínio '{dominio_digitado}' resolvido para {ip_p}. "
                            "CIDR informado manualmente."
                        )
                    else:
                        cidr_val, origem_inferida = inferir_cidr_por_ip(ip_p)
                        cidr_origem = (
                            f"Domínio '{dominio_digitado}' resolvido para {ip_p}. "
                            f"{origem_inferida}."
                        )
                except ValueError:
                    logger.warning("CIDR inválido informado no modo domínio")
                    erro = "No modo Domínio, o CIDR (se informado) deve ser um número inteiro entre 0 e 32."
                    invalid_fields.add("cidr")
                except Exception:
                    logger.exception("Erro ao resolver domínio/hostname no modo domínio")
                    erro = f"Não foi possível resolver o domínio/hostname informado: {dominio_digitado}"
                    invalid_fields.add("ip")

        elif erro is None and modo == "cidr":
            if not cidr_raw:
                erro = "No modo CIDR, preencha o campo CIDR."
                invalid_fields.add("cidr")
            else:
                try:
                    cidr_val = int(cidr_raw)
                except ValueError:
                    logger.warning("CIDR inválido no modo cidr")
                    erro = "O CIDR deve ser um número inteiro entre 0 e 32."
                    invalid_fields.add("cidr")

        elif erro is None and modo == "mask":
            if not mask_dec_p:
                erro = "No modo Máscara Decimal, preencha a máscara (ex.: 255.255.255.240)."
                invalid_fields.add("mask_decimal")
            else:
                cidr_val = mascara_dotted_para_cidr(mask_dec_p)
                if cidr_val is None:
                    try:
                        parse_ipv4_parts(mask_dec_p, "Máscara decimal")
                        erro = (
                            "Máscara decimal inválida. Use máscara contígua "
                            "(ex.: 255.255.255.0), não valores como 255.0.255.0."
                        )
                    except EntradaInvalidaError as exc:
                        logger.warning("Máscara decimal inválida: %s", exc)
                        erro = str(exc)
                        invalid_fields.add("mask_decimal")

        elif erro is None and modo == "wildcard":
            if not wildcard_p:
                erro = "No modo Wildcard, preencha a wildcard mask (ex.: 0.0.15.255)."
                invalid_fields.add("wildcard_mask")
            else:
                cidr_val = wildcard_dotted_para_cidr(wildcard_p)
                if cidr_val is None:
                    try:
                        parse_ipv4_parts(wildcard_p, "Wildcard mask")
                        erro = (
                            "Wildcard inválida. Use formato x.x.x.x com inverso de máscara contígua "
                            "(ex.: 0.0.15.255)."
                        )
                    except EntradaInvalidaError as exc:
                        logger.warning("Wildcard inválida: %s", exc)
                        erro = str(exc)
                        invalid_fields.add("wildcard_mask")

        elif erro is None and modo == "autoip":
            if not ip_p:
                erro = "No modo Descobrir CIDR do IP, informe um endereço IP."
                invalid_fields.add("ip")
            else:
                try:
                    cidr_val, cidr_origem = inferir_cidr_por_ip(ip_p)
                except EntradaInvalidaError as exc:
                    logger.warning("Falha ao inferir CIDR por IP: %s", exc)
                    erro = str(exc)
                    invalid_fields.add("ip")

        if erro is None and cidr_val is not None and not (0 <= cidr_val <= 32):
            erro = "CIDR deve estar entre 0 e 32."
            invalid_fields.add("cidr")

        if erro is None and cidr_val is not None:
            try:
                if ip_p:
                    res = processar(ip_p, cidr_val, regua_count=regua_count)
                else:
                    res = processar_somente_mascara(cidr_val)
                    res["regua_count"] = regua_count

                if res is not None:
                    cidr_p = str(cidr_val)
                    if not mask_dec_p:
                        mask_dec_p = res["mask"]
                    if not wildcard_p:
                        wildcard_p = res["wildcard"]
                    res["cidr_origem"] = cidr_origem or ""
                    res["grc_resumo"] = grc_resumo(res)
                    registrar_consulta(
                        {
                            "modo": modo,
                            "ip": ip_entrada_original,
                            "cidr": cidr_raw,
                            "mask_decimal": mask_dec_p,
                            "wildcard_mask": wildcard_p,
                        },
                        res,
                    )
            except EntradaInvalidaError as exc:
                logger.warning("Entrada inválida durante processamento: %s", exc)
                erro = str(exc)
            except Exception:
                logger.exception("Erro interno inesperado durante processamento principal")
                erro = "Erro interno ao processar os dados. Revise os campos e tente novamente."

    pag = paginate_history(history_limit_pre, history_page_pre)
    return render_template(
        "index.html",
        res=res,
        ipv6_res=ipv6_res,
        erro=erro,
        ip_pre=ip_p,
        ipv6_pre=ipv6_p,
        cidr_pre=cidr_p,
        mask_dec_pre=mask_dec_p,
        wildcard_pre=wildcard_p,
        regua_count_pre=regua_count_pre,
        history_limit_pre=pag["history_limit_pre"],
        history_limit=pag["history_limit"],
        history_limit_max=pag["history_limit_max"],
        history_page=pag["history_page"],
        total_history_pages=pag["total_history_pages"],
        has_prev_history=pag["has_prev_history"],
        has_next_history=pag["has_next_history"],
        invalid_fields=invalid_fields,
        history=pag["history"],
        history_page_items=pag["history_page_items"],
    )


@app.before_request
def _before_request_log_context():
    g.request_id = str(uuid.uuid4())[:8]
    g.started_at = time.time()
    logger.info("Request iniciada: %s %s", request.method, request.path)


@app.after_request
def _after_request_log(response):
    elapsed_ms = int((time.time() - getattr(g, "started_at", time.time())) * 1000)
    logger.info("Request finalizada: status=%s tempo_ms=%s", response.status_code, elapsed_ms)
    return response


@app.errorhandler(Exception)
def _handle_unexpected_error(exc):
    if isinstance(exc, HTTPException):
        return exc
    logger.exception("Exceção não tratada capturada pelo handler global")
    return (
        render_template(
            "index.html",
            res=None,
            erro="Erro interno inesperado. O evento foi registrado em log para auditoria.",
            ip_pre="",
            cidr_pre="",
            mask_dec_pre="",
            wildcard_pre="",
            regua_count_pre="5",
        ),
        500,
    )


@app.route("/history", methods=["GET"])
def history_api():
    return jsonify({"items": list_history()})


@app.route("/export/json", methods=["GET"])
def export_json():
    payload = {
        "generated_at": utc_now_iso(),
        "history": list_history(),
        "last_request_id": getattr(g, "request_id", "-"),
    }
    return jsonify(payload)


@app.route("/export/pdf", methods=["GET"])
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


@app.route("/icone.png", methods=["GET"])
def project_icon():
    icon_path = BASE_DIR / "icone.png"
    if not icon_path.exists():
        abort(404)
    return send_file(icon_path, mimetype="image/png")


if __name__ == "__main__":
    carregar_historico()
    app_host = os.getenv("APP_HOST", "127.0.0.1")
    app_port = int(os.getenv("APP_PORT", "5000"))
    app_debug = os.getenv("APP_DEBUG", "true").lower() in {"1", "true", "yes", "on"}
    app_open_browser = os.getenv("APP_OPEN_BROWSER", "true").lower() in {"1", "true", "yes", "on"}
    logger.info(
        "Inicializando aplicação local host=%s porta=%s debug=%s open_browser=%s",
        app_host,
        app_port,
        app_debug,
        app_open_browser,
    )
    if app_open_browser and app_host in {"127.0.0.1", "localhost"}:
        threading.Timer(1.0, lambda: webbrowser.open(f"http://{app_host}:{app_port}")).start()
    app.run(host=app_host, port=app_port, debug=app_debug)

