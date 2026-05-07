"""Rotas principais da aplicação (home, informações, API geo, ícone)."""

from flask import Flask, abort, jsonify, render_template, request, send_file

from backend.config import (
    BASE_DIR,
    COMPARADOR_CIDR_PADRAO_A,
    COMPARADOR_CIDR_PADRAO_B,
    REGUA_COUNT_OPCOES,
)
from backend.core.exceptions import (
    DnsResolucaoError,
    EntradaInvalidaError,
    HistoricoPersistenciaError,
)
from backend.core.logging import log_event, logger
from backend.analise.dominio_service import resolver_dns_com_cache
from backend.analise.geo_service import (
    cliente_ip_efetivo,
    lookup_regiao_geografica,
    normalizar_ip_digitado,
)
from backend.suporte.grc.grc_service import grc_resumo
from backend.suporte.historico.historico_service import (
    list_history,
    paginate_history,
    registrar_consulta,
)
from backend.analise.cidr_service import (
    mascara_dotted_para_cidr,
    processar,
    processar_somente_mascara,
)
from backend.analise.helpers_web import (
    explicar_erro_didatico,
    montar_timeline_bloco,
    montar_wizard_calculo,
    motivo_analise,
)
from backend.analise.cidr.cidr_service import processar_modo_cidr
from backend.analise.mascara.mascara_service import processar_modo_mascara
from backend.analise.wildcard.wildcard_service import processar_modo_wildcard
from backend.analise.auto_cidr.auto_cidr_service import processar_modo_auto_cidr
from backend.analise.comparador.comparador_service import processar_modo_comparador
from backend.analise.dominio.dominio_service import processar_modo_dominio
from backend.analise.geo.geo_service import executar_api_informacoes_geo
from backend.analise.ipv6.ipv6_service import processar_modo_ipv6
from backend.analise.portas.portas_service import montar_portas_catalogo_exibicao
from backend.analise.protocolos.protocolos_catalog import PROTOCOLOS_CATALOGO


def home():
    res, erro = None, None
    ip_p, cidr_p, mask_dec_p, wildcard_p, ipv6_p = "", "", "", "", ""
    regua_count_pre = "5"
    history_limit_pre = "1"
    history_page_pre = "1"
    cidr_origem = ""
    ipv6_res = None
    invalid_fields = set()
    wizard_calculo = []
    timeline_bloco = None
    erro_didatico = None
    comparador_cidr_a_pre = COMPARADOR_CIDR_PADRAO_A
    comparador_cidr_b_pre = COMPARADOR_CIDR_PADRAO_B
    comparador_cards = []
    comparador_only = False
    comparador_ip = ""
    active_tab_pre = request.args.get("tab", "cidr").strip().lower() or "cidr"

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
            modo_replay = (selected.get("modo") or "").strip().lower()
            if modo_replay in {"cidr", "mask", "wildcard", "autoip", "dominio", "ipv6", "comparador", "geo", "portas", "protocolos"}:
                active_tab_pre = modo_replay
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
        log_event("info", "calc_request", status="start")
        ip_p = request.form.get("ip", "").strip()
        ip_entrada_original = ip_p
        ipv6_p = request.form.get("ipv6", "").strip()
        cidr_raw = request.form.get("cidr", "").strip()
        mask_dec_p = request.form.get("mask_decimal", "").strip()
        wildcard_p = request.form.get("wildcard_mask", "").strip()
        regua_count_pre = request.form.get("regua_count", "5").strip() or "5"
        comparador_cidr_a_pre = (
            request.form.get("comparador_cidr_a", COMPARADOR_CIDR_PADRAO_A).strip() or COMPARADOR_CIDR_PADRAO_A
        )
        comparador_cidr_b_pre = (
            request.form.get("comparador_cidr_b", COMPARADOR_CIDR_PADRAO_B).strip() or COMPARADOR_CIDR_PADRAO_B
        )
        history_limit_pre = request.form.get("history_limit", history_limit_pre).strip() or history_limit_pre
        history_page_pre = request.form.get("history_page", history_page_pre).strip() or history_page_pre
        modo = request.form.get("modo", "").strip().lower()
        active_tab_pre = modo or active_tab_pre

        try:
            regua_count = int(regua_count_pre)
        except ValueError:
            regua_count = 5
        if regua_count not in REGUA_COUNT_OPCOES:
            regua_count = 5
        regua_count_pre = str(regua_count)

        cidr_val = None
        forcar_somente_mascara = False
        if modo not in {"cidr", "mask", "wildcard", "autoip", "dominio", "ipv6", "comparador", "geo", "portas", "protocolos"}:
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
        if erro is None:
            log_event("info", "analysis_use", modo=modo, reason=motivo_analise(modo))

        # Resolve DNS automático apenas quando o modo depende de IP de host.
        if (
            erro is None
            and modo in {"cidr", "autoip", "comparador"}
            and ip_p
            and not all(c.isdigit() or c == "." for c in ip_p)
        ):
            try:
                log_event("info", "dns_autoresolve", status="start", modo=modo)
                ip_p = resolver_dns_com_cache(ip_p)
            except DnsResolucaoError as exc:
                logger.warning("evento=dns_autoresolve status=error modo=%s erro=%s", modo, exc)
                erro = f"Não foi possível resolver o domínio informado: {ip_p}"

        if erro is None and modo == "ipv6":
            ipv6_ctx = processar_modo_ipv6(ipv6_p)
            if ipv6_ctx["erro"]:
                erro = ipv6_ctx["erro"]
                invalid_fields.update(ipv6_ctx["invalid_fields"])
            else:
                ipv6_res = ipv6_ctx["ipv6_res"]
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

        if erro is None and modo == "dominio":
            dom_ctx = processar_modo_dominio(ip_entrada_original, cidr_raw)
            if dom_ctx["erro"]:
                erro = dom_ctx["erro"]
                invalid_fields.update(dom_ctx["invalid_fields"])
            else:
                ip_p = dom_ctx["ip_p"]
                cidr_val = dom_ctx["cidr_val"]
                cidr_origem = dom_ctx["cidr_origem"]

        elif erro is None and modo == "cidr":
            cidr_ctx = processar_modo_cidr(ip_p=ip_p, cidr_raw=cidr_raw)
            if cidr_ctx["erro"]:
                erro = cidr_ctx["erro"]
            cidr_val = cidr_ctx["cidr_val"]
            if cidr_ctx["cidr_origem"]:
                cidr_origem = cidr_ctx["cidr_origem"]
            invalid_fields.update(cidr_ctx["invalid_fields"])

        elif erro is None and modo == "mask":
            mascara_ctx = processar_modo_mascara(ip_p=ip_p, mask_dec_p=mask_dec_p)
            if mascara_ctx["erro"]:
                erro = mascara_ctx["erro"]
            cidr_val = mascara_ctx["cidr_val"]
            if mascara_ctx["cidr_origem"]:
                cidr_origem = mascara_ctx["cidr_origem"]
            forcar_somente_mascara = mascara_ctx["forcar_somente_mascara"]
            invalid_fields.update(mascara_ctx["invalid_fields"])

        elif erro is None and modo == "wildcard":
            wildcard_ctx = processar_modo_wildcard(ip_p=ip_p, wildcard_p=wildcard_p)
            if wildcard_ctx["erro"]:
                erro = wildcard_ctx["erro"]
            cidr_val = wildcard_ctx["cidr_val"]
            invalid_fields.update(wildcard_ctx["invalid_fields"])

        elif erro is None and modo == "autoip":
            auto_ctx = processar_modo_auto_cidr(ip_p)
            if auto_ctx["erro"]:
                erro = auto_ctx["erro"]
                invalid_fields.update(auto_ctx["invalid_fields"])
            else:
                cidr_val = auto_ctx["cidr_val"]
                cidr_origem = auto_ctx["cidr_origem"]
        elif erro is None and modo == "comparador":
            comparador_only = True
            cmp_ctx = processar_modo_comparador(
                ip_p,
                comparador_cidr_a_pre,
                comparador_cidr_b_pre,
            )
            if cmp_ctx["erro"]:
                erro = cmp_ctx["erro"]
                invalid_fields.update(cmp_ctx["invalid_fields"])
            else:
                comparador_ip = cmp_ctx["comparador_ip"]
                comparador_cards = cmp_ctx["comparador_cards"]

        if erro is None and cidr_val is not None and not (0 <= cidr_val <= 32):
            erro = "CIDR deve estar entre 0 e 32."
            invalid_fields.add("cidr")

        if erro is None and cidr_val is not None:
            # Se o "IP" é na verdade uma máscara (ex.: 255.255.192.0), não usar lógica de host:
            # o 1º octeto 255 seria mostrado como classe E — o desejado é o modo sub-rede (A/B/C pelo /).
            ci_como_mascara = mascara_dotted_para_cidr(ip_p) if ip_p else None
            if ci_como_mascara is not None and not forcar_somente_mascara:
                if ci_como_mascara != cidr_val:
                    cidr_val = ci_como_mascara
                    cidr_origem = (
                        f"O texto no campo de endereço é uma máscara contígua (→ /{cidr_val}). "
                        "O número depois do / foi alinhado a essa máscara para não classificar 255.x como host "
                        "(como faixa E)."
                    )
                else:
                    suf = (
                        " Campo de endereço reconhecido como máscara pontuada — análise só sub-rede "
                        "(referência de classe pelo prefixo /), não pelo 1º octeto como host."
                    )
                    cidr_origem = ((cidr_origem or "").strip() + suf).strip()
                forcar_somente_mascara = True
            try:
                if forcar_somente_mascara:
                    res = processar_somente_mascara(cidr_val)
                elif ip_p:
                    res = processar(ip_p, cidr_val, regua_count=regua_count)
                else:
                    res = processar_somente_mascara(cidr_val)
                if res is not None and res.get("somente_mascara"):
                    res["regua_count"] = regua_count

                if res is not None:
                    cidr_p = str(cidr_val)
                    if not mask_dec_p:
                        mask_dec_p = res["mask"]
                    if not wildcard_p:
                        wildcard_p = res["wildcard"]
                    res["cidr_origem"] = cidr_origem or ""
                    res["grc_resumo"] = grc_resumo(res)
                    try:
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
                    except HistoricoPersistenciaError as exc:
                        logger.warning("evento=history_persist status=warn modo=%s erro=%s", modo, exc)
            except EntradaInvalidaError as exc:
                logger.warning("evento=calc status=invalid_input modo=%s erro=%s", modo, exc)
                erro = str(exc)
            except Exception:
                logger.exception("evento=calc status=error modo=%s", modo)
                erro = "Erro interno ao processar os dados. Revise os campos e tente novamente."

        if res and not res.get("somente_mascara"):
            wizard_calculo = montar_wizard_calculo(res)
            timeline_bloco = montar_timeline_bloco(res)

        if erro:
            erro_didatico = explicar_erro_didatico(erro)

    pag = paginate_history(history_limit_pre, history_page_pre)
    active_main_menu = active_tab_pre if active_tab_pre in {"portas", "protocolos"} else "analise"
    return render_template(
        "analise/index.html",
        active_main_menu=active_main_menu,
        res=res,
        ipv6_res=ipv6_res,
        erro=erro,
        ip_pre=ip_p,
        ipv6_pre=ipv6_p,
        cidr_pre=cidr_p,
        mask_dec_pre=mask_dec_p,
        wildcard_pre=wildcard_p,
        regua_count_pre=regua_count_pre,
        comparador_cidr_a_pre=comparador_cidr_a_pre,
        comparador_cidr_b_pre=comparador_cidr_b_pre,
        comparador_cards=comparador_cards,
        comparador_only=comparador_only,
        comparador_ip=comparador_ip,
        active_tab_pre=active_tab_pre,
        wizard_calculo=wizard_calculo,
        timeline_bloco=timeline_bloco,
        erro_didatico=erro_didatico,
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
        portas_catalogo=montar_portas_catalogo_exibicao(),
        protocolos_catalogo=PROTOCOLOS_CATALOGO,
    )


def informacoes():
    cliente_ip = cliente_ip_efetivo(request)
    raw_digitado = (request.args.get("ip") or "").strip()

    if raw_digitado:
        norm, err_msg = normalizar_ip_digitado(raw_digitado)
        if err_msg:
            geo = {
                "ok": False,
                "motivo": "invalid",
                "mensagem": err_msg,
                "ip": raw_digitado,
            }
            consultado = raw_digitado
            modo_geo = "manual"
        else:
            geo = lookup_regiao_geografica(norm)
            consultado = norm
            modo_geo = "manual"
    else:
        geo = lookup_regiao_geografica(cliente_ip)
        consultado = cliente_ip
        modo_geo = "ligacao"

    log_event(
        "info",
        "page_view",
        page="informacoes",
        reason="Página de informações didáticas com separador de região geográfica.",
        cliente_ip=cliente_ip,
        geo_ok=geo.get("ok"),
        modo_geo=modo_geo,
    )
    return render_template(
        "geo/informacoes.html",
        active_main_menu="informacoes",
        cliente_ip=cliente_ip,
        consultado=consultado,
        modo_geo=modo_geo,
        geo=geo,
        ip_digitado_prefill=raw_digitado if raw_digitado else "",
    )


def api_informacoes_geo():
    """JSON para atualizar o painel de região sem recarregar a página."""
    cliente_ip = cliente_ip_efetivo(request)
    raw_digitado = (request.args.get("ip") or "").strip()
    return jsonify(executar_api_informacoes_geo(cliente_ip, raw_digitado))


def project_icon():
    icon_path = BASE_DIR / "icone.png"
    if not icon_path.exists():
        abort(404)
    return send_file(icon_path, mimetype="image/png")


def register_views(app: Flask) -> None:
    app.add_url_rule("/", "home", home, methods=["GET", "POST"])
    app.add_url_rule("/informacoes", "informacoes", informacoes, methods=["GET"])
    app.add_url_rule(
        "/api/informacoes/geo",
        "api_informacoes_geo",
        api_informacoes_geo,
        methods=["GET"],
    )
    app.add_url_rule("/icone.png", "project_icon", project_icon, methods=["GET"])
