"""Rotas principais da aplicação (home, informações, API geo, ícone)."""

import html
import re
import unicodedata
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
from backend.core.logging import log_event
from backend.analise.dominio_service import resolver_dns_com_cache
from backend.analise.geo.geo_lookup_service import _enriquecer_resposta_geo
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

VALID_ANALYSIS_MODES = {
    "cidr",
    "mask",
    "wildcard",
    "autoip",
    "dominio",
    "ipv6",
    "comparador",
    "geo",
    "portas",
    "protocolos",
}


def _default_home_state() -> dict[str, object]:
    return {
        "res": None,
        "erro": None,
        "ip_p": "",
        "cidr_p": "",
        "mask_dec_p": "",
        "wildcard_p": "",
        "ipv6_p": "",
        "regua_count_pre": "5",
        "history_limit_pre": "1",
        "history_page_pre": "1",
        "cidr_origem": "",
        "ipv6_res": None,
        "invalid_fields": set(),
        "wizard_calculo": [],
        "timeline_bloco": None,
        "erro_didatico": None,
        "comparador_cidr_a_pre": COMPARADOR_CIDR_PADRAO_A,
        "comparador_cidr_b_pre": COMPARADOR_CIDR_PADRAO_B,
        "comparador_cards": [],
        "comparador_only": False,
        "comparador_ip": "",
        "active_tab_pre": request.args.get("tab", "cidr").strip().lower() or "cidr",
    }


def _apply_history_qs_defaults(
    history_limit_pre: str, history_page_pre: str
) -> tuple[str, str]:
    history_limit_qs = request.args.get("history_limit", "").strip()
    history_page_qs = request.args.get("history_page", "").strip()
    if history_limit_qs.isdigit():
        history_limit_pre = history_limit_qs
    if history_page_qs.isdigit():
        history_page_pre = history_page_qs
    return history_limit_pre, history_page_pre


def _apply_replay_defaults(
    active_tab_pre: str,
    ip_p: str,
    ipv6_p: str,
    cidr_p: str,
    mask_dec_p: str,
    wildcard_p: str,
) -> tuple[str, str, str, str, str, str]:
    replay_id = request.args.get("replay", "").strip()
    if request.method != "GET" or not replay_id:
        return active_tab_pre, ip_p, ipv6_p, cidr_p, mask_dec_p, wildcard_p

    selected = next((item for item in list_history() if item.get("id") == replay_id), None)
    if not selected:
        return active_tab_pre, ip_p, ipv6_p, cidr_p, mask_dec_p, wildcard_p

    modo_replay = (selected.get("modo") or "").strip().lower()
    if modo_replay in VALID_ANALYSIS_MODES:
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
    return active_tab_pre, ip_p, ipv6_p, cidr_p, mask_dec_p, wildcard_p


def _carregar_readme() -> tuple[str | None, str | None]:
    caminho = BASE_DIR / "README.md"
    if not caminho.exists() or not caminho.is_file():
        return None, "Arquivo README.md não encontrado na raiz do projeto."
    try:
        return caminho.read_text(encoding="utf-8"), None
    except OSError:
        return None, "Não foi possível ler o README.md."


def _inline_md(texto: str) -> str:
    placeholders: dict[str, str] = {}

    def keep(value: str) -> str:
        key = f"__PH_{len(placeholders)}__"
        placeholders[key] = value
        return key

    # [![alt](img)](href)  -> badge clicável
    texto = re.sub(
        r"\[!\[([^\]]*)\]\((https?://[^\s)]+)\)\]\((https?://[^\s)]+)\)",
        lambda m: keep(
            f'<a href="{html.escape(m.group(3), quote=True)}" target="_blank" rel="noopener noreferrer">'
            f'<img src="{html.escape(m.group(2), quote=True)}" alt="{html.escape(m.group(1), quote=True)}"></a>'
        ),
        texto,
    )
    # ![alt](img)
    texto = re.sub(
        r"!\[([^\]]*)\]\((https?://[^\s)]+|[./][^\s)]+)\)",
        lambda m: keep(
            f'<img src="{html.escape(m.group(2), quote=True)}" alt="{html.escape(m.group(1), quote=True)}">'
        ),
        texto,
    )
    # [texto](url)
    texto = re.sub(
        r"\[([^\]]+)\]\((https?://[^\s)]+|[./][^\s)]+)\)",
        lambda m: keep(
            f'<a href="{html.escape(m.group(2), quote=True)}" target="_blank" rel="noopener noreferrer">{html.escape(m.group(1))}</a>'
        ),
        texto,
    )
    # `code`
    texto = re.sub(
        r"`([^`]+)`",
        lambda m: keep(f"<code>{html.escape(m.group(1))}</code>"),
        texto,
    )

    escaped = html.escape(texto)
    # Resolve placeholders simples e encadeados (ex.: link contendo imagem-placeholder).
    for _ in range(3):
        mudou = False
        for key, val in placeholders.items():
            if key in escaped:
                escaped = escaped.replace(key, val)
                mudou = True
        if not mudou:
            break
    return escaped


def _slugify_heading(texto: str) -> str:
    normalized = unicodedata.normalize("NFKD", texto)
    sem_acentos = "".join(c for c in normalized if not unicodedata.combining(c))
    base = re.sub(r"[^a-zA-Z0-9\s-]", "", sem_acentos).strip().lower()
    slug = re.sub(r"[\s-]+", "-", base).strip("-")
    return slug or "secao"


def _markdown_para_html(texto: str) -> tuple[str, list[dict[str, str | int]]]:
    linhas = texto.splitlines()
    blocos: list[str] = []
    secoes: list[dict[str, str | int]] = []
    slugs_usados: set[str] = set()
    em_code = False
    lang_code = ""
    code_buffer: list[str] = []
    em_ul = False
    em_ol = False

    def fechar_listas() -> None:
        nonlocal em_ul, em_ol
        if em_ul:
            blocos.append("</ul>")
            em_ul = False
        if em_ol:
            blocos.append("</ol>")
            em_ol = False

    for linha in linhas:
        raw = linha.rstrip("\n")
        stripped = raw.strip()

        if stripped.startswith("```"):
            fechar_listas()
            fence_lang = stripped[3:].strip().lower()
            if not em_code:
                em_code = True
                lang_code = fence_lang
                code_buffer = []
            else:
                code_texto = "\n".join(code_buffer)
                if lang_code == "mermaid":
                    blocos.append(f"<div class=\"mermaid\">{html.escape(code_texto)}</div>")
                else:
                    classe = f" language-{lang_code}" if lang_code else ""
                    blocos.append(
                        f"<pre class='doc-pre'><code class=\"{classe.strip()}\">{html.escape(code_texto)}</code></pre>"
                    )
                em_code = False
                lang_code = ""
                code_buffer = []
            continue

        if em_code:
            code_buffer.append(raw)
            continue

        if not stripped:
            fechar_listas()
            continue

        # Permite HTML inline no README (ex.: <p align="center">, <img ... />)
        if stripped.startswith("<") and stripped.endswith(">"):
            fechar_listas()
            blocos.append(raw)
            continue

        m_head = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if m_head:
            fechar_listas()
            nivel = len(m_head.group(1))
            titulo_raw = m_head.group(2).strip()
            conteudo = _inline_md(titulo_raw)
            slug_base = _slugify_heading(titulo_raw)
            slug = slug_base
            idx = 2
            while slug in slugs_usados:
                slug = f"{slug_base}-{idx}"
                idx += 1
            slugs_usados.add(slug)
            secoes.append({"id": slug, "titulo": titulo_raw, "nivel": nivel})
            blocos.append(f"<h{nivel} id=\"{slug}\">{conteudo}</h{nivel}>")
            continue

        m_ol = re.match(r"^(\d+)\.\s+(.*)$", stripped)
        if m_ol:
            if em_ul:
                blocos.append("</ul>")
                em_ul = False
            if not em_ol:
                blocos.append("<ol>")
                em_ol = True
            blocos.append(f"<li>{_inline_md(m_ol.group(2))}</li>")
            continue

        if stripped.startswith("- "):
            if em_ol:
                blocos.append("</ol>")
                em_ol = False
            if not em_ul:
                blocos.append("<ul>")
                em_ul = True
            blocos.append(f"<li>{_inline_md(stripped[2:])}</li>")
            continue

        fechar_listas()
        blocos.append(f"<p>{_inline_md(stripped)}</p>")

    if em_code:
        code_texto = "\n".join(code_buffer)
        if lang_code == "mermaid":
            blocos.append(f"<div class=\"mermaid\">{html.escape(code_texto)}</div>")
        else:
            classe = f" language-{lang_code}" if lang_code else ""
            blocos.append(
                f"<pre class='doc-pre'><code class=\"{classe.strip()}\">{html.escape(code_texto)}</code></pre>"
            )
    if em_ul:
        blocos.append("</ul>")
    if em_ol:
        blocos.append("</ol>")

    return "\n".join(blocos), secoes


def _normalizar_linhas_badges(texto: str) -> str:
    """Agrupa linhas consecutivas de badges shields em uma linha markdown."""
    linhas = texto.splitlines()
    badge_click = re.compile(r"^\[!\[[^\]]*\]\(https?://img\.shields\.io/[^\)]*\)\]\([^)]+\)\s*$")
    badge_img = re.compile(r"^!\[[^\]]*\]\(https?://img\.shields\.io/[^\)]*\)\s*$")
    saida: list[str] = []
    buffer: list[str] = []

    def flush_badges() -> None:
        if buffer:
            saida.append(" ".join(buffer))
            buffer.clear()

    for linha in linhas:
        stripped = linha.strip()
        if badge_click.match(stripped) or badge_img.match(stripped):
            buffer.append(stripped)
            continue
        flush_badges()
        saida.append(linha)

    flush_badges()
    return "\n".join(saida)


def _read_home_form_inputs(
    history_limit_pre: str, history_page_pre: str
) -> dict[str, object]:
    ip_p = request.form.get("ip", "").strip()
    regua_count_pre = request.form.get("regua_count", "5").strip() or "5"
    comparador_cidr_a_pre = (
        request.form.get("comparador_cidr_a", COMPARADOR_CIDR_PADRAO_A).strip()
        or COMPARADOR_CIDR_PADRAO_A
    )
    comparador_cidr_b_pre = (
        request.form.get("comparador_cidr_b", COMPARADOR_CIDR_PADRAO_B).strip()
        or COMPARADOR_CIDR_PADRAO_B
    )
    try:
        regua_count = int(regua_count_pre)
    except ValueError:
        regua_count = 5
    if regua_count not in REGUA_COUNT_OPCOES:
        regua_count = 5
    return {
        "ip_p": ip_p,
        "ip_entrada_original": ip_p,
        "ipv6_p": request.form.get("ipv6", "").strip(),
        "cidr_raw": request.form.get("cidr", "").strip(),
        "mask_dec_p": request.form.get("mask_decimal", "").strip(),
        "wildcard_p": request.form.get("wildcard_mask", "").strip(),
        "regua_count": regua_count,
        "regua_count_pre": str(regua_count),
        "comparador_cidr_a_pre": comparador_cidr_a_pre,
        "comparador_cidr_b_pre": comparador_cidr_b_pre,
        "history_limit_pre": (
            request.form.get("history_limit", history_limit_pre).strip()
            or history_limit_pre
        ),
        "history_page_pre": (
            request.form.get("history_page", history_page_pre).strip() or history_page_pre
        ),
        "modo": request.form.get("modo", "").strip().lower(),
    }


def _resolve_analysis_mode(
    modo: str, cidr_raw: str, mask_dec_p: str, wildcard_p: str, ipv6_p: str, ip_p: str
) -> str:
    if modo in VALID_ANALYSIS_MODES:
        return modo
    if cidr_raw:
        return "cidr"
    if mask_dec_p:
        return "mask"
    if wildcard_p:
        return "wildcard"
    if ipv6_p:
        return "ipv6"
    if ip_p:
        return "autoip"
    return ""


def _finalize_home_post(
    res: object, erro: object, wizard_calculo: object, timeline_bloco: object, erro_didatico: object
) -> tuple[object, object, object]:
    if res and not getattr(res, "get", lambda *_: None)("somente_mascara"):
        wizard_calculo = montar_wizard_calculo(res)
        timeline_bloco = montar_timeline_bloco(res)
    if erro:
        erro_didatico = explicar_erro_didatico(str(erro))
    return wizard_calculo, timeline_bloco, erro_didatico


def _apply_mode_processing(
    modo: str,
    erro: object,
    ip_p: str,
    ipv6_p: str,
    cidr_raw: str,
    mask_dec_p: str,
    wildcard_p: str,
    ip_entrada_original: str,
    comparador_cidr_a_pre: str,
    comparador_cidr_b_pre: str,
    invalid_fields: set,
) -> dict[str, object]:
    cidr_val = None
    cidr_origem = ""
    forcar_somente_mascara = False
    ipv6_res = None
    comparador_only = False
    comparador_ip = ""
    comparador_cards = []

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
            ip_p, comparador_cidr_a_pre, comparador_cidr_b_pre
        )
        if cmp_ctx["erro"]:
            erro = cmp_ctx["erro"]
            invalid_fields.update(cmp_ctx["invalid_fields"])
        else:
            comparador_ip = cmp_ctx["comparador_ip"]
            comparador_cards = cmp_ctx["comparador_cards"]

    return {
        "erro": erro,
        "ip_p": ip_p,
        "cidr_val": cidr_val,
        "cidr_origem": cidr_origem,
        "forcar_somente_mascara": forcar_somente_mascara,
        "ipv6_res": ipv6_res,
        "comparador_only": comparador_only,
        "comparador_ip": comparador_ip,
        "comparador_cards": comparador_cards,
    }


def _run_ipv4_cidr_post_processing(
    erro: object,
    cidr_val: int | None,
    ip_p: str,
    forcar_somente_mascara: bool,
    cidr_origem: str,
    regua_count: int,
    mode: str,
    ip_entrada_original: str,
    cidr_raw: str,
    mask_dec_p: str,
    wildcard_p: str,
) -> dict[str, object]:
    res = None
    cidr_p = ""
    invalid_fields = set()

    if erro is None and cidr_val is not None and not (0 <= cidr_val <= 32):
        erro = "CIDR deve estar entre 0 e 32."
        invalid_fields.add("cidr")

    if erro is None and cidr_val is not None:
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
                            "modo": mode,
                            "ip": ip_entrada_original,
                            "cidr": cidr_raw,
                            "mask_decimal": mask_dec_p,
                            "wildcard_mask": wildcard_p,
                        },
                        res,
                    )
                except HistoricoPersistenciaError as exc:
                    log_event(
                        "warning", "history_persist", status="warn", modo=mode, erro=exc
                    )
        except EntradaInvalidaError as exc:
            log_event("warning", "calc", status="invalid_input", modo=mode, erro=exc)
            erro = str(exc)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log_event(
                "error",
                "calc",
                status="error",
                modo=mode,
                erro=exc.__class__.__name__,
                exc_info=True,
            )
            erro = "Erro interno ao processar os dados. Revise os campos e tente novamente."

    return {
        "erro": erro,
        "res": res,
        "cidr_p": cidr_p,
        "mask_dec_p": mask_dec_p,
        "wildcard_p": wildcard_p,
        "cidr_origem": cidr_origem,
        "invalid_fields": invalid_fields,
    }


def _process_home_post(context: dict[str, object]) -> dict[str, object]:
    res = context["res"]
    erro = context["erro"]
    ip_p = str(context["ip_p"])
    cidr_p = str(context["cidr_p"])
    mask_dec_p = str(context["mask_dec_p"])
    wildcard_p = str(context["wildcard_p"])
    ipv6_p = str(context["ipv6_p"])
    regua_count_pre = str(context["regua_count_pre"])
    history_limit_pre = str(context["history_limit_pre"])
    history_page_pre = str(context["history_page_pre"])
    cidr_origem = str(context["cidr_origem"])
    ipv6_res = context["ipv6_res"]
    invalid_fields = context["invalid_fields"]
    comparador_cidr_a_pre = str(context["comparador_cidr_a_pre"])
    comparador_cidr_b_pre = str(context["comparador_cidr_b_pre"])
    comparador_cards = context["comparador_cards"]
    comparador_only = bool(context["comparador_only"])
    comparador_ip = str(context["comparador_ip"])
    active_tab_pre = str(context["active_tab_pre"])

    log_event("info", "calc_request", status="start")
    form = _read_home_form_inputs(history_limit_pre, history_page_pre)
    ip_p = str(form["ip_p"])
    ip_entrada_original = str(form["ip_entrada_original"])
    ipv6_p = str(form["ipv6_p"])
    cidr_raw = str(form["cidr_raw"])
    mask_dec_p = str(form["mask_dec_p"])
    wildcard_p = str(form["wildcard_p"])
    regua_count = int(form["regua_count"])
    regua_count_pre = str(form["regua_count_pre"])
    comparador_cidr_a_pre = str(form["comparador_cidr_a_pre"])
    comparador_cidr_b_pre = str(form["comparador_cidr_b_pre"])
    history_limit_pre = str(form["history_limit_pre"])
    history_page_pre = str(form["history_page_pre"])
    modo = str(form["modo"])
    active_tab_pre = modo or active_tab_pre

    modo = _resolve_analysis_mode(modo, cidr_raw, mask_dec_p, wildcard_p, ipv6_p, ip_p)
    if not modo:
        erro = "Selecione um modo e preencha o campo correspondente."
        invalid_fields.add("modo")
    if erro is None:
        log_event("info", "analysis_use", modo=modo, reason=motivo_analise(modo))

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
            log_event(
                "warning", "dns_autoresolve", status="error", modo=modo, erro=exc
            )
            erro = f"Não foi possível resolver o domínio informado: {ip_p}"

    mode_result = _apply_mode_processing(
        modo=modo,
        erro=erro,
        ip_p=ip_p,
        ipv6_p=ipv6_p,
        cidr_raw=cidr_raw,
        mask_dec_p=mask_dec_p,
        wildcard_p=wildcard_p,
        ip_entrada_original=ip_entrada_original,
        comparador_cidr_a_pre=comparador_cidr_a_pre,
        comparador_cidr_b_pre=comparador_cidr_b_pre,
        invalid_fields=invalid_fields,
    )
    erro = mode_result["erro"]
    ip_p = mode_result["ip_p"]
    cidr_val = mode_result["cidr_val"]
    cidr_origem = mode_result["cidr_origem"]
    forcar_somente_mascara = mode_result["forcar_somente_mascara"]
    ipv6_res = mode_result["ipv6_res"] or ipv6_res
    comparador_only = mode_result["comparador_only"] or comparador_only
    comparador_ip = mode_result["comparador_ip"] or comparador_ip
    comparador_cards = mode_result["comparador_cards"] or comparador_cards

    ipv4_result = _run_ipv4_cidr_post_processing(
        erro=erro,
        cidr_val=cidr_val,
        ip_p=ip_p,
        forcar_somente_mascara=forcar_somente_mascara,
        cidr_origem=cidr_origem,
        regua_count=regua_count,
        mode=modo,
        ip_entrada_original=ip_entrada_original,
        cidr_raw=cidr_raw,
        mask_dec_p=mask_dec_p,
        wildcard_p=wildcard_p,
    )
    erro = ipv4_result["erro"]
    res = ipv4_result["res"] or res
    cidr_p = ipv4_result["cidr_p"] or cidr_p
    mask_dec_p = ipv4_result["mask_dec_p"]
    wildcard_p = ipv4_result["wildcard_p"]
    cidr_origem = ipv4_result["cidr_origem"]
    invalid_fields.update(ipv4_result["invalid_fields"])

    wizard_calculo = context["wizard_calculo"]
    timeline_bloco = context["timeline_bloco"]
    erro_didatico = context["erro_didatico"]
    wizard_calculo, timeline_bloco, erro_didatico = _finalize_home_post(
        res, erro, wizard_calculo, timeline_bloco, erro_didatico
    )

    return {
        "res": res,
        "erro": erro,
        "ip_p": ip_p,
        "cidr_p": cidr_p,
        "mask_dec_p": mask_dec_p,
        "wildcard_p": wildcard_p,
        "ipv6_p": ipv6_p,
        "regua_count_pre": regua_count_pre,
        "history_limit_pre": history_limit_pre,
        "history_page_pre": history_page_pre,
        "cidr_origem": cidr_origem,
        "ipv6_res": ipv6_res,
        "invalid_fields": invalid_fields,
        "wizard_calculo": wizard_calculo,
        "timeline_bloco": timeline_bloco,
        "erro_didatico": erro_didatico,
        "comparador_cidr_a_pre": comparador_cidr_a_pre,
        "comparador_cidr_b_pre": comparador_cidr_b_pre,
        "comparador_cards": comparador_cards,
        "comparador_only": comparador_only,
        "comparador_ip": comparador_ip,
        "active_tab_pre": active_tab_pre,
    }


def home():
    state = _default_home_state()
    res, erro = state["res"], state["erro"]
    ip_p, cidr_p, mask_dec_p, wildcard_p, ipv6_p = (
        state["ip_p"],
        state["cidr_p"],
        state["mask_dec_p"],
        state["wildcard_p"],
        state["ipv6_p"],
    )
    regua_count_pre = state["regua_count_pre"]
    history_limit_pre = state["history_limit_pre"]
    history_page_pre = state["history_page_pre"]
    cidr_origem = state["cidr_origem"]
    ipv6_res = state["ipv6_res"]
    invalid_fields = state["invalid_fields"]
    wizard_calculo = state["wizard_calculo"]
    timeline_bloco = state["timeline_bloco"]
    erro_didatico = state["erro_didatico"]
    comparador_cidr_a_pre = state["comparador_cidr_a_pre"]
    comparador_cidr_b_pre = state["comparador_cidr_b_pre"]
    comparador_cards = state["comparador_cards"]
    comparador_only = state["comparador_only"]
    comparador_ip = state["comparador_ip"]
    active_tab_pre = state["active_tab_pre"]

    history_limit_pre, history_page_pre = _apply_history_qs_defaults(
        history_limit_pre, history_page_pre
    )
    active_tab_pre, ip_p, ipv6_p, cidr_p, mask_dec_p, wildcard_p = _apply_replay_defaults(
        active_tab_pre, ip_p, ipv6_p, cidr_p, mask_dec_p, wildcard_p
    )

    if request.method == "POST":
        post_result = _process_home_post(
            {
                "res": res,
                "erro": erro,
                "ip_p": ip_p,
                "cidr_p": cidr_p,
                "mask_dec_p": mask_dec_p,
                "wildcard_p": wildcard_p,
                "ipv6_p": ipv6_p,
                "regua_count_pre": regua_count_pre,
                "history_limit_pre": history_limit_pre,
                "history_page_pre": history_page_pre,
                "cidr_origem": cidr_origem,
                "ipv6_res": ipv6_res,
                "invalid_fields": invalid_fields,
                "wizard_calculo": wizard_calculo,
                "timeline_bloco": timeline_bloco,
                "erro_didatico": erro_didatico,
                "comparador_cidr_a_pre": comparador_cidr_a_pre,
                "comparador_cidr_b_pre": comparador_cidr_b_pre,
                "comparador_cards": comparador_cards,
                "comparador_only": comparador_only,
                "comparador_ip": comparador_ip,
                "active_tab_pre": active_tab_pre,
            }
        )
        res = post_result["res"]
        erro = post_result["erro"]
        ip_p = post_result["ip_p"]
        cidr_p = post_result["cidr_p"]
        mask_dec_p = post_result["mask_dec_p"]
        wildcard_p = post_result["wildcard_p"]
        ipv6_p = post_result["ipv6_p"]
        regua_count_pre = post_result["regua_count_pre"]
        history_limit_pre = post_result["history_limit_pre"]
        history_page_pre = post_result["history_page_pre"]
        cidr_origem = post_result["cidr_origem"]
        ipv6_res = post_result["ipv6_res"]
        invalid_fields = post_result["invalid_fields"]
        wizard_calculo = post_result["wizard_calculo"]
        timeline_bloco = post_result["timeline_bloco"]
        erro_didatico = post_result["erro_didatico"]
        comparador_cidr_a_pre = post_result["comparador_cidr_a_pre"]
        comparador_cidr_b_pre = post_result["comparador_cidr_b_pre"]
        comparador_cards = post_result["comparador_cards"]
        comparador_only = post_result["comparador_only"]
        comparador_ip = post_result["comparador_ip"]
        active_tab_pre = post_result["active_tab_pre"]

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
            geo = _enriquecer_resposta_geo(
                {
                    "ok": False,
                    "motivo": "invalid",
                    "mensagem": err_msg,
                    "ip": raw_digitado,
                    "pais": "",
                    "codigo_pais": "",
                    "pais_codigo": "",
                    "regiao": "",
                    "cidade": "",
                    "lat": None,
                    "lon": None,
                    "isp": "—",
                    "reservado": False,
                    "valido": False,
                    "tipo": "",
                    "fonte": "",
                }
            )
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


def documentacao():
    conteudo_html = ""
    secoes: list[dict[str, str | int]] = []
    conteudo_txt, erro = _carregar_readme()
    if conteudo_txt is not None:
        conteudo_txt = _normalizar_linhas_badges(conteudo_txt)
        conteudo_html, secoes = _markdown_para_html(conteudo_txt)

    return render_template(
        "documentacao/index.html",
        active_main_menu="documentacao",
        nome_documento="README.md",
        conteudo_html=conteudo_html,
        secoes=secoes,
        erro=erro,
    )


def register_views(app: Flask) -> None:
    app.add_url_rule("/", "home", home, methods=["GET", "POST"])
    app.add_url_rule("/informacoes", "informacoes", informacoes, methods=["GET"])
    app.add_url_rule("/documentacao", "documentacao", documentacao, methods=["GET"])
    app.add_url_rule(
        "/api/informacoes/geo",
        "api_informacoes_geo",
        api_informacoes_geo,
        methods=["GET"],
    )
    app.add_url_rule("/icone.png", "project_icon", project_icon, methods=["GET"])
