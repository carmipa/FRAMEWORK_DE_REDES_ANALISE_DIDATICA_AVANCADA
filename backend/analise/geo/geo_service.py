"""Orquestração da API GeoIP e registro no histórico."""

from backend.analise.geo_service import (
    lookup_regiao_geografica,
    normalizar_ip_digitado,
)
from backend.core.exceptions import HistoricoPersistenciaError
from backend.core.logging import log_event
from backend.suporte.historico.historico_service import registrar_consulta

_GEO_HIST_SNAPSHOT_KEYS = (
    "ip",
    "tipo",
    "reservado",
    "reservado_motivo",
    "pais",
    "pais_codigo",
    "pais_bandeira",
    "regiao",
    "cidade",
    "isp",
    "org",
    "as_name",
    "proxy",
    "hosting",
    "mobile",
    "risco_nivel",
    "risco_badge_color",
    "fonte",
    "ok",
    "motivo",
)


def _snapshot_geo_consulta(payload: dict) -> dict:
    out: dict = {}
    for k in _GEO_HIST_SNAPSHOT_KEYS:
        if k not in payload:
            continue
        v = payload[k]
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[k] = v
    return out


def _registrar_historico_geo(payload_geo: dict) -> None:
    consultado = (payload_geo.get("consultado") or "").strip()
    if not consultado:
        return
    ok_geo = bool(payload_geo.get("ok"))
    motivo = payload_geo.get("motivo") or ""

    if not ok_geo and motivo == "private_or_local":
        pais = "Local"
        regiao = "Privado"
        codigo_pais = "LOCAL"
        nivel = f"GeoIP: {regiao}/{pais}"
    elif ok_geo:
        pais = payload_geo.get("pais") or "N/A"
        regiao = payload_geo.get("regiao") or "N/A"
        codigo_pais = payload_geo.get("codigo_pais") or ""
        nivel = f"GeoIP: {regiao}/{pais}"
    else:
        pais = "N/A"
        regiao = "Erro"
        codigo_pais = ""
        nivel = f"GeoIP indisponível ({motivo or 'sem detalhe'})"

    try:
        registrar_consulta(
            {
                "modo": "geo",
                "ip": consultado,
                "ipv6": "",
                "cidr": "",
                "mask_decimal": codigo_pais,
                "wildcard_mask": "",
            },
            {
                "rede": regiao,
                "broad": pais,
                "mask": "N/A",
                "cidr": "",
                "nivel_tema": nivel,
                "geo_consulta": _snapshot_geo_consulta(payload_geo),
            },
        )
    except HistoricoPersistenciaError as exc:
        log_event("warning", "history_geo", status="warn", erro=exc)


def executar_api_informacoes_geo(cliente_ip: str, raw_digitado: str) -> dict:
    """Monta o payload JSON de `/api/informacoes/geo` e o histórico."""
    if raw_digitado:
        norm, err_msg = normalizar_ip_digitado(raw_digitado)
        if err_msg or not norm:
            return {
                "cliente_ip": cliente_ip,
                "consultado": raw_digitado,
                "modo": "manual",
                "ok": False,
                "motivo": "invalid",
                "mensagem": err_msg,
            }
        geo = lookup_regiao_geografica(norm)
        payload = {
            "cliente_ip": cliente_ip,
            "consultado": norm,
            "modo": "manual",
            **geo,
        }
        _registrar_historico_geo(payload)
        return payload

    geo = lookup_regiao_geografica(cliente_ip)
    payload = {
        "cliente_ip": cliente_ip,
        "consultado": cliente_ip,
        "modo": "ligacao",
        **geo,
    }
    _registrar_historico_geo(payload)
    return payload
