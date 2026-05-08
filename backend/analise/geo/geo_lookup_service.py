"""
GeoIP — motor principal geoip2fast (base embutida no pacote pip).

Sem chave de API; sem download separado; internet opcional.
Fallback HTTP (ip-api.com) só se geoip2fast não devolver país válido.
"""

from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Optional

from backend.core.logging import log_event

# ── Configuração ───────────────────────────────────────────────────────────
GEO_TIMEOUT_S = float(os.environ.get("GEO_TIMEOUT_SECONDS", "4.0"))
GEO_CACHE_TTL_SECONDS = int(
    os.environ.get("GEO_CACHE_TTL_SECONDS", os.environ.get("GEO_CACHE_TTL", "300"))
)
GEO_CACHE_MAX_ITEMS = int(os.environ.get("GEO_CACHE_MAX_ITEMS", "500"))
GEO_USAR_FALLBACK = os.environ.get("GEO_USAR_FALLBACK", "1").lower() not in (
    "0",
    "false",
    "no",
)

# ── Singleton geoip2fast ───────────────────────────────────────────────────
_lock = threading.Lock()
_reader: Any = None
_geoip2fast_ready: bool = False
_geoip2fast_error: str | None = None

# ── Cache em memória (payload legado + aliases) ────────────────────────────
_cache_lock = threading.Lock()
_geo_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def _inicializar_geoip2fast() -> None:
    global _reader, _geoip2fast_ready, _geoip2fast_error
    if _geoip2fast_ready:
        return
    with _lock:
        if _geoip2fast_ready:
            return
        try:
            import geoip2fast as _gf
            from geoip2fast import GeoIP2Fast

            pkg_dir = os.path.dirname(_gf.__file__)
            preferencia = [
                "geoip2fast-asn-ipv6.dat.gz",
                "geoip2fast-asn.dat.gz",
                "geoip2fast-ipv6.dat.gz",
                "geoip2fast.dat.gz",
            ]
            arquivo: str | None = None
            for nome in preferencia:
                caminho = os.path.join(pkg_dir, nome)
                if os.path.exists(caminho):
                    arquivo = caminho
                    break
            if arquivo:
                _reader = GeoIP2Fast(geoip2fast_data_file=arquivo, verbose=False)
                log_event(
                    "info",
                    "geoip2fast_ok",
                    arquivo=os.path.basename(arquivo),
                )
            else:
                _reader = GeoIP2Fast(verbose=False)
                log_event("info", "geoip2fast_ok", arquivo="default")
        except Exception as exc:  # noqa: BLE001  # pylint: disable=broad-exception-caught
            _reader = None
            _geoip2fast_error = str(exc)[:200]
            log_event("warning", "geoip2fast_falhou", erro=_geoip2fast_error)
        _geoip2fast_ready = True


def _normalizar_ip_texto(raw: str) -> str:
    """Normaliza candidato de IP (IPv6-mapped → IPv4 quando aplicável)."""
    txt = (raw or "").strip()
    if not txt:
        return ""
    try:
        addr = ipaddress.ip_address(txt)
    except ValueError:
        return ""
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    return str(addr)


def cliente_ip_efetivo(request) -> str:
    """
    IP aparente do cliente com heurística de proxy.
    Preferência: IPv4 global no XFF; depois qualquer global; senão primeiro válido.
    """
    candidatos_raw: list[str] = []
    xff = (request.headers.get("X-Forwarded-For") or "").strip()
    if xff:
        candidatos_raw.extend([p.strip() for p in xff.split(",") if p.strip()])
    real = (request.headers.get("X-Real-IP") or "").strip()
    if real:
        candidatos_raw.append(real)
    remote = (request.remote_addr or "").strip()
    if remote:
        candidatos_raw.append(remote)

    candidatos = [_normalizar_ip_texto(v) for v in candidatos_raw]
    candidatos = [v for v in candidatos if v]
    if not candidatos:
        return ""

    for ip in candidatos:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_global and isinstance(addr, ipaddress.IPv4Address):
                return ip
        except ValueError:
            continue

    for ip in candidatos:
        try:
            if ipaddress.ip_address(ip).is_global:
                return ip
        except ValueError:
            continue

    return candidatos[0]


def ip_e_publico_global(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def normalizar_ip_digitado(texto: str) -> tuple[str | None, str | None]:
    """
    Valida texto livre como IPv4/IPv6 (com saneamento leve de URL/porta).
    Retorna (ip_canónico, None) ou (None, mensagem de erro em PT).
    """
    raw = (texto or "").strip()
    if not raw:
        return None, "Digite um endereço IPv4 ou IPv6."
    ip = raw
    for prefix in ("https://", "http://", "ftp://"):
        if ip.lower().startswith(prefix):
            ip = ip[len(prefix) :]
    for sep in ("/", "?", "#", " "):
        ip = ip.split(sep)[0]
    ip = ip.strip().strip("[]")
    if ip.count(":") == 1 and "://" not in raw:
        ip = ip.rsplit(":", 1)[0]
    ip = ip.strip()
    if not ip:
        return None, "Digite um endereço IPv4 ou IPv6."
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None, "Endereço IP inválido. Usa IPv4 ou IPv6 válidos."
    return str(addr), None


def _cache_get(ip: str) -> dict[str, Any] | None:
    now = time.time()
    with _cache_lock:
        item = _geo_cache.get(ip)
        if not item:
            return None
        expires_at, payload = item
        if expires_at < now:
            _geo_cache.pop(ip, None)
            return None
        raw = dict(payload)
        raw.pop("cache", None)
        enriched = _enriquecer_resposta_geo(raw)
        enriched["cache"] = "hit"
        return enriched


def _cache_set(ip: str, payload: dict[str, Any]) -> None:
    if GEO_CACHE_MAX_ITEMS <= 0 or GEO_CACHE_TTL_SECONDS <= 0:
        return
    now = time.time()
    to_store = {k: v for k, v in payload.items() if k != "cache"}
    with _cache_lock:
        if len(_geo_cache) >= GEO_CACHE_MAX_ITEMS:
            expired_keys = [k for k, (exp, _) in _geo_cache.items() if exp < now]
            for k in expired_keys:
                _geo_cache.pop(k, None)
            if len(_geo_cache) >= GEO_CACHE_MAX_ITEMS:
                _geo_cache.pop(next(iter(_geo_cache)), None)
        _geo_cache[ip] = (now + GEO_CACHE_TTL_SECONDS, to_store)


def _http_json(url: str) -> dict | None:
    try:
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "CyberNetFramework/3.0",
            },
        )
        with urllib.request.urlopen(req, timeout=GEO_TIMEOUT_S) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        log_event(
            "warning",
            "geo_fallback_http_erro",
            url=url[:80],
            erro=str(exc)[:120],
        )
    return None


def _fallback_ip_api(ip: str) -> dict[str, Any] | None:
    data = _http_json(f"http://ip-api.com/json/{ip}?fields=66846719")
    if not data or data.get("status") != "success":
        return None
    return {
        "fonte": "ip-api.com (fallback)",
        "pais": data.get("country") or "",
        "pais_codigo": (data.get("countryCode") or "").upper(),
        "regiao": data.get("regionName") or "",
        "cidade": data.get("city") or "",
        "isp": data.get("isp") or "",
        "org": data.get("org") or "",
        "latitude": data.get("lat"),
        "longitude": data.get("lon"),
        "proxy": bool(data.get("proxy")),
        "hosting": bool(data.get("hosting")),
        "mobile": bool(data.get("mobile")),
    }


def _lookup_geoip2fast_dict(ip: str) -> dict[str, Any] | None:
    _inicializar_geoip2fast()
    if _reader is None:
        return None
    try:
        r = _reader.lookup(ip)
        d = r.to_dict() if hasattr(r, "to_dict") else {}
        cc = (d.get("country_code") or "").strip().upper()
        nome_en = (d.get("country_name") or "").strip()
        asn_name = (d.get("asn_name") or "").strip()
        return {
            "fonte": "geoip2fast (local)",
            "pais_codigo": cc,
            "pais_en": nome_en,
            "regiao": "",
        "cidade": "",
        "isp": asn_name,
            "as_name": asn_name,
            "as_cidr": (d.get("asn_cidr") or "").strip(),
            "cidr": (d.get("cidr") or "").strip(),
            "latitude": None,
            "longitude": None,
            "proxy": False,
            "hosting": False,
            "mobile": False,
            "is_private_local": bool(d.get("is_private")),
        }
    except Exception as exc:  # noqa: BLE001  # pylint: disable=broad-exception-caught
        log_event("warning", "geo_local_lookup_erro", ip=ip, erro=str(exc)[:120])
        return None


_NOMES_PT = {
    "United States": "Estados Unidos",
    "Brazil": "Brasil",
    "Australia": "Austrália",
    "China": "China",
    "Russia": "Rússia",
    "Germany": "Alemanha",
    "France": "França",
    "United Kingdom": "Reino Unido",
    "Japan": "Japão",
    "Canada": "Canadá",
    "India": "Índia",
    "Spain": "Espanha",
    "Italy": "Itália",
    "Mexico": "México",
    "Argentina": "Argentina",
    "Portugal": "Portugal",
}

_ALTO = frozenset({"CN", "RU", "KP", "IR", "BY", "SY", "CU"})
_MEDIO = frozenset(
    {
        "VE",
        "NG",
        "GH",
        "PK",
        "BD",
        "TR",
        "RO",
        "UA",
        "VN",
        "ID",
        "TH",
        "IN",
        "BR",
    }
)

_BANDEIRAS = {
    "BR": "🇧🇷",
    "US": "🇺🇸",
    "DE": "🇩🇪",
    "JP": "🇯🇵",
    "GB": "🇬🇧",
    "FR": "🇫🇷",
    "CN": "🇨🇳",
    "RU": "🇷🇺",
    "AU": "🇦🇺",
    "CA": "🇨🇦",
    "AR": "🇦🇷",
    "MX": "🇲🇽",
    "PT": "🇵🇹",
    "NL": "🇳🇱",
    "ES": "🇪🇸",
    "IT": "🇮🇹",
    "IN": "🇮🇳",
    "UA": "🇺🇦",
    "TR": "🇹🇷",
    "VE": "🇻🇪",
    "NG": "🇳🇬",
}


def _motivo_reservado(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if ip_obj.is_loopback:
        return "Loopback (localhost)"
    if ip_obj.is_link_local:
        return "Link-local (APIPA / fe80::)"
    if ip_obj.is_private:
        return "Privado (RFC 1918 / ULA IPv6)"
    if ip_obj.is_multicast:
        return "Multicast"
    if ip_obj.is_unspecified:
        return "Endereço não especificado (::)"
    if ip_obj.is_reserved:
        return "Reservado (IANA)"
    try:
        if ip_obj in ipaddress.ip_network("100.64.0.0/10"):
            return "CGNAT (RFC 6598)"
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    return "Não-roteável"


def _risco(cc: str) -> dict[str, str]:
    cc = (cc or "").upper()
    if not cc or cc in ("--", "XX", "ZZ"):
        return {
            "nivel": "Desconhecido",
            "badge": "⚫ Desconhecido",
            "badge_color": "secondary",
            "recomendacao": "País não identificado. Monitorar tráfego em contexto de SOC.",
        }
    if cc in _ALTO:
        return {
            "nivel": "Alto",
            "badge": "🔴 Alto Risco",
            "badge_color": "danger",
            "recomendacao": (
                f"País ({cc}) frequentemente associado a ameaças avançadas "
                "(referências CISA/ENISA). Avaliar geo-blocking seletivo, "
                "DPI e correlação no SIEM."
            ),
        }
    if cc in _MEDIO:
        return {
            "nivel": "Médio",
            "badge": "🟡 Risco Moderado",
            "badge_color": "warning",
            "recomendacao": (
                f"País ({cc}) com incidência moderada de ameaças. "
                "Reforçar MFA em contas privilegiadas e monitorização contínua."
            ),
        }
    return {
        "nivel": "Baixo",
        "badge": "🟢 Risco Baixo",
        "badge_color": "success",
        "recomendacao": (
            "Nenhuma restrição geográfica especial identificada para este prefixo."
        ),
    }


def _bandeira(cc: str, reservado: bool) -> str:
    if reservado:
        return "🏠"
    cc = (cc or "").upper()
    return _BANDEIRAS.get(cc, "🌐")


def _enriquecer_resposta_geo(out: dict[str, Any]) -> dict[str, Any]:
    """Preenche campos didáticos (GRC, bandeira, aliases) para UI e histórico."""
    d = dict(out)
    if not d.get("ok") and (d.get("motivo") or "").strip() == "private_or_local":
        d["reservado"] = True
    reservado = bool(d.get("reservado"))
    ok = bool(d.get("ok"))

    if reservado:
        # Nunca misturar dados de país público com IP não roteável.
        d["pais"] = ""
        d["codigo_pais"] = ""
        d["pais_codigo"] = ""
        d["regiao"] = ""
        d["cidade"] = ""
        d["lat"] = None
        d["lon"] = None
        d["latitude"] = None
        d["longitude"] = None
        d["timezone"] = ""
        d["isp"] = "—"
        d["org"] = ""
        d["as_name"] = ""
        d["cidr"] = ""
        d["as_cidr"] = ""
        d["maps_url"] = ""
        d["fonte"] = ""
        d["proxy"] = False
        d["hosting"] = False
        d["mobile"] = False
        cc = ""
        lat = None
        lon = None
    else:
        cc = (d.get("codigo_pais") or d.get("pais_codigo") or "").strip().upper()
        lat = d.get("latitude")
        lon = d.get("longitude")
        if lat is None and d.get("lat") is not None:
            lat = d.get("lat")
            d["latitude"] = lat
        if lon is None and d.get("lon") is not None:
            lon = d.get("lon")
            d["longitude"] = lon
        d["pais_codigo"] = d.get("pais_codigo") or cc
        d["codigo_pais"] = d.get("codigo_pais") or cc

    d["pais_bandeira"] = _bandeira(cc, reservado)

    d.setdefault("org", "")
    d.setdefault("as_name", "")
    d.setdefault("timezone", "")
    d.setdefault("proxy", False)
    d.setdefault("hosting", False)
    d.setdefault("mobile", False)

    if reservado:
        d["proxy_flag"] = "🏠 Rede local (sem rota pública)"
        d["hosting_flag"] = ""
        d["mobile_flag"] = ""
    else:
        d["proxy_flag"] = (
            "🔴 Proxy/VPN detectado" if d.get("proxy") else "🟢 Conexão direta"
        )
        d["hosting_flag"] = (
            "🟡 Datacenter / Hosting" if d.get("hosting") else ""
        )
        d["mobile_flag"] = (
            "📱 Rede móvel (operadora)" if d.get("mobile") else ""
        )

    if reservado:
        d["maps_url"] = ""
    elif lat is not None and lon is not None:
        d["maps_url"] = f"https://www.google.com/maps?q={lat},{lon}&z=10"
    else:
        d.setdefault("maps_url", "")

    if reservado:
        ip_txt = d.get("ip") or ""
        try:
            ip_o = ipaddress.ip_address(ip_txt)
            motivo_r = _motivo_reservado(ip_o)
        except ValueError:
            motivo_r = "Não-roteável"
        d["reservado_motivo"] = d.get("reservado_motivo") or motivo_r
        d["risco_nivel"] = "N/A"
        d["risco_badge"] = "🏠 Rede local"
        d["risco_badge_color"] = "secondary"
        d["risco_recomendacao"] = (
            f"Classificação: {d['reservado_motivo']}. Endereço não roteável na Internet — "
            "geolocalização pública não aplicável."
        )
    elif ok and cc:
        r = _risco(cc)
        d["risco_nivel"] = r["nivel"]
        d["risco_badge"] = r["badge"]
        d["risco_badge_color"] = r["badge_color"]
        d["risco_recomendacao"] = r["recomendacao"]
    else:
        d.setdefault(
            "risco_nivel",
            "Desconhecido",
        )
        d.setdefault("risco_badge", "⚫ Indisponível")
        d.setdefault("risco_badge_color", "secondary")
        d.setdefault(
            "risco_recomendacao",
            "Não foi possível classificar o risco para esta consulta.",
        )

    if d.get("motivo") == "invalid":
        d["erro"] = d.get("erro") or d.get("mensagem") or "Endereço IP inválido."
    elif d.get("motivo") == "empty":
        d["erro"] = d.get("erro") or d.get("mensagem") or "IP não identificado."
    else:
        d.setdefault("erro", None)

    # Normaliza campos vazios para o template (opcionais)
    if d.get("regiao") == "—":
        d["regiao"] = ""
    if d.get("cidade") == "—":
        d["cidade"] = ""

    return d


def _pais_pt(nome_en: str, codigo: str) -> str:
    if not nome_en:
        return codigo or "—"
    return _NOMES_PT.get(nome_en, nome_en)


def _merge_fontes(
    local: dict[str, Any] | None, fallback: dict[str, Any] | None
) -> dict[str, Any] | None:
    if fallback and local:
        merged = dict(fallback)
        for k in ("cidr", "as_cidr"):
            if local.get(k):
                merged.setdefault(k, local[k])
        return merged
    return fallback or local


def _montar_sucesso(ip: str, dados: dict[str, Any]) -> dict[str, Any]:
    cc = (dados.get("pais_codigo") or "").upper()
    nome_en = (dados.get("pais_en") or dados.get("pais") or "").strip()
    pais = (dados.get("pais") or "").strip() or _pais_pt(nome_en, cc)
    if not pais and cc:
        pais = cc
    regiao = (dados.get("regiao") or "").strip()
    cidade = (dados.get("cidade") or "").strip()
    lat = dados.get("latitude")
    lon = dados.get("longitude")
    isp = (dados.get("isp") or dados.get("as_name") or "—").strip() or "—"
    org = (dados.get("org") or "").strip()
    as_name = (dados.get("as_name") or dados.get("isp") or "").strip()
    fonte = dados.get("fonte") or ""
    return {
        "ok": True,
        "motivo": "",
        "mensagem": "",
        "ip": ip,
        "pais": pais or "—",
        "codigo_pais": cc,
        "pais_codigo": cc,
        "regiao": regiao,
        "cidade": cidade,
        "lat": lat,
        "lon": lon,
        "latitude": lat,
        "longitude": lon,
        "isp": isp,
        "org": org,
        "as_name": as_name,
        "timezone": (dados.get("timezone") or "").strip(),
        "proxy": bool(dados.get("proxy")),
        "hosting": bool(dados.get("hosting")),
        "mobile": bool(dados.get("mobile")),
        "fonte": fonte,
        "reservado": False,
        "valido": True,
        "tipo": "IPv4" if ipaddress.ip_address(ip).version == 4 else "IPv6",
        "cache": "miss",
        "as_cidr": dados.get("as_cidr") or "",
        "cidr": dados.get("cidr") or "",
    }


def lookup_regiao_geografica(ip: str) -> dict[str, Any]:
    """
    Geolocalização para IPs públicos.

    Formato legado (UI / JSON): ok, motivo, mensagem, ip, pais, codigo_pais,
    regiao, cidade, lat, lon, isp.

    Aliases extras: pais_codigo (= codigo_pais), reservado (bool), fonte.
    """
    ip = (ip or "").strip()
    if not ip:
        return _enriquecer_resposta_geo(
            {
                "ok": False,
                "motivo": "empty",
                "mensagem": "IP não identificado.",
                "ip": "",
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

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return _enriquecer_resposta_geo(
            {
                "ok": False,
                "motivo": "invalid",
                "mensagem": "Endereço IP inválido.",
                "ip": ip,
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

    if not ip_obj.is_global:
        msg = (
            "Endereço local ou privado (RFC 1918, loopback, etc.) — "
            "não há geolocalização pública para este IP."
        )
        return _enriquecer_resposta_geo(
            {
                "ok": False,
                "motivo": "private_or_local",
                "mensagem": msg,
                "ip": ip,
                "pais": "",
                "codigo_pais": "",
                "pais_codigo": "",
                "regiao": "",
                "cidade": "",
                "lat": None,
                "lon": None,
                "isp": "—",
                "reservado": True,
                "valido": True,
                "tipo": "IPv4" if ip_obj.version == 4 else "IPv6",
                "fonte": "",
            }
        )

    cached = _cache_get(ip)
    if cached is not None:
        return cached

    local = _lookup_geoip2fast_dict(ip)
    dados = local
    if GEO_USAR_FALLBACK and (
        local is None or (local.get("pais_codigo") or "") in ("", "--", "XX", "ZZ")
    ):
        log_event("info", "geo_usando_fallback", ip=ip)
        dados = _merge_fontes(local, _fallback_ip_api(ip))

    if not dados or (dados.get("pais_codigo") or "").upper() in ("", "--", "XX", "ZZ"):
        return _enriquecer_resposta_geo(
            {
                "ok": False,
                "motivo": "network",
                "mensagem": (
                    "Não foi possível obter geolocalização para este IP. "
                    "Tente novamente em instantes."
                ),
                "ip": ip,
                "pais": "",
                "codigo_pais": "",
                "pais_codigo": "",
                "regiao": "",
                "cidade": "",
                "lat": None,
                "lon": None,
                "isp": "—",
                "reservado": False,
                "valido": True,
                "tipo": "IPv4" if ip_obj.version == 4 else "IPv6",
                "fonte": "",
            }
        )

    # Nome de país PT quando veio só código / inglês do geoip2fast
    if dados.get("fonte", "").startswith("geoip2fast"):
        en = (local or {}).get("pais_en") or ""
        cc = (dados.get("pais_codigo") or "").upper()
        dados = dict(dados)
        dados["pais"] = _pais_pt(en, cc)

    out = _enriquecer_resposta_geo(_montar_sucesso(ip, dados))
    _cache_set(ip, out)
    log_event(
        "info",
        "geo_ok",
        ip=ip,
        pais=out.get("codigo_pais"),
        fonte=out.get("fonte"),
    )
    return out
