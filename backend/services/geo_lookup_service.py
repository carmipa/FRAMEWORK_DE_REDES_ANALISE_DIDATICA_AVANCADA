"""GeoIP didático: região a partir do IP do cliente (IPv4/IPv6 públicos)."""

from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
import urllib.error
import urllib.request

GEO_TIMEOUT_S = 4
USER_AGENT = "CyberNetFramework/1.0"
GEO_PROVIDER_BASE_URL = os.getenv("GEO_PROVIDER_BASE_URL", "http://ip-api.com/json")
GEO_CACHE_TTL_SECONDS = int(os.getenv("GEO_CACHE_TTL_SECONDS", "300"))
GEO_CACHE_MAX_ITEMS = int(os.getenv("GEO_CACHE_MAX_ITEMS", "500"))
_geo_cache_lock = threading.Lock()
_geo_cache: dict[str, tuple[float, dict]] = {}


def _cache_get(ip: str) -> dict | None:
    now = time.time()
    with _geo_cache_lock:
        item = _geo_cache.get(ip)
        if not item:
            return None
        expires_at, payload = item
        if expires_at < now:
            _geo_cache.pop(ip, None)
            return None
        return dict(payload)


def _cache_set(ip: str, payload: dict) -> None:
    if GEO_CACHE_MAX_ITEMS <= 0 or GEO_CACHE_TTL_SECONDS <= 0:
        return
    now = time.time()
    with _geo_cache_lock:
        if len(_geo_cache) >= GEO_CACHE_MAX_ITEMS:
            expired_keys = [k for k, (exp, _) in _geo_cache.items() if exp < now]
            for k in expired_keys:
                _geo_cache.pop(k, None)
            if len(_geo_cache) >= GEO_CACHE_MAX_ITEMS:
                _geo_cache.pop(next(iter(_geo_cache)), None)
        _geo_cache[ip] = (now + GEO_CACHE_TTL_SECONDS, dict(payload))


def _normalizar_ip_texto(raw: str) -> str:
    """Normaliza texto de IP e converte IPv6-mapped IPv4 para formato IPv4."""
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
    IP aparente do cliente com heurística robusta de proxy.
    Regra: preferir IP global (prioridade para IPv4 global), senão primeiro válido.
    """
    candidatos_raw = []
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
    Valida texto livre como IPv4/IPv6.
    Retorna (ip_canónico, None) ou (None, mensagem de erro em PT).
    """
    raw = (texto or "").strip()
    if not raw:
        return None, "Digite um endereço IPv4 ou IPv6."
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return None, "Endereço IP inválido. Usa IPv4 ou IPv6 válidos."
    return str(addr), None


def lookup_regiao_geografica(ip: str) -> dict:
    """Consulta ip-api.com (HTTP, sem chave) só para IPs globalmente roteáveis."""
    if not ip:
        return {
            "ok": False,
            "motivo": "empty",
            "mensagem": "IP não identificado.",
        }
    if not ip_e_publico_global(ip):
        return {
            "ok": False,
            "motivo": "private_or_local",
            "mensagem": (
                "Endereço local ou privado (RFC 1918, loopback, etc.) — "
                "não há geolocalização pública para este IP."
            ),
            "ip": ip,
        }
    cached = _cache_get(ip)
    if cached is not None:
        cached["cache"] = "hit"
        return cached

    base = GEO_PROVIDER_BASE_URL.rstrip("/")
    url = (
        f"{base}/{ip}"
        "?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,query"
    )
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=GEO_TIMEOUT_S) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (
        urllib.error.URLError,
        TimeoutError,
        json.JSONDecodeError,
        OSError,
    ) as exc:
        return {
            "ok": False,
            "motivo": "network",
            "mensagem": "Não foi possível conectar ao provedor de localização no momento. Tente novamente.",
            "ip": ip,
        }
    if data.get("status") != "success":
        return {
            "ok": False,
            "motivo": "api",
            "mensagem": "O provedor de localização não conseguiu processar este IP agora.",
            "ip": ip,
        }
    payload = {
        "ok": True,
        "ip": data.get("query") or ip,
        "pais": data.get("country") or "—",
        "codigo_pais": data.get("countryCode") or "",
        "regiao": data.get("regionName") or "—",
        "cidade": data.get("city") or "—",
        "lat": data.get("lat"),
        "lon": data.get("lon"),
        "isp": data.get("isp") or "—",
        "cache": "miss",
    }
    _cache_set(ip, payload)
    return payload
