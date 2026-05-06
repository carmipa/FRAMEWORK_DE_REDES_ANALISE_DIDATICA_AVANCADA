"""GeoIP didático: região a partir do IP do cliente (IPv4/IPv6 públicos)."""

from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.request

GEO_TIMEOUT_S = 4
USER_AGENT = "CyberNetFramework/1.0"


def cliente_ip_efetivo(request) -> str:
    """IP aparente do cliente (proxy: X-Forwarded-For / X-Real-IP)."""
    xff = (request.headers.get("X-Forwarded-For") or "").strip()
    if xff:
        return xff.split(",")[0].strip()
    real = (request.headers.get("X-Real-IP") or "").strip()
    if real:
        return real
    return (request.remote_addr or "").strip()


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
    url = (
        f"http://ip-api.com/json/{ip}"
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
            "mensagem": (
                "Consulta externa indisponível ou timeout "
                f"({exc.__class__.__name__})."
            ),
            "ip": ip,
        }
    if data.get("status") != "success":
        return {
            "ok": False,
            "motivo": "api",
            "mensagem": data.get("message") or "Resposta da API inválida.",
            "ip": ip,
        }
    return {
        "ok": True,
        "ip": data.get("query") or ip,
        "pais": data.get("country") or "—",
        "codigo_pais": data.get("countryCode") or "",
        "regiao": data.get("regionName") or "—",
        "cidade": data.get("city") or "—",
        "lat": data.get("lat"),
        "lon": data.get("lon"),
        "isp": data.get("isp") or "—",
    }
