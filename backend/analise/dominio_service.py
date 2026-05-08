"""Resolução de DNS com cache e tratamento de erros controlado.

Padrões aplicados:
- validação de entrada com `EntradaInvalidaError`;
- timeout específico com `DnsResolucaoTimeoutError`;
- falha de resolução com `DnsResolucaoError`;
- logs estruturados via `log_event`.
"""

from concurrent import futures
import socket
import time
from typing import Any

from backend.config import DNS_CACHE_TTL_SECONDS, DNS_RESOLVE_TIMEOUT_SECONDS
from backend.core.exceptions import DnsResolucaoError, DnsResolucaoTimeoutError, EntradaInvalidaError
from backend.core.logging import log_event

_dns_cache: dict[str, dict[str, Any]] = {}
_dns_executor = futures.ThreadPoolExecutor(max_workers=2)


def _normalizar_hostname(hostname: str) -> str:
    normalized = (hostname or "").strip().lower()
    if not normalized:
        log_event("warning", "dns_resolve", status="invalid_input", reason="empty_hostname")
        raise EntradaInvalidaError("Domínio/hostname vazio.")
    return normalized


def _cache_hit(hostname: str, now: float) -> str | None:
    cached = _dns_cache.get(hostname)
    if cached and cached["expires_at"] > now:
        log_event("info", "dns_cache", status="hit", hostname=hostname)
        return str(cached["ip"])
    return None


def _persistir_cache(hostname: str, ip: str, now: float) -> None:
    _dns_cache[hostname] = {"ip": ip, "expires_at": now + DNS_CACHE_TTL_SECONDS}


def _resolver_dns_live(hostname: str) -> tuple[str, int]:
    dns_started = time.perf_counter()
    future = _dns_executor.submit(socket.gethostbyname, hostname)
    try:
        ip = future.result(timeout=DNS_RESOLVE_TIMEOUT_SECONDS)
        elapsed_ms = int((time.perf_counter() - dns_started) * 1000)
        return str(ip), elapsed_ms
    except futures.TimeoutError as exc:
        future.cancel()
        elapsed_ms = int((time.perf_counter() - dns_started) * 1000)
        log_event(
            "warning",
            "dns_resolve",
            status="timeout",
            hostname=hostname,
            timeout_s=DNS_RESOLVE_TIMEOUT_SECONDS,
            elapsed_ms=elapsed_ms,
        )
        raise DnsResolucaoTimeoutError(
            "Timeout ao resolver DNS do domínio informado. Tente novamente em alguns segundos."
        ) from exc
    except socket.gaierror as exc:
        elapsed_ms = int((time.perf_counter() - dns_started) * 1000)
        log_event("warning", "dns_resolve", status="not_found", hostname=hostname, elapsed_ms=elapsed_ms)
        raise DnsResolucaoError(f"Não foi possível resolver o domínio/hostname informado: {hostname}") from exc
    except Exception as exc:  # noqa: BLE001  # pylint: disable=broad-exception-caught
        elapsed_ms = int((time.perf_counter() - dns_started) * 1000)
        log_event("error", "dns_resolve", status="error", hostname=hostname, elapsed_ms=elapsed_ms, exc_info=True)
        raise DnsResolucaoError("Erro interno ao resolver DNS. Tente novamente.") from exc


def resolver_dns_com_cache(hostname: str) -> str:
    """Resolve hostname com cache local e timeout configurável."""
    h = _normalizar_hostname(hostname)
    now = time.time()
    cache_ip = _cache_hit(h, now)
    if cache_ip is not None:
        return cache_ip

    log_event("info", "dns_cache", status="miss", hostname=h)
    ip, elapsed_ms = _resolver_dns_live(h)
    log_event("info", "dns_resolve", status="ok", hostname=h, ip=ip, elapsed_ms=elapsed_ms)
    _persistir_cache(h, ip, now)
    return ip
