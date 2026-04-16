from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
import socket
import time

from backend.common import (
    DNS_CACHE_TTL_SECONDS,
    DNS_RESOLVE_TIMEOUT_SECONDS,
    DnsResolucaoError,
    DnsResolucaoTimeoutError,
    EntradaInvalidaError,
    log_event,
)

_dns_cache = {}
_dns_executor = ThreadPoolExecutor(max_workers=2)


def resolver_dns_com_cache(hostname):
    h = (hostname or "").strip().lower()
    if not h:
        raise EntradaInvalidaError("Domínio/hostname vazio.")
    now = time.time()
    cached = _dns_cache.get(h)
    if cached and cached["expires_at"] > now:
        log_event("info", "dns_cache", status="hit", hostname=h)
        return cached["ip"]
    log_event("info", "dns_cache", status="miss", hostname=h)
    dns_started = time.perf_counter()
    future = _dns_executor.submit(socket.gethostbyname, h)
    try:
        ip = future.result(timeout=DNS_RESOLVE_TIMEOUT_SECONDS)
    except FuturesTimeoutError as exc:
        future.cancel()
        elapsed_ms = int((time.perf_counter() - dns_started) * 1000)
        log_event(
            "warning",
            "dns_resolve",
            status="timeout",
            hostname=h,
            timeout_s=DNS_RESOLVE_TIMEOUT_SECONDS,
            elapsed_ms=elapsed_ms,
        )
        raise DnsResolucaoTimeoutError(
            "Timeout ao resolver DNS do domínio informado. Tente novamente em alguns segundos."
        ) from exc
    except socket.gaierror as exc:
        elapsed_ms = int((time.perf_counter() - dns_started) * 1000)
        log_event("warning", "dns_resolve", status="not_found", hostname=h, elapsed_ms=elapsed_ms)
        raise DnsResolucaoError(f"Não foi possível resolver o domínio/hostname informado: {h}") from exc
    except Exception as exc:
        elapsed_ms = int((time.perf_counter() - dns_started) * 1000)
        log_event("error", "dns_resolve", status="error", hostname=h, elapsed_ms=elapsed_ms, exc_info=True)
        raise DnsResolucaoError("Erro interno ao resolver DNS. Tente novamente.") from exc
    elapsed_ms = int((time.perf_counter() - dns_started) * 1000)
    log_event("info", "dns_resolve", status="ok", hostname=h, ip=ip, elapsed_ms=elapsed_ms)
    _dns_cache[h] = {"ip": ip, "expires_at": now + DNS_CACHE_TTL_SECONDS}
    return ip

