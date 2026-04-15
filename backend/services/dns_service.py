import socket
import time

from backend.common import DNS_CACHE_TTL_SECONDS, EntradaInvalidaError, logger

_dns_cache = {}


def resolver_dns_com_cache(hostname):
    h = (hostname or "").strip().lower()
    if not h:
        raise EntradaInvalidaError("Domínio/hostname vazio.")
    now = time.time()
    cached = _dns_cache.get(h)
    if cached and cached["expires_at"] > now:
        logger.info("DNS cache hit para hostname=%s", h)
        return cached["ip"]
    logger.info("DNS cache miss para hostname=%s", h)
    ip = socket.gethostbyname(h)
    _dns_cache[h] = {"ip": ip, "expires_at": now + DNS_CACHE_TTL_SECONDS}
    return ip

