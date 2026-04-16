import logging
import os
from pathlib import Path

from flask import g

# Logging estruturado para rastreabilidade (GRC/auditoria)
LOG_LEVEL = os.getenv("APP_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(name)s | req=%(request_id)s | %(message)s",
)
_base_logger = logging.getLogger("cybernet")


class RequestIdFilter(logging.Filter):
    def filter(self, record):
        if not hasattr(record, "request_id"):
            try:
                record.request_id = getattr(g, "request_id", "-")
            except RuntimeError:
                record.request_id = "-"
        return True


for handler in logging.getLogger().handlers:
    handler.addFilter(RequestIdFilter())


class RequestLoggerAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        extra = kwargs.setdefault("extra", {})
        try:
            request_id = getattr(g, "request_id", "-")
        except RuntimeError:
            request_id = "-"
        extra.setdefault("request_id", request_id)
        return msg, kwargs


logger = RequestLoggerAdapter(_base_logger, {})


def log_event(level: str, evento: str, exc_info: bool = False, **fields):
    cleaned = {k: v for k, v in fields.items() if v is not None and v != ""}
    payload = " ".join(f"{k}={cleaned[k]}" for k in sorted(cleaned))
    message = f"evento={evento}" + (f" {payload}" if payload else "")
    getattr(logger, level.lower(), logger.info)(message, exc_info=exc_info)

BASE_DIR = Path(__file__).resolve().parent.parent
HISTORY_FILE = BASE_DIR / "consulta_history.json"
MAX_HISTORY = 60
DNS_CACHE_TTL_SECONDS = int(os.getenv("DNS_CACHE_TTL_SECONDS", "180"))
DNS_RESOLVE_TIMEOUT_SECONDS = float(os.getenv("DNS_RESOLVE_TIMEOUT_SECONDS", "3.0"))


class EntradaInvalidaError(ValueError):
    """Erro de validação de entrada informado ao usuário."""


class InfraestruturaError(RuntimeError):
    """Erro de infraestrutura/serviço interno."""


class DnsResolucaoError(InfraestruturaError):
    """Falha geral ao resolver DNS."""


class DnsResolucaoTimeoutError(DnsResolucaoError):
    """Timeout durante resolução DNS."""


class HistoricoPersistenciaError(InfraestruturaError):
    """Falha ao carregar/persistir histórico local."""

