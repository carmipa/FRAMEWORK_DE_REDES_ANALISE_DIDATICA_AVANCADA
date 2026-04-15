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

BASE_DIR = Path(__file__).resolve().parent.parent
HISTORY_FILE = BASE_DIR / "consulta_history.json"
MAX_HISTORY = 60
DNS_CACHE_TTL_SECONDS = int(os.getenv("DNS_CACHE_TTL_SECONDS", "180"))


class EntradaInvalidaError(ValueError):
    """Erro de validação de entrada informado ao usuário."""

