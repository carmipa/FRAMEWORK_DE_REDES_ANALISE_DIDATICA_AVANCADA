import logging
import os
import time
from pathlib import Path

from flask import g

# Logging estruturado para rastreabilidade (GRC/auditoria)
LOG_LEVEL = os.getenv("APP_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(name)s | req=%(request_id)s | %(message)s",
)
_base_logger = logging.getLogger("cybernet")


class UTCFormatter(logging.Formatter):
    converter = time.gmtime


class ConsoleUTCFormatter(UTCFormatter):
    ANSI_RESET = "\033[0m"
    LEVEL_STYLES = {
        "DEBUG": ("🔍", "36"),  # ciano
        "INFO": ("✅", "32"),  # verde
        "WARNING": ("⚠️", "33"),  # amarelo
        "ERROR": ("❌", "31"),  # vermelho
        "CRITICAL": ("🛑", "35"),  # magenta
    }

    def __init__(self, fmt: str, use_color: bool):
        super().__init__(fmt)
        self.use_color = use_color

    def format(self, record):
        icon, color = self.LEVEL_STYLES.get(record.levelname, ("•", "37"))
        original_levelname = record.levelname
        styled_level = f"{icon} {record.levelname}"
        if self.use_color:
            styled_level = f"\033[{color}m{styled_level}{self.ANSI_RESET}"
        record.levelname = styled_level
        try:
            return super().format(record)
        finally:
            record.levelname = original_levelname


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
    stream = getattr(handler, "stream", None)
    stream_is_tty = bool(getattr(stream, "isatty", lambda: False)())
    allow_color = os.getenv("APP_LOG_COLOR", "1") != "0"
    force_color = os.getenv("APP_LOG_FORCE_COLOR", "1") != "0"
    handler.setFormatter(
        ConsoleUTCFormatter(
            "%(asctime)sZ | %(levelname)s | %(name)s | req=%(request_id)s | %(message)s",
            use_color=allow_color and (stream_is_tty or force_color),
        )
    )


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
    try:
        from backend.services.audit_log_service import register_audit_event

        request_id = getattr(g, "request_id", "-")
    except Exception:
        register_audit_event = None
        request_id = "-"
    if register_audit_event is not None:
        register_audit_event(level=level, evento=evento, fields=cleaned, request_id=request_id)

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

