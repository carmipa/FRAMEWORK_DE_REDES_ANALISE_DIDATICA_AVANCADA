import logging
import os
import re
import sys
import time
from pathlib import Path

from flask import g

try:
    from colorama import just_fix_windows_console

    just_fix_windows_console()
except Exception:
    pass

# Logging estruturado para rastreabilidade (GRC/auditoria)
LOG_LEVEL = os.getenv("APP_LOG_LEVEL", "INFO").upper()
LOG_FORMAT = "%(asctime)sZ | %(levelname)s | %(name)s | req=%(request_id)s | %(message)s"


class UTCFormatter(logging.Formatter):
    converter = time.gmtime


class ConsoleUTCFormatter(UTCFormatter):
    """Nível e nome do logger coloridos; timestamp, req= e mensagem enriquecidos no pós-processamento."""

    ANSI_RESET = "\033[0m"
    LOGGER_NAME_COLOR = "36"  # ciano
    TS_DIM = "90"
    REQ_ID_COLOR = "35"  # magenta — request_id
    REQ_DASH_COLOR = "90"  # cinza — req sem contexto HTTP

    LEVEL_STYLES = {
        "DEBUG": ("🔍", "36"),
        "INFO": ("✅", "32"),
        "WARNING": ("⚠️", "33"),
        "ERROR": ("❌", "31"),
        "CRITICAL": ("🛑", "35"),
    }

    def __init__(self, fmt: str, use_color: bool):
        super().__init__(fmt)
        self.use_color = use_color

    def format(self, record):
        icon, color = self.LEVEL_STYLES.get(record.levelname, ("•", "37"))
        original_levelname = record.levelname
        original_name = record.name

        if self.use_color:
            record.levelname = f"\033[{color}m{icon} {record.levelname}{self.ANSI_RESET}"
            record.name = f"\033[{self.LOGGER_NAME_COLOR}m{record.name}{self.ANSI_RESET}"
        else:
            record.levelname = f"{icon} {record.levelname}"

        try:
            line = super().format(record)
            if self.use_color:
                line = self._enhance_full_line(line, original_levelname)
            return line
        finally:
            record.levelname = original_levelname
            record.name = original_name

    def _enhance_full_line(self, line: str, raw_level: str) -> str:
        """Colore timestamp, campo req= e corpo da mensagem (estruturado ou access log Werkzeug)."""
        parts = line.split(" | ", 4)
        if len(parts) < 5:
            return line
        ts, lvl, name, req_field, msg = parts
        ts_colored = f"\033[{self.TS_DIM}m{ts}{self.ANSI_RESET}"
        req_colored = self._colorize_req_field(req_field)
        msg_colored = self._colorize_message_body(msg, raw_level)
        return " | ".join([ts_colored, lvl, name, req_colored, msg_colored])

    def _colorize_req_field(self, req_field: str) -> str:
        m = re.match(r"^(req=)(.+)$", req_field.strip())
        if not m:
            return req_field
        prefix, value = m.group(1), m.group(2)
        if value == "-":
            return f"{prefix}\033[{self.REQ_DASH_COLOR}m{value}{self.ANSI_RESET}"
        return f"{prefix}\033[{self.REQ_ID_COLOR}m{value}{self.ANSI_RESET}"

    def _colorize_message_body(self, msg: str, raw_level: str) -> str:
        if not msg:
            return msg
        # Linha típica de access log do Werkzeug
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3} - - \[", msg):
            return self._colorize_werkzeug_access(msg)
        # Logs estruturados evento=... chave=valor (cybernet)
        if "evento=" in msg:
            return self._colorize_structured_message(msg)
        tint = {"DEBUG": "36", "INFO": "37", "WARNING": "33", "ERROR": "31", "CRITICAL": "35"}.get(
            raw_level, "37"
        )
        return f"\033[{tint}m{msg}{self.ANSI_RESET}"

    def _colorize_werkzeug_access(self, msg: str) -> str:
        # Formato típico: 127.0.0.1 - - [01/May/2026 18:46:38] "GET / HTTP/1.1" 200 -
        m = re.match(
            r"^(\d{1,3}(?:\.\d{1,3}){3}) (- - )(\[[^\]]+\]) \"([A-Z]+) (\S+) (HTTP/[^\"]+)\" (\d+) (.*)$",
            msg,
        )
        if not m:
            return re.sub(r"^(\d{1,3}(?:\.\d{1,3}){3})", r"\033[96m\1\033[0m", msg, count=1)
        ip, mid, ts, method, path, http_ver, code, tail = m.groups()
        code_i = int(code)
        code_color = "32" if 200 <= code_i < 400 else "33" if code_i < 500 else "31"
        quoted = (
            f"\"\033[92m{method}\033[0m \033[93m{path}\033[0m \033[36m{http_ver}\033[0m\""
        )
        return (
            f"\033[96m{ip}\033[0m{mid}"
            f"\033[{self.TS_DIM}m{ts}\033[0m {quoted} "
            f"\033[{code_color}m{code}\033[0m {tail}"
        )

    def _colorize_structured_message(self, msg: str) -> str:
        out = msg
        out = re.sub(r"\bevento=(\S+)", r"\033[93m\033[1mevento=\033[22m\033[1;93m\1\033[22m\033[0m", out)
        out = re.sub(r"\bmethod=(\S+)", r"\033[92mmethod=\033[1;92m\1\033[22m\033[0m", out)
        out = re.sub(r"\bpath=(\S+)", r"\033[94mpath=\033[1;94m\1\033[22m\033[0m", out)
        out = re.sub(r"\b(code|elapsed_ms|status)=(\S+)", r"\033[90m\1=\033[97m\2\033[0m", out)
        return out


class RequestIdFilter(logging.Filter):
    def filter(self, record):
        if not hasattr(record, "request_id"):
            try:
                record.request_id = getattr(g, "request_id", "-")
            except RuntimeError:
                record.request_id = "-"
        return True


allow_color = os.getenv("APP_LOG_COLOR", "1") != "0"
force_color = os.getenv("APP_LOG_FORCE_COLOR", "1") != "0"
_stream = sys.stdout
_stream_is_tty = bool(getattr(_stream, "isatty", lambda: False)())
_use_color = allow_color and (_stream_is_tty or force_color)

_root = logging.getLogger()
_root.handlers.clear()
_root.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

_handler = logging.StreamHandler(_stream)
_handler.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
_handler.addFilter(RequestIdFilter())
_handler.setFormatter(ConsoleUTCFormatter(LOG_FORMAT, use_color=_use_color))
_root.addHandler(_handler)

_base_logger = logging.getLogger("cybernet")


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

