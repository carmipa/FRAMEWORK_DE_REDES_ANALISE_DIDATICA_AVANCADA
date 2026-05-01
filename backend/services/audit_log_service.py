from __future__ import annotations

import os
from collections import deque
from datetime import datetime, timezone
from typing import Any

AUDIT_LOG_LIMIT = int(os.getenv("APP_AUDIT_LOG_LIMIT", "400"))
_AUDIT_LOGS: deque[dict[str, Any]] = deque(maxlen=AUDIT_LOG_LIMIT)

_LEVEL_ICON = {
    "DEBUG": "🛠️",
    "INFO": "ℹ️",
    "WARNING": "⚠️",
    "ERROR": "❌",
    "CRITICAL": "🚨",
}

_LEVEL_BADGE = {
    "DEBUG": "info",
    "INFO": "primary",
    "WARNING": "warning",
    "ERROR": "danger",
    "CRITICAL": "danger",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def register_audit_event(
    *,
    level: str,
    evento: str,
    fields: dict[str, Any] | None = None,
    request_id: str = "-",
) -> None:
    payload = dict(fields or {})
    level_up = (level or "INFO").upper()
    motivo = payload.pop("reason", "") or payload.pop("motivo", "")
    item = {
        "timestamp_utc": utc_now_iso(),
        "level": level_up,
        "level_icon": _LEVEL_ICON.get(level_up, "ℹ️"),
        "badge": _LEVEL_BADGE.get(level_up, "secondary"),
        "evento": evento,
        "request_id": request_id or "-",
        "motivo": str(motivo).strip(),
        "fields": payload,
    }
    _AUDIT_LOGS.appendleft(item)


def list_audit_logs(*, level: str = "", limit: int = 200) -> list[dict[str, Any]]:
    level_norm = (level or "").strip().upper()
    logs = list(_AUDIT_LOGS)
    if level_norm:
        logs = [item for item in logs if item["level"] == level_norm]
    if limit > 0:
        logs = logs[:limit]
    return logs


def audit_log_stats() -> dict[str, int]:
    stats = {"DEBUG": 0, "INFO": 0, "WARNING": 0, "ERROR": 0, "CRITICAL": 0}
    for item in _AUDIT_LOGS:
        lvl = item.get("level", "INFO")
        if lvl not in stats:
            stats[lvl] = 0
        stats[lvl] += 1
    stats["TOTAL"] = len(_AUDIT_LOGS)
    return stats
