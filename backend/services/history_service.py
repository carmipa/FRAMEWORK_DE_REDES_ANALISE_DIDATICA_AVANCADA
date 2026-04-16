import json
import uuid
from collections import deque
from datetime import datetime, timezone

from backend.common import HISTORY_FILE, HistoricoPersistenciaError, MAX_HISTORY, log_event

history_store = deque(maxlen=MAX_HISTORY)


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def formatar_timestamp_utc(ts):
    s = (ts or "").strip()
    if not s:
        return "—"
    try:
        normalized = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt_utc = dt.astimezone(timezone.utc)
        return dt_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return f"{s} UTC"


def carregar_historico():
    if not HISTORY_FILE.exists():
        return True
    try:
        raw = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        if isinstance(raw, list):
            for item in raw[-MAX_HISTORY:]:
                if isinstance(item, dict):
                    history_store.append(item)
        log_event("info", "history_load", status="ok", total=len(history_store))
        return True
    except Exception as exc:
        log_event("error", "history_load", status="error", erro=exc.__class__.__name__, exc_info=True)
        raise HistoricoPersistenciaError("Falha ao carregar histórico local.") from exc


def persistir_historico():
    try:
        HISTORY_FILE.write_text(
            json.dumps(list(history_store), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        log_event("info", "history_persist", status="ok", total=len(history_store))
        return True
    except Exception as exc:
        log_event("error", "history_persist", status="error", erro=exc.__class__.__name__, exc_info=True)
        raise HistoricoPersistenciaError("Falha ao persistir histórico local.") from exc


def registrar_consulta(entrada, res):
    if not res:
        return
    registro = {
        "id": str(uuid.uuid4())[:8],
        "timestamp": utc_now_iso(),
        "modo": entrada.get("modo", ""),
        "ip_entrada": entrada.get("ip", ""),
        "ipv6_entrada": entrada.get("ipv6", ""),
        "cidr_entrada": entrada.get("cidr", ""),
        "mask_entrada": entrada.get("mask_decimal", ""),
        "wildcard_entrada": entrada.get("wildcard_mask", ""),
        "rede": res.get("rede", ""),
        "broadcast": res.get("broad", ""),
        "mask": res.get("mask", ""),
        "cidr": res.get("cidr", ""),
        "tema": res.get("nivel_tema", ""),
    }
    history_store.appendleft(registro)
    log_event("info", "history_append", status="ok", modo=registro.get("modo"), id=registro.get("id"))
    persistir_historico()


def list_history():
    return list(history_store)


def paginate_history(history_limit_pre, history_page_pre):
    if not (history_limit_pre or "").isdigit():
        history_limit_pre = "1"
    history_limit_int = int(history_limit_pre)
    if history_limit_int < 0:
        history_limit_int = 0
    if history_limit_int > MAX_HISTORY:
        history_limit_int = MAX_HISTORY
    if not (history_page_pre or "").isdigit():
        history_page_pre = "1"
    history_page_int = int(history_page_pre)
    if history_page_int < 1:
        history_page_int = 1

    history_list = list(history_store)
    total_history = len(history_list)
    if history_limit_int > 0:
        total_history_pages = max(1, (total_history + history_limit_int - 1) // history_limit_int)
        if history_page_int > total_history_pages:
            history_page_int = total_history_pages
        history_start = (history_page_int - 1) * history_limit_int
        history_end = history_start + history_limit_int
        history_page_items = history_list[history_start:history_end]
        for item in history_page_items:
            item["timestamp_utc"] = formatar_timestamp_utc(item.get("timestamp", ""))
    else:
        total_history_pages = 1
        history_page_items = []
        history_page_int = 1

    return {
        "history": history_list,
        "history_limit": history_limit_int,
        "history_limit_pre": str(history_limit_int),
        "history_limit_max": MAX_HISTORY,
        "history_page": history_page_int,
        "total_history_pages": total_history_pages,
        "has_prev_history": history_page_int > 1,
        "has_next_history": history_page_int < total_history_pages,
        "history_page_items": history_page_items,
    }

