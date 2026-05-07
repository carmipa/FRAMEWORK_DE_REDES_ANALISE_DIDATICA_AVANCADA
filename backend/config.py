import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
HISTORY_FILE = BASE_DIR / "consulta_history.json"

# Flask
APP_HOST = os.getenv("APP_HOST", "127.0.0.1")
APP_PORT_RAW = os.getenv("APP_PORT", "5000")
APP_DEBUG = os.getenv("APP_DEBUG", "true").lower() in {"1", "true", "yes", "on"}
APP_OPEN_BROWSER = os.getenv("APP_OPEN_BROWSER", "true").lower() in {"1", "true", "yes", "on"}

# UI
REGUA_COUNT_OPCOES = {5, 10, 15, 25, 50, 100}
COMPARADOR_CIDR_PADRAO_A = "20"
COMPARADOR_CIDR_PADRAO_B = "24"

# Histórico
MAX_HISTORY = int(os.getenv("APP_MAX_HISTORY", "60"))

# DNS
DNS_CACHE_TTL_SECONDS = int(os.getenv("DNS_CACHE_TTL_SECONDS", "180"))
DNS_RESOLVE_TIMEOUT_SECONDS = float(
    os.getenv("DNS_RESOLVE_TIMEOUT_SECONDS", "3.0")
)
