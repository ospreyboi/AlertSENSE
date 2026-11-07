import os
from dotenv import load_dotenv

load_dotenv()


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


API_KEY = os.getenv("ALERTSENSE_API_KEY", "")
DB_URL = os.getenv("ALERTSENSE_DB_URL", "sqlite:///alertsense.db")

# Day 3: threat intel
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VT_KEY = os.getenv("VT_API_KEY", "")

# Day 4: response
AUTO_BLOCK_SCORE = _int("ALERTSENSE_AUTO_BLOCK_SCORE", 0)     # 0 = approval mode (no auto-blocking)
BLOCK_HOURS = _int("ALERTSENSE_BLOCK_HOURS", 24)
ALLOWLIST = {ip.strip() for ip in os.getenv("ALERTSENSE_ALLOWLIST", "127.0.0.1,::1").split(",") if ip.strip()}
NOTIFY_MIN_SCORE = _int("ALERTSENSE_NOTIFY_MIN_SCORE", 60)
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
WEBHOOK_URL = os.getenv("ALERTSENSE_WEBHOOK_URL", "")
