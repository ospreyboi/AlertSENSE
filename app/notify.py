"""Notifications to Telegram and/or a Slack-style webhook. Failures never break triage."""
import json
import logging
import time

import httpx

from app.config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, WEBHOOK_URL

log = logging.getLogger("alertsense.notify")
_last_sent: dict[str, float] = {}
COOLDOWN_S = 600   # same IP + rule notifies at most once per 10 minutes


def notify(text: str, key: str | None = None) -> None:
    if key:
        now = time.time()
        if now - _last_sent.get(key, 0) < COOLDOWN_S:
            return
        _last_sent[key] = now

    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        try:
            httpx.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                       json={"chat_id": TELEGRAM_CHAT_ID, "text": text[:4000]},
                       timeout=5).raise_for_status()
        except httpx.HTTPError as exc:
            # log only the error type: the exception message contains the URL with the bot token
            log.warning("Telegram notification failed: %s", type(exc).__name__)

    if WEBHOOK_URL:
        try:
            httpx.post(WEBHOOK_URL, json={"text": text[:3000], "content": text[:1900]},
                       timeout=5).raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("Webhook notification failed: %s", type(exc).__name__)

    if not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID) and not WEBHOOK_URL:
        log.warning("NOTIFY (no channel configured):\n%s", text)


def format_alert(alert, auto_blocked: bool = False) -> str:
    reasons = json.loads(alert.score_reasons or "[]")
    lines = [
        f"🚨 AlertSense | {(alert.priority or '?').upper()} ({alert.risk_score or 0:.0f}/100)",
        f"#{alert.id} {alert.rule_name}",
        f"Source IP: {alert.src_ip or '-'}",
    ]
    if alert.url:
        lines.append(f"URL: {alert.url[:200]}")
    lines.append("Why:")
    lines += [f"  {r}" for r in reasons[:4]]
    lines.append("🛑 Source IP auto-blocked" if auto_blocked
                 else f"➡️ To block: POST /alerts/{alert.id}/block")
    return "\n".join(lines)
