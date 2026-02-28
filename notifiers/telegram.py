"""
notifiers/telegram.py
---------------------
Send alert messages to a Telegram chat via the Bot API.

Configuration (read from environment variables or a .env file):
    TELEGRAM_BOT_TOKEN   – bot token issued by @BotFather
    TELEGRAM_CHAT_ID     – target chat / group / channel ID

Usage
-----
    from notifiers.telegram import send_message

    ok = send_message("Hello from nginx-log-analyzer!")

The function returns True on success and False on any error so the caller
can decide whether to abort or continue.
"""

from __future__ import annotations

import logging
import os

import requests
from dotenv import load_dotenv

load_dotenv()  # no-op if .env is absent

logger = logging.getLogger(__name__)

_API_BASE = "https://api.telegram.org/bot{token}/sendMessage"
_TIMEOUT  = 10  # seconds


def send_message(
    text: str,
    parse_mode: str = "HTML",
    disable_web_page_preview: bool = True,
) -> bool:
    """
    Send *text* to the configured Telegram chat.

    Parameters
    ----------
    text                     : str   – message body (HTML or Markdown)
    parse_mode               : str   – "HTML" (default) or "MarkdownV2"
    disable_web_page_preview : bool  – suppress link previews (default True)

    Returns
    -------
    bool – True if Telegram accepted the message, False on any error.
    """
    token   = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID",   "").strip()

    if not token:
        logger.error("TELEGRAM_BOT_TOKEN is not set — skipping notification")
        return False
    if not chat_id:
        logger.error("TELEGRAM_CHAT_ID is not set — skipping notification")
        return False

    # Telegram hard-limits messages to 4096 characters
    if len(text) > 4096:
        text = text[:4000] + "\n\n<i>… message truncated …</i>"

    url     = _API_BASE.format(token=token)
    payload = {
        "chat_id":                  chat_id,
        "text":                     text,
        "parse_mode":               parse_mode,
        "disable_web_page_preview": disable_web_page_preview,
    }

    try:
        resp = requests.post(url, json=payload, timeout=_TIMEOUT)
        resp.raise_for_status()
        logger.info("Telegram message delivered (chat_id=%s, %d chars)", chat_id, len(text))
        return True

    except requests.exceptions.HTTPError as exc:
        logger.error("Telegram HTTP error %s: %s", exc.response.status_code, exc.response.text)
    except requests.exceptions.ConnectionError:
        logger.error("Telegram: connection failed — check network / token")
    except requests.exceptions.Timeout:
        logger.error("Telegram: request timed out after %ds", _TIMEOUT)
    except Exception as exc:                          # noqa: BLE001
        logger.error("Telegram: unexpected error — %s", exc)

    return False