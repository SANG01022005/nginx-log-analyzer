"""
config.py
---------
Central configuration loader for nginx-log-analyzer.

All settings are read from environment variables, which can be supplied via
a ``.env`` file in the project root (loaded automatically by python-dotenv).

Usage
-----
    from config import settings

    print(settings.ABUSEIPDB_API_KEY)
    print(settings.TELEGRAM_BOT_TOKEN)

Never import raw ``os.getenv()`` calls scattered across modules — import from
here instead so every key name and default lives in one place.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# Load .env from the project root (file is optional — no error if absent)
_ENV_FILE = Path(__file__).parent / ".env"
load_dotenv(_ENV_FILE)


@dataclass(frozen=True)
class _Settings:
    """
    Immutable snapshot of all configuration values read at import time.

    Attributes
    ----------
    ABUSEIPDB_API_KEY   : str   – AbuseIPDB v2 API key
                                  https://www.abuseipdb.com/account/api
    ABUSEIPDB_MAX_AGE   : int   – look-back window in days (default 90)
    ABUSEIPDB_THRESHOLD : int   – abuseConfidenceScore above which an IP is
                                  considered malicious (default 50)

    TELEGRAM_BOT_TOKEN  : str   – Telegram bot token from @BotFather
    TELEGRAM_CHAT_ID    : str   – target chat / group / channel ID
    """

    # ── AbuseIPDB ─────────────────────────────────────────────────────────
    ABUSEIPDB_API_KEY:    str = field(default="")
    ABUSEIPDB_MAX_AGE:    int = field(default=90)
    ABUSEIPDB_THRESHOLD:  int = field(default=50)

    # ── Telegram ──────────────────────────────────────────────────────────
    TELEGRAM_BOT_TOKEN:   str = field(default="")
    TELEGRAM_CHAT_ID:     str = field(default="")

    # ── Factory: read from environment ───────────────────────────────────
    @classmethod
    def from_env(cls) -> "_Settings":
        return cls(
            ABUSEIPDB_API_KEY   = os.getenv("ABUSEIPDB_API_KEY",   "").strip(),
            ABUSEIPDB_MAX_AGE   = int(os.getenv("ABUSEIPDB_MAX_AGE",   "90")),
            ABUSEIPDB_THRESHOLD = int(os.getenv("ABUSEIPDB_THRESHOLD", "50")),
            TELEGRAM_BOT_TOKEN  = os.getenv("TELEGRAM_BOT_TOKEN",  "").strip(),
            TELEGRAM_CHAT_ID    = os.getenv("TELEGRAM_CHAT_ID",    "").strip(),
        )

    # ── Helpers ───────────────────────────────────────────────────────────
    def is_abuseipdb_configured(self) -> bool:
        return bool(self.ABUSEIPDB_API_KEY)

    def is_telegram_configured(self) -> bool:
        return bool(self.TELEGRAM_BOT_TOKEN and self.TELEGRAM_CHAT_ID)


# Module-level singleton — import this in other modules
settings = _Settings.from_env()