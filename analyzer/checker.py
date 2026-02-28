"""
analyzer/checker.py
-------------------
Check IP addresses against the AbuseIPDB v2 API.

AbuseIPDB returns an ``abuseConfidenceScore`` (0–100) representing the
community's confidence that the IP is malicious.  This module treats any
score above ``config.settings.ABUSEIPDB_THRESHOLD`` (default 50) as a
positive "malicious" signal.

Public API
----------
    check_ip(ip)                      -> AbuseCheckResult
    check_ips(ips, max_workers=10)    -> list[AbuseCheckResult]

The batch helper ``check_ips`` uses a thread pool so a list of IPs is
resolved concurrently without blocking on each HTTP round-trip.

AbuseIPDB free tier: 1,000 checks / day.  The module logs a warning when
the API key is missing so the caller can degrade gracefully.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable

import requests

# config.py lives at the project root; support both installed-package layout
# and running scripts directly from analyzer/
try:
    from config import settings
except ImportError:
    from ..config import settings  # type: ignore[no-redef]

logger = logging.getLogger(__name__)

# ── AbuseIPDB v2 endpoint ────────────────────────────────────────────────────
_API_URL = "https://api.abuseipdb.com/api/v2/check"
_TIMEOUT = 10  # seconds per request


# ─────────────────────────────────────────────────────────────────────────────
# Result dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AbuseCheckResult:
    """
    Outcome of a single AbuseIPDB lookup.

    Attributes
    ----------
    ip                   : str   – queried IP address
    abuse_confidence     : int   – abuseConfidenceScore returned by the API
                                   (0 = clean, 100 = universally flagged)
    is_malicious         : bool  – True when abuse_confidence > threshold
    total_reports        : int   – number of distinct reports in the DB
    country_code         : str   – ISO-3166-1 alpha-2 country code (or "")
    isp                  : str   – ISP / organisation name (or "")
    domain               : str   – reverse-DNS domain (or "")
    is_whitelisted       : bool  – AbuseIPDB's own whitelist flag
    error                : str   – non-empty when the lookup failed
    """

    ip:               str
    abuse_confidence: int  = 0
    is_malicious:     bool = False
    total_reports:    int  = 0
    country_code:     str  = ""
    isp:              str  = ""
    domain:           str  = ""
    is_whitelisted:   bool = False
    error:            str  = ""

    # ── convenience ──────────────────────────────────────────────────────
    @property
    def ok(self) -> bool:
        """True when the lookup completed without error."""
        return not self.error

    def as_dict(self) -> dict:
        return {
            "ip":               self.ip,
            "abuse_confidence": self.abuse_confidence,
            "is_malicious":     self.is_malicious,
            "total_reports":    self.total_reports,
            "country_code":     self.country_code,
            "isp":              self.isp,
            "domain":           self.domain,
            "is_whitelisted":   self.is_whitelisted,
            "error":            self.error,
        }

    def summary(self) -> str:
        """One-line human-readable summary for logging / display."""
        if self.error:
            return f"{self.ip}  ✖ error: {self.error}"
        verdict = "🔴 MALICIOUS" if self.is_malicious else "🟢 clean"
        return (
            f"{self.ip:<18}  score={self.abuse_confidence:>3}  {verdict}"
            f"  reports={self.total_reports}  [{self.country_code}] {self.isp}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Single-IP check
# ─────────────────────────────────────────────────────────────────────────────

def check_ip(ip: str) -> AbuseCheckResult:
    """
    Query AbuseIPDB for a single IP address.

    Parameters
    ----------
    ip : str
        IPv4 or IPv6 address to check.

    Returns
    -------
    AbuseCheckResult
        Always returns a result object — never raises.  On failure the
        ``error`` field describes what went wrong and ``abuse_confidence``
        is 0 so the caller can safely apply threshold logic.

    Notes
    -----
    * API key is read from ``config.settings.ABUSEIPDB_API_KEY``.
    * Look-back window is ``config.settings.ABUSEIPDB_MAX_AGE`` days.
    * Threshold is ``config.settings.ABUSEIPDB_THRESHOLD``.
    """
    api_key = settings.ABUSEIPDB_API_KEY
    if not api_key:
        msg = "ABUSEIPDB_API_KEY is not configured — skipping lookup"
        logger.warning(msg)
        return AbuseCheckResult(ip=ip, error=msg)

    params = {
        "ipAddress":    ip,
        "maxAgeInDays": settings.ABUSEIPDB_MAX_AGE,
    }
    headers = {
        "Key":    api_key,
        "Accept": "application/json",
    }

    try:
        resp = requests.get(_API_URL, params=params, headers=headers, timeout=_TIMEOUT)
        return _parse_response(ip, resp)

    except requests.exceptions.ConnectionError:
        err = "connection failed — check network connectivity"
    except requests.exceptions.Timeout:
        err = f"request timed out after {_TIMEOUT}s"
    except requests.exceptions.RequestException as exc:
        err = f"request error: {exc}"
    except Exception as exc:              # noqa: BLE001
        err = f"unexpected error: {exc}"

    logger.error("AbuseIPDB check failed for %s — %s", ip, err)
    return AbuseCheckResult(ip=ip, error=err)


# ─────────────────────────────────────────────────────────────────────────────
# Batch check (concurrent)
# ─────────────────────────────────────────────────────────────────────────────

def check_ips(
    ips: Iterable[str],
    max_workers: int = 10,
) -> list[AbuseCheckResult]:
    """
    Check multiple IP addresses concurrently.

    Uses a ``ThreadPoolExecutor`` so HTTP I/O for each IP overlaps.
    Results are returned in the same order as the input iterable.

    Parameters
    ----------
    ips         : Iterable[str]  – IP addresses to check
    max_workers : int            – thread pool size (default 10)
                                   Keep ≤ AbuseIPDB rate limits.

    Returns
    -------
    list[AbuseCheckResult]
        One result per IP, preserving input order.
    """
    ip_list = list(ips)
    if not ip_list:
        return []

    logger.info("Checking %d IP(s) against AbuseIPDB (workers=%d)", len(ip_list), max_workers)

    # Map future → original index to reconstruct input order
    results: list[AbuseCheckResult | None] = [None] * len(ip_list)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_idx = {
            pool.submit(check_ip, ip): idx
            for idx, ip in enumerate(ip_list)
        }
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception as exc:          # noqa: BLE001
                results[idx] = AbuseCheckResult(ip=ip_list[idx], error=str(exc))

    # Cast: all slots filled by this point
    final: list[AbuseCheckResult] = results  # type: ignore[assignment]

    malicious = sum(1 for r in final if r.is_malicious)
    errors    = sum(1 for r in final if r.error)
    logger.info(
        "AbuseIPDB batch complete: %d checked, %d malicious, %d errors",
        len(final), malicious, errors,
    )
    return final


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _parse_response(ip: str, resp: requests.Response) -> AbuseCheckResult:
    """
    Turn a raw HTTP response into an ``AbuseCheckResult``.

    Handles the three distinct failure modes the API can return:
    - HTTP 4xx / 5xx  → error string from ``resp.status_code``
    - HTTP 200 with ``errors`` key in body  → API-level error
    - HTTP 200 with valid ``data`` key  → success path
    """
    # ── HTTP-level errors ─────────────────────────────────────────────────
    if resp.status_code == 401:
        err = "invalid API key (HTTP 401) — check ABUSEIPDB_API_KEY"
        logger.error("AbuseIPDB: %s", err)
        return AbuseCheckResult(ip=ip, error=err)

    if resp.status_code == 422:
        # Unprocessable Entity — usually an invalid IP format
        err = f"invalid IP address format rejected by API: {ip!r}"
        logger.warning("AbuseIPDB: %s", err)
        return AbuseCheckResult(ip=ip, error=err)

    if resp.status_code == 429:
        err = "rate limit exceeded (HTTP 429) — daily quota reached"
        logger.warning("AbuseIPDB: %s", err)
        return AbuseCheckResult(ip=ip, error=err)

    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError as exc:
        err = f"HTTP {resp.status_code}: {exc}"
        logger.error("AbuseIPDB: %s", err)
        return AbuseCheckResult(ip=ip, error=err)

    # ── Parse JSON body ───────────────────────────────────────────────────
    try:
        body = resp.json()
    except ValueError:
        err = f"non-JSON response (status={resp.status_code})"
        logger.error("AbuseIPDB: %s", err)
        return AbuseCheckResult(ip=ip, error=err)

    # ── API-level errors (valid JSON, but contains an "errors" key) ───────
    if api_errors := body.get("errors"):
        # AbuseIPDB returns a list of {detail, status, source} objects
        detail = api_errors[0].get("detail", "unknown API error")
        err    = f"API error: {detail}"
        logger.warning("AbuseIPDB: %s for IP %s", err, ip)
        return AbuseCheckResult(ip=ip, error=err)

    # ── Success path ──────────────────────────────────────────────────────
    data = body.get("data", {})
    score = int(data.get("abuseConfidenceScore", 0))

    result = AbuseCheckResult(
        ip               = data.get("ipAddress", ip),
        abuse_confidence = score,
        is_malicious     = score > settings.ABUSEIPDB_THRESHOLD,
        total_reports    = int(data.get("totalReports", 0)),
        country_code     = data.get("countryCode") or "",
        isp              = data.get("isp")          or "",
        domain           = data.get("domain")       or "",
        is_whitelisted   = bool(data.get("isWhitelisted", False)),
    )

    logger.debug(
        "AbuseIPDB: %s  score=%d  malicious=%s  reports=%d",
        result.ip, result.abuse_confidence, result.is_malicious, result.total_reports,
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Smoke test  (python checker.py <ip> [ip2 ...])
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    import logging as _logging

    _logging.basicConfig(level=logging.DEBUG, format="%(levelname)s  %(message)s")

    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <ip> [ip2 ...]")
        print(f"       ABUSEIPDB_API_KEY must be set in .env or environment")
        sys.exit(1)

    ips = sys.argv[1:]
    print(f"\nChecking {len(ips)} IP(s) against AbuseIPDB "
          f"(threshold={settings.ABUSEIPDB_THRESHOLD}, maxAge={settings.ABUSEIPDB_MAX_AGE}d)\n")

    results = check_ips(ips) if len(ips) > 1 else [check_ip(ips[0])]

    for r in results:
        print(f"  {r.summary()}")
        if r.is_malicious:
            print(f"    ⚠ Score {r.abuse_confidence} > threshold {settings.ABUSEIPDB_THRESHOLD}"
                  f" — IP flagged as malicious")

    malicious_count = sum(1 for r in results if r.is_malicious)
    print(f"\n  {malicious_count}/{len(results)} IP(s) flagged as malicious.")