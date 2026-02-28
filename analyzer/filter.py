"""
analyzer/filter.py
------------------
Filter and threat-score Nginx log entries produced by ``parser.py``.

Three independent concerns are handled here:

1. **HTTP error filtering** – extract entries with 4xx / 5xx status codes.
2. **Blacklist checking**   – cross-reference IPs against a local CSV file.
3. **Threat scoring**       – assign each unique IP a ThreatLevel based on a
   combination of signals:

   Signal                                    │ Threat level bump
   ──────────────────────────────────────────┼────────────────────────
   Malformed / non-HTTP request              │ → HIGH  (automatic)
   IP on blacklist                           │ → HIGH  (automatic)
   AbuseIPDB score > threshold               │ → HIGH  (automatic)
   Path hits a HIGH-severity sensitive word  │ → HIGH  (automatic, 1 hit)
   Path hits a MEDIUM-severity sensitive word│ → MEDIUM (automatic, 1 hit)
   ≥ threshold 5xx errors                    │ → MEDIUM or HIGH
   ≥ threshold 4xx errors                    │ → MEDIUM
   No anomalies detected                     │ → LOW

   Sensitive path keywords are configured in ``SENSITIVE_PATHS``.  Each
   entry carries a ``level`` (HIGH/MEDIUM) and a human-readable ``label``
   used in the threat reason string.  A single matching request is enough
   to trigger the bump — volume does not matter.

Public API
----------
    filter_errors(entries)               → list[dict]   (4xx + 5xx only)
    load_blacklist(csv_path)             → set[str]     (IP strings)
    score_threats(entries, blacklist)    → list[ThreatResult]
"""

import csv
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

try:
    from analyzer.checker import check_ips, AbuseCheckResult
except ImportError:
    from checker import check_ips, AbuseCheckResult  # type: ignore[no-redef]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Threat level enum
# ---------------------------------------------------------------------------

class ThreatLevel(str, Enum):
    LOW    = "LOW"
    MEDIUM = "MEDIUM"
    HIGH   = "HIGH"

    def __lt__(self, other: "ThreatLevel") -> bool:
        order = {ThreatLevel.LOW: 0, ThreatLevel.MEDIUM: 1, ThreatLevel.HIGH: 2}
        return order[self] < order[other]


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class ThreatResult:
    """Aggregated threat profile for a single IP address."""
    ip:                  str
    threat_level:        ThreatLevel
    reasons:             list[str]          = field(default_factory=list)

    # request counters
    total_requests:      int                = 0
    malformed_count:     int                = 0
    error_4xx_count:     int                = 0
    error_5xx_count:     int                = 0

    # blacklist metadata
    in_blacklist:        bool               = False
    blacklist_reason:    str                = ""

    # raw payload samples for forensics (malformed entries only)
    malformed_samples:   list[str]          = field(default_factory=list)

    # AbuseIPDB enrichment
    country_code:        str                = ""   # ISO-3166-1 alpha-2 from AbuseIPDB
    abuse_confidence:    int                = 0    # abuseConfidenceScore (0–100)

    # sensitive path hits: list of (path, label) tuples — one per matched request
    sensitive_path_hits: list[tuple[str, str]] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "ip":               self.ip,
            "threat_level":     self.threat_level.value,
            "reasons":          self.reasons,
            "total_requests":   self.total_requests,
            "malformed_count":  self.malformed_count,
            "error_4xx_count":  self.error_4xx_count,
            "error_5xx_count":  self.error_5xx_count,
            "in_blacklist":     self.in_blacklist,
            "blacklist_reason": self.blacklist_reason,
            "country_code":     self.country_code,
            "abuse_confidence": self.abuse_confidence,
            "malformed_samples":     self.malformed_samples,
            "sensitive_path_hits": [
                {"path": p, "label": l} for p, l in self.sensitive_path_hits
            ],
        }


# ---------------------------------------------------------------------------
# Thresholds (tune to your environment)
# ---------------------------------------------------------------------------

THRESHOLDS = {
    "malformed_for_high":  1,   # any malformed request → HIGH immediately
    "5xx_for_high":        5,   # ≥ N 5xx errors → HIGH
    "5xx_for_medium":      2,   # ≥ N 5xx errors → MEDIUM
    "4xx_for_medium":      10,  # ≥ N 4xx errors → MEDIUM
    "malformed_samples":   3,   # how many raw payloads to store per IP
}


# ---------------------------------------------------------------------------
# Sensitive path keywords
# ---------------------------------------------------------------------------
# Each entry is a dict with:
#   keyword  – substring matched case-insensitively against the request path
#   level    – ThreatLevel to enforce if matched (HIGH or MEDIUM)
#   label    – short human-readable attack category for the reason string
#
# Matching rule: a SINGLE request hitting any keyword is enough to trigger
# the bump.  Add / remove / reorder entries freely — the scorer iterates all
# of them and picks the highest level found across all requests from that IP.
#
# Severity rationale:
#   HIGH   – known CVE targets, credential files, or remote-code-execution paths
#   MEDIUM – admin panels, login pages that warrant investigation but may be
#            legitimate (e.g. your own staff hitting /admin)

SENSITIVE_PATHS: list[dict] = [
    # ── HIGH severity ──────────────────────────────────────────────────────
    {
        "keyword": "geoserver",
        "level":   ThreatLevel.HIGH,
        "label":   "GeoServer RCE probe (CVE-2024-36401 / CVE-2023-25157)",
    },
    {
        "keyword": "etc/passwd",
        "level":   ThreatLevel.HIGH,
        "label":   "Path traversal / LFI — /etc/passwd",
    },
    {
        "keyword": "../",
        "level":   ThreatLevel.HIGH,
        "label":   "Directory traversal sequence (../)",
    },
    {
        "keyword": ".env",
        "level":   ThreatLevel.HIGH,
        "label":   "Environment file exfiltration probe (.env)",
    },
    {
        "keyword": "phpunit",
        "level":   ThreatLevel.HIGH,
        "label":   "PHPUnit RCE probe",
    },
    {
        "keyword": "eval-stdin",
        "level":   ThreatLevel.HIGH,
        "label":   "PHP eval-stdin RCE probe",
    },
    {
        "keyword": "shell",
        "level":   ThreatLevel.HIGH,
        "label":   "Shell / webshell access attempt",
    },
    # ── MEDIUM severity ────────────────────────────────────────────────────
    {
        "keyword": "admin",
        "level":   ThreatLevel.MEDIUM,
        "label":   "Admin panel access attempt",
    },
    {
        "keyword": "wp-login",
        "level":   ThreatLevel.MEDIUM,
        "label":   "WordPress login brute-force probe",
    },
    {
        "keyword": "wp-admin",
        "level":   ThreatLevel.MEDIUM,
        "label":   "WordPress admin panel probe",
    },
    {
        "keyword": "phpmyadmin",
        "level":   ThreatLevel.MEDIUM,
        "label":   "phpMyAdmin probe",
    },
    {
        "keyword": "login",
        "level":   ThreatLevel.MEDIUM,
        "label":   "Login endpoint probe",
    },
    {
        "keyword": "config",
        "level":   ThreatLevel.MEDIUM,
        "label":   "Configuration file probe",
    },
    {
        "keyword": "backup",
        "level":   ThreatLevel.MEDIUM,
        "label":   "Backup file discovery attempt",
    },
]

# Pre-compile: list of (compiled_regex, level, label) for O(1) lower() + search
_COMPILED_SENSITIVE: list[tuple] = [
    (
        __import__("re").compile(__import__("re").escape(sp["keyword"]), __import__("re").IGNORECASE),
        sp["level"],
        sp["label"],
    )
    for sp in SENSITIVE_PATHS
]


# ---------------------------------------------------------------------------
# 1. HTTP error filter
# ---------------------------------------------------------------------------

def filter_errors(entries: list[dict]) -> list[dict]:
    """
    Return only entries whose status_code is in the 4xx or 5xx range.

    Malformed entries with a salvaged status code are also included if they
    fall in those ranges.  Malformed entries with status_code=None are always
    included because the true status is unknown (treat as suspicious).

    Parameters
    ----------
    entries : list[dict]
        Output of ``parser.parse_log_file()``.

    Returns
    -------
    list[dict]
        Subset of *entries* with HTTP errors or unknown status.
    """
    result = []
    for entry in entries:
        status = entry.get("status_code")
        is_malformed = entry.get("is_malformed", False)

        if is_malformed and status is None:
            result.append(entry)          # unknown status — keep as suspicious
        elif status is not None and 400 <= status <= 599:
            result.append(entry)

    logger.info("filter_errors: %d/%d entries kept", len(result), len(entries))
    return result


# ---------------------------------------------------------------------------
# 2. Blacklist loader
# ---------------------------------------------------------------------------

def load_blacklist(csv_path: str) -> dict[str, str]:
    """
    Load an IP blacklist from a CSV file.

    Expected CSV format (header row required):
        ip,reason,added_date
        1.2.3.4,Known scanner,2024-01-15
        5.6.7.8,Brute force,2024-03-22

    The ``reason`` column is optional; other columns are ignored.

    Parameters
    ----------
    csv_path : str
        Path to the blacklist CSV file.

    Returns
    -------
    dict[str, str]
        Mapping of ``ip → reason``.  Empty string reason when column absent.

    Raises
    ------
    FileNotFoundError – if the CSV file does not exist.
    """
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"Blacklist file not found: {csv_path}")

    blacklist: dict[str, str] = {}

    with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)

        # Normalise column names to lowercase, strip whitespace
        if reader.fieldnames is None:
            logger.warning("Blacklist CSV '%s' appears empty", csv_path)
            return blacklist

        reader.fieldnames = [f.strip().lower() for f in reader.fieldnames]

        if "ip" not in reader.fieldnames:
            raise ValueError(
                f"Blacklist CSV must have an 'ip' column. "
                f"Found columns: {reader.fieldnames}"
            )

        for row_num, row in enumerate(reader, start=2):
            ip = row.get("ip", "").strip()
            if not ip:
                logger.warning("Blacklist row %d: empty IP — skipped", row_num)
                continue
            reason = row.get("reason", "").strip()
            blacklist[ip] = reason

    logger.info("Loaded %d IPs from blacklist '%s'", len(blacklist), csv_path)
    return blacklist


# ---------------------------------------------------------------------------
# 3. Threat scorer
# ---------------------------------------------------------------------------

def score_threats(
    entries: list[dict],
    blacklist: dict[str, str] | None = None,
    use_abuseipdb: bool = False,
) -> list[ThreatResult]:
    """
    Compute a ThreatResult for every unique IP seen in *entries*.

    Scoring logic (applied in priority order — all signals accumulate):

    ┌─────────────────────────────────────────────┬─────────────┐
    │ Condition                                   │ ThreatLevel │
    ├─────────────────────────────────────────────┼─────────────┤
    │ Any malformed (non-HTTP) request            │    HIGH     │
    │ IP present in blacklist                     │    HIGH     │
    │ ≥ THRESHOLDS["5xx_for_high"] 5xx errors     │    HIGH     │
    │ ≥ THRESHOLDS["5xx_for_medium"] 5xx errors   │   MEDIUM    │
    │ ≥ THRESHOLDS["4xx_for_medium"] 4xx errors   │   MEDIUM    │
    │ Sensitive HIGH-severity path probed         │    HIGH     │
    │ Sensitive MEDIUM-severity path probed       │   MEDIUM    │
    │ AbuseIPDB confidence score > threshold      │    HIGH     │
    │ None of the above                           │    LOW      │
    └─────────────────────────────────────────────┴─────────────┘

    Multiple HIGH conditions accumulate as separate ``reasons`` entries so
    that the reporter can explain *why* an IP is dangerous.

    Parameters
    ----------
    entries        : list[dict]          Output of ``parser.parse_log_file()``.
    blacklist      : dict[str, str]|None Output of ``load_blacklist()``; None skips.
    use_abuseipdb  : bool                When True, call ``checker.check_ips()``
                                         to enrich every unique IP via the
                                         AbuseIPDB v2 API.  Requires
                                         ``ABUSEIPDB_API_KEY`` in environment.
                                         Default: False (opt-in to avoid
                                         unintended API quota consumption).

    Returns
    -------
    list[ThreatResult]
        One result per unique IP, sorted by threat level (HIGH first) then
        by total request count descending.
    """
    if blacklist is None:
        blacklist = {}

    # --- Aggregate per-IP counters ---
    agg: dict[str, dict] = defaultdict(lambda: {
        "total": 0,
        "malformed": 0,
        "4xx": 0,
        "5xx": 0,
        "malformed_samples": [],
        # sensitive path hits: list of (path, label, level) — deduped by path+label
        "sensitive_hits": [],
        "sensitive_hit_keys": set(),     # (path, label) dedup guard
    })

    for entry in entries:
        ip = entry.get("ip") or "unknown"
        bucket = agg[ip]
        bucket["total"] += 1

        if entry.get("is_malformed"):
            bucket["malformed"] += 1
            # Collect a few raw payloads for the report
            if len(bucket["malformed_samples"]) < THRESHOLDS["malformed_samples"]:
                sample = entry.get("raw_request") or entry.get("raw_line", "")
                bucket["malformed_samples"].append(sample[:120])
        else:
            status = entry.get("status_code")
            if status is not None:
                if 400 <= status <= 499:
                    bucket["4xx"] += 1
                elif 500 <= status <= 599:
                    bucket["5xx"] += 1

            # ── Sensitive path detection ─────────────────────────────────
            path = entry.get("path") or ""
            for pattern, sp_level, sp_label in _COMPILED_SENSITIVE:
                if pattern.search(path):
                    key = (path, sp_label)
                    if key not in bucket["sensitive_hit_keys"]:
                        bucket["sensitive_hits"].append((path, sp_label, sp_level))
                        bucket["sensitive_hit_keys"].add(key)
                    # Only record the first matching rule per path to avoid
                    # flooding the report, but keep scanning for higher-level hits
                    break

    # --- AbuseIPDB enrichment (opt-in, runs once for all unique IPs) -------
    # Build lookup dict BEFORE the scoring loop so each IP costs O(1).
    abuse_lookup: dict[str, AbuseCheckResult] = {}
    if use_abuseipdb:
        unique_ips = [ip for ip in agg if ip != "unknown"]
        logger.info("Querying AbuseIPDB for %d unique IP(s)…", len(unique_ips))
        for result in check_ips(unique_ips):
            abuse_lookup[result.ip] = result

    # --- Score each IP ---
    results: list[ThreatResult] = []

    for ip, counts in agg.items():
        reasons: list[str] = []
        level = ThreatLevel.LOW

        # Signal 1 — malformed / non-HTTP requests (HIGHEST priority)
        if counts["malformed"] >= THRESHOLDS["malformed_for_high"]:
            level = ThreatLevel.HIGH
            reasons.append(
                f"Sent {counts['malformed']} malformed (non-HTTP) request(s) — "
                "possible TCP scanner, exploit attempt, or protocol abuse"
            )

        # Signal 2 — blacklist hit
        if ip in blacklist:
            level = ThreatLevel.HIGH          # already HIGH or upgrading to HIGH
            bl_reason = blacklist[ip] or "no reason given"
            reasons.append(f"Listed in blacklist: {bl_reason}")

        # Signal 3 — 5xx errors (server-side, often from hammering / fuzzing)
        if counts["5xx"] >= THRESHOLDS["5xx_for_high"]:
            level = ThreatLevel.HIGH
            reasons.append(
                f"{counts['5xx']} server-error (5xx) responses — "
                "may indicate brute-force or vulnerability scanning"
            )
        elif counts["5xx"] >= THRESHOLDS["5xx_for_medium"] and level == ThreatLevel.LOW:
            level = ThreatLevel.MEDIUM
            reasons.append(
                f"{counts['5xx']} server-error (5xx) responses"
            )

        # Signal 4 — 4xx errors (client-side, crawling / path discovery)
        if counts["4xx"] >= THRESHOLDS["4xx_for_medium"] and level == ThreatLevel.LOW:
            level = ThreatLevel.MEDIUM
            reasons.append(
                f"{counts['4xx']} client-error (4xx) responses — "
                "may indicate path enumeration or credential stuffing"
            )

        # Signal 5 — sensitive path keywords ─────────────────────────────
        # Walk every recorded hit and apply the highest severity found.
        # We report each unique (path, label) pair so the operator knows
        # *exactly* which URLs were probed, regardless of current level.
        high_hits   = [(p, lbl) for p, lbl, lvl in counts["sensitive_hits"] if lvl == ThreatLevel.HIGH]
        medium_hits = [(p, lbl) for p, lbl, lvl in counts["sensitive_hits"] if lvl == ThreatLevel.MEDIUM]

        if high_hits:
            level = ThreatLevel.HIGH          # unconditional upgrade
            for path, label in high_hits:
                reasons.append(f"Sensitive path probe [{label}] → {path!r}")

        if medium_hits:
            # Only upgrade LOW → MEDIUM; don't downgrade an existing HIGH
            if level == ThreatLevel.LOW:
                level = ThreatLevel.MEDIUM
            for path, label in medium_hits:
                reasons.append(f"Sensitive path probe [{label}] → {path!r}")

        # Build the flat (path, label) list stored on the result for reporters
        sensitive_path_hits = [(p, lbl) for p, lbl, _ in counts["sensitive_hits"]]

        # Signal 6 — AbuseIPDB community score ───────────────────────────
        # Populated only when use_abuseipdb=True; skipped silently otherwise.
        abuse_result: AbuseCheckResult | None = abuse_lookup.get(ip)
        country_code   = ""
        abuse_confidence = 0

        if abuse_result and not abuse_result.error:
            country_code     = abuse_result.country_code
            abuse_confidence = abuse_result.abuse_confidence

            if abuse_result.is_malicious:
                level = ThreatLevel.HIGH   # unconditional upgrade
                isp_info = f" ({abuse_result.isp})" if abuse_result.isp else ""
                reasons.append(
                    f"AbuseIPDB Confidence Score: {abuse_result.abuse_confidence}%{isp_info}"
                )
                logger.warning(
                    "AbuseIPDB flagged %s as malicious (score=%d, country=%s)",
                    ip, abuse_result.abuse_confidence, country_code,
                )
        elif abuse_result and abuse_result.error:
            logger.debug("AbuseIPDB lookup error for %s: %s", ip, abuse_result.error)

        if not reasons:
            reasons.append("No anomalies detected")

        results.append(ThreatResult(
            ip                 = ip,
            threat_level       = level,
            reasons            = reasons,
            total_requests     = counts["total"],
            malformed_count    = counts["malformed"],
            error_4xx_count    = counts["4xx"],
            error_5xx_count    = counts["5xx"],
            in_blacklist       = ip in blacklist,
            blacklist_reason   = blacklist.get(ip, ""),
            country_code       = country_code,
            abuse_confidence   = abuse_confidence,
            malformed_samples  = counts["malformed_samples"],
            sensitive_path_hits= sensitive_path_hits,
        ))

    # Sort: HIGH → MEDIUM → LOW, then by total requests desc
    level_order = {ThreatLevel.HIGH: 0, ThreatLevel.MEDIUM: 1, ThreatLevel.LOW: 2}
    results.sort(key=lambda r: (level_order[r.threat_level], -r.total_requests))

    high   = sum(1 for r in results if r.threat_level == ThreatLevel.HIGH)
    medium = sum(1 for r in results if r.threat_level == ThreatLevel.MEDIUM)
    low    = sum(1 for r in results if r.threat_level == ThreatLevel.LOW)
    logger.info(
        "score_threats: %d unique IPs — HIGH=%d MEDIUM=%d LOW=%d",
        len(results), high, medium, low,
    )
    return results


# ---------------------------------------------------------------------------
# Convenience wrapper
# ---------------------------------------------------------------------------

def analyze(
    entries: list[dict],
    blacklist_csv: str | None = None,
    use_abuseipdb: bool = False,
) -> tuple[list[dict], list[ThreatResult]]:
    """
    One-shot helper: run error filtering + threat scoring together.

    Parameters
    ----------
    entries        : list[dict]   Parsed log entries from ``parser``.
    blacklist_csv  : str | None   Path to CSV blacklist; None skips.
    use_abuseipdb  : bool         Forward to ``score_threats``; enables
                                  AbuseIPDB enrichment (default False).

    Returns
    -------
    (error_entries, threat_results)
    """
    blacklist = load_blacklist(blacklist_csv) if blacklist_csv else {}
    error_entries = filter_errors(entries)
    threats = score_threats(entries, blacklist, use_abuseipdb=use_abuseipdb)
    return error_entries, threats


# ---------------------------------------------------------------------------
# Smoke test  (python filter.py <access.log> [blacklist.csv])
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    import json
    from parser import parse_log_file   # noqa: relative import for direct run

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <access.log> [blacklist.csv]")
        sys.exit(1)

    log_path = sys.argv[1]
    bl_path  = sys.argv[2] if len(sys.argv) >= 3 else None

    all_entries = parse_log_file(log_path)
    error_entries, threats = analyze(all_entries, bl_path)

    print(f"\n{'='*60}")
    print(f"  HTTP Error Entries  ({len(error_entries)} total)")
    print(f"{'='*60}")
    for e in error_entries:
        ts  = e["timestamp"].isoformat() if e.get("timestamp") else "unknown"
        if e.get("is_malformed"):
            print(f"  [MALFORMED] {e['ip']:>18}  status={e.get('status_code','?')}  {ts}")
        else:
            print(f"  [{e['status_code']}] {e['ip']:>18}  {e.get('method','?')} {e.get('path','?')}  {ts}")

    print(f"\n{'='*60}")
    print(f"  Threat Report  ({len(threats)} unique IPs)")
    print(f"{'='*60}")
    for t in threats:
        badge = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}[t.threat_level.value]
        print(f"\n  {badge} {t.threat_level.value:<6}  IP: {t.ip}")
        print(f"           Requests: {t.total_requests}  "
              f"(malformed={t.malformed_count}, 4xx={t.error_4xx_count}, 5xx={t.error_5xx_count})")
        for reason in t.reasons:
            print(f"           • {reason}")
        if t.malformed_samples:
            print(f"           Payloads:")
            for sample in t.malformed_samples:
                print(f"             ↳ {sample!r}")
        if t.sensitive_path_hits:
            print(f"           Sensitive paths:")
            for path, label in t.sensitive_path_hits:
                print(f"             ↳ [{label}]  {path}")