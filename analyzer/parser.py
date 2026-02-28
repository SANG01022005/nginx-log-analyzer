"""
analyzer/parser.py
------------------
Parse Nginx access logs in Combined Log Format.

Combined Log Format pattern:
  $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
  "$http_referer" "$http_user_agent"

Example line:
  192.168.1.1 - frank [10/Oct/2024:13:55:36 -0700] "GET /index.html HTTP/1.1"
  200 2326 "http://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

Malformed entries (lines that do not match the Combined Log Format regex) are
NOT discarded.  Instead they are returned with ``is_malformed=True`` so that
``filter.py`` can flag the originating IP as HIGH DANGER.  The raw request
payload is preserved in the ``raw_request`` field for forensic inspection.
"""

import re
import logging
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex – Combined Log Format (normal, well-formed requests)
# ---------------------------------------------------------------------------
# Named groups:
#   ip            – remote address
#   timestamp_raw – e.g. "10/Oct/2024:13:55:36 -0700"
#   method        – HTTP verb
#   path          – request path + optional query string
#   status_code   – 3-digit HTTP status
#   bytes_sent    – body bytes ("-" when 0)
#   referrer      – Referer header value
#   user_agent    – User-Agent header value

COMBINED_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)'                          # remote_addr
    r'\s+\S+'                               # ident  (ignored)
    r'\s+\S+'                               # auth   (ignored)
    r'\s+\[(?P<timestamp_raw>[^\]]+)\]'     # [timestamp]
    r'\s+"(?P<method>\S+)'                  # "METHOD
    r'\s+(?P<path>\S+)'                     #  /path
    r'\s+\S+"'                              #  HTTP/x.y"
    r'\s+(?P<status_code>\d{3})'            # status
    r'\s+(?P<bytes_sent>\S+)'               # bytes
    r'\s+"(?P<referrer>[^"]*)"'             # "referrer"
    r'\s+"(?P<user_agent>[^"]*)"'           # "user-agent"
)

# ---------------------------------------------------------------------------
# Regex – salvage IP + timestamp from a malformed line
# ---------------------------------------------------------------------------
# Nginx still writes the client IP and timestamp even when the request field
# is garbage (e.g. TCP scanners sending raw payloads).  We extract what we
# can so the IP can be identified and threat-scored downstream.

MALFORMED_SALVAGE_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{2,39})'  # IPv4 or IPv6
    r'.*?'                                                     # ident / auth
    r'\[(?P<timestamp_raw>[^\]]+)\]'                          # [timestamp]
    r'.*?"(?P<raw_request>[^"]*)"'                            # "raw payload"
    r'\s+(?P<status_code>\d{3})'                              # status code
)

TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_log_file(filepath: str) -> list[dict]:
    """
    Parse an Nginx Combined Log Format file.

    Parameters
    ----------
    filepath : str
        Absolute or relative path to the log file.

    Returns
    -------
    list[dict]
        All entries — both well-formed and malformed.  Each dict always
        contains the following keys:

        Core fields (all entries):
          - ip           (str)
          - timestamp    (datetime | None)  – None only when salvage also fails
          - status_code  (int | None)
          - is_malformed (bool)             – True for non-HTTP / scanner traffic

        Well-formed only (is_malformed=False):
          - method, path, bytes_sent, referrer, user_agent

        Malformed only (is_malformed=True):
          - raw_request  (str)  – the verbatim payload inside the first quotes
          - raw_line     (str)  – full original log line for forensics

    Raises
    ------
    FileNotFoundError  – if *filepath* does not exist.
    ValueError         – if *filepath* is not a regular file.
    PermissionError    – if the process lacks read access.
    """
    path = Path(filepath)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {filepath}")
    if not path.is_file():
        raise ValueError(f"Path is not a regular file: {filepath}")

    entries: list[dict] = []
    total_lines = 0
    malformed_count = 0

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_number, raw_line in enumerate(fh, start=1):
            total_lines = line_number
            line = raw_line.strip()
            if not line:
                continue

            entry = _parse_line(line, line_number)
            entries.append(entry)

            if entry["is_malformed"]:
                malformed_count += 1

    good_count = len(entries) - malformed_count
    logger.info(
        "Finished parsing '%s': %d total lines | %d well-formed | %d malformed",
        filepath, total_lines, good_count, malformed_count,
    )
    return entries


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_line(line: str, line_number: int) -> dict:
    """
    Attempt to parse *line* as Combined Log Format.

    Always returns a dict; sets ``is_malformed=True`` when the line does not
    conform to the standard format and falls back to the salvage pattern.
    """
    match = COMBINED_LOG_PATTERN.match(line)
    if match:
        return _build_normal_entry(match, line_number)

    # --- Normal parse failed: try to salvage IP + metadata ---
    logger.warning(
        "Line %d: non-standard HTTP request (malformed) — attempting salvage: %r",
        line_number, line[:120],
    )
    return _build_malformed_entry(line, line_number)


def _build_normal_entry(match: re.Match, line_number: int) -> dict:
    """Build a well-formed entry dict from a successful regex match."""
    data = match.groupdict()
    timestamp = _parse_timestamp(data["timestamp_raw"], line_number)
    bytes_sent = _parse_bytes(data["bytes_sent"], line_number)

    return {
        "ip":          data["ip"],
        "timestamp":   timestamp,
        "method":      data["method"].upper(),
        "path":        data["path"],
        "status_code": int(data["status_code"]),
        "bytes_sent":  bytes_sent,
        "referrer":    data["referrer"],
        "user_agent":  data["user_agent"],
        "is_malformed": False,
    }


def _build_malformed_entry(line: str, line_number: int) -> dict:
    """
    Build a malformed entry dict.

    Uses MALFORMED_SALVAGE_PATTERN to extract whatever is recoverable (IP,
    timestamp, raw payload, status code).  If even that fails, all optional
    fields are set to None / sentinel values so downstream code can still
    operate without KeyError.
    """
    salvage = MALFORMED_SALVAGE_PATTERN.search(line)

    if salvage:
        ip          = salvage.group("ip")
        timestamp   = _parse_timestamp(salvage.group("timestamp_raw"), line_number)
        raw_request = salvage.group("raw_request")
        try:
            status_code = int(salvage.group("status_code"))
        except (TypeError, ValueError):
            status_code = None
        logger.info("Line %d: salvaged IP=%s status=%s payload=%r", line_number, ip, status_code, raw_request[:60])
    else:
        # Total salvage failure — preserve as much as possible
        ip          = _extract_first_ip(line)
        timestamp   = None
        raw_request = line
        status_code = None
        logger.error("Line %d: salvage also failed — raw line preserved for forensics", line_number)

    return {
        "ip":          ip,
        "timestamp":   timestamp,
        "status_code": status_code,
        "raw_request": raw_request,
        "raw_line":    line,
        "is_malformed": True,
    }


def _extract_first_ip(line: str) -> str:
    """Last-resort helper: grab the first IPv4 address found in *line*."""
    match = re.search(r'\d{1,3}(?:\.\d{1,3}){3}', line)
    return match.group(0) if match else "unknown"


def _parse_timestamp(raw: str, line_number: int) -> datetime | None:
    """Convert '10/Oct/2024:13:55:36 -0700' to a timezone-aware datetime."""
    try:
        return datetime.strptime(raw, TIMESTAMP_FORMAT)
    except ValueError:
        logger.warning("Line %d: cannot parse timestamp %r", line_number, raw)
        return None


def _parse_bytes(raw: str, line_number: int) -> int:
    """Convert bytes field to int; returns 0 for '-' (no body)."""
    if raw == "-":
        return 0
    try:
        value = int(raw)
        if value < 0:
            raise ValueError("negative value")
        return value
    except ValueError:
        logger.warning("Line %d: invalid bytes_sent %r — defaulting to 0", line_number, raw)
        return 0


# ---------------------------------------------------------------------------
# Quick smoke-test  (python parser.py <logfile>)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    import json

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <nginx_access.log>")
        sys.exit(1)

    results = parse_log_file(sys.argv[1])

    normal   = [e for e in results if not e["is_malformed"]]
    bad      = [e for e in results if e["is_malformed"]]

    print(f"\nTotal entries : {len(results)}")
    print(f"  Well-formed : {len(normal)}")
    print(f"  Malformed   : {len(bad)}")

    if bad:
        print("\n--- Malformed entries ---")
        for entry in bad:
            display = {**entry, "timestamp": entry["timestamp"].isoformat() if entry["timestamp"] else None}
            print(json.dumps(display, indent=2))

    if normal:
        print("\n--- First 3 well-formed entries ---")
        for entry in normal[:3]:
            display = {**entry, "timestamp": entry["timestamp"].isoformat()}
            print(json.dumps(display, indent=2))