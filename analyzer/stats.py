"""
analyzer/stats.py
-----------------
Aggregate statistics from parsed Nginx log entries.

Accepts any iterable of entry dicts produced by ``parser.parse_log_file()``,
including generators, so large log files are never fully loaded into RAM.

Public API
----------
    calculate(entries) -> StatsResult
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

logger = logging.getLogger(__name__)

TOP_N = 10  # entries returned in top_ips / top_paths

# Status-group label derived from the leading digit of the status code.
# Counter key "other" catches 1xx responses and None (malformed entries).
_STATUS_LABEL: dict[int, str] = {2: "2xx", 3: "3xx", 4: "4xx", 5: "5xx"}


# ─────────────────────────────────────────────────────────────────────────────
# Result dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class StatsResult:
    """
    Aggregated statistics for one Nginx log file (or any entry collection).

    Attributes
    ----------
    total_requests  : int             – total entries processed (incl. malformed)
    top_ips         : list[(ip, n)]   – TOP_N most frequent source IPs
    status_counts   : Counter[str]    – requests per group: "2xx"…"5xx"/"other"
    total_bandwidth : int             – sum of bytes_sent (bytes)
    top_paths       : list[(path, n)] – TOP_N most requested URL paths
    malformed_count : int             – entries flagged is_malformed=True
    unique_ips      : int             – distinct IP count
    unique_paths    : int             – distinct path count (excl. malformed)
    first_request   : datetime|None   – earliest timestamp seen
    last_request    : datetime|None   – latest timestamp seen
    method_counts   : Counter[str]    – requests per HTTP method
    """

    total_requests:   int                    = 0
    top_ips:          list[tuple[str, int]]  = field(default_factory=list)
    status_counts:    Counter                = field(default_factory=Counter)
    total_bandwidth:  int                    = 0
    top_paths:        list[tuple[str, int]]  = field(default_factory=list)
    malformed_count:  int                    = 0
    unique_ips:       int                    = 0
    unique_paths:     int                    = 0
    first_request:    datetime | None        = None
    last_request:     datetime | None        = None
    method_counts:    Counter                = field(default_factory=Counter)

    # ── bandwidth helpers ─────────────────────────────────────────────────

    def bandwidth_human(self) -> str:
        """Return total_bandwidth as a human-readable string (B/KB/MB/GB)."""
        b = self.total_bandwidth
        for unit, threshold in (("GB", 1_073_741_824), ("MB", 1_048_576), ("KB", 1_024)):
            if b >= threshold:
                return f"{b / threshold:.2f} {unit}"
        return f"{b} B"

    def as_dict(self) -> dict:
        return {
            "total_requests":  self.total_requests,
            "malformed_count": self.malformed_count,
            "unique_ips":      self.unique_ips,
            "unique_paths":    self.unique_paths,
            "total_bandwidth": self.total_bandwidth,
            "bandwidth_human": self.bandwidth_human(),
            "status_counts":   dict(self.status_counts),
            "method_counts":   dict(self.method_counts),
            "top_ips":         [{"ip": ip,  "count": n} for ip, n in self.top_ips],
            "top_paths":       [{"path": p, "count": n} for p,  n in self.top_paths],
            "first_request":   self.first_request.isoformat() if self.first_request else None,
            "last_request":    self.last_request.isoformat()  if self.last_request  else None,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def calculate(entries: Iterable[dict]) -> StatsResult:
    """
    Compute aggregate statistics over an iterable of parsed log entries.

    Consumes *entries* in a single pass — safe to pass a generator.
    Returns a zeroed ``StatsResult`` for empty input without raising errors.
    """
    ip_counter:     Counter[str] = Counter()
    path_counter:   Counter[str] = Counter()
    status_counter: Counter[str] = Counter()
    method_counter: Counter[str] = Counter()

    total_requests  = 0
    malformed_count = 0
    total_bandwidth = 0
    first_ts: datetime | None = None
    last_ts:  datetime | None = None

    for entry in entries:
        total_requests += 1
        is_malformed: bool = entry.get("is_malformed", False)

        # ── IP ────────────────────────────────────────────────────────────
        if ip := entry.get("ip"):
            ip_counter[ip] += 1

        # ── Status group: 200→"2xx", 404→"4xx", None→"other" ─────────────
        status: int | None = entry.get("status_code")
        status_counter[_STATUS_LABEL.get(status // 100 if status else 0, "other")] += 1

        # ── Bandwidth ─────────────────────────────────────────────────────
        total_bandwidth += entry.get("bytes_sent") or 0

        if is_malformed:
            malformed_count += 1
        else:
            # ── Path — strip query string so /search?q=a and /search?q=b unify
            if path := entry.get("path"):
                path_counter[path.split("?")[0] or "/"] += 1

            # ── HTTP method ───────────────────────────────────────────────
            if method := entry.get("method"):
                method_counter[method.upper()] += 1

        # ── Running min/max timestamps (no sort needed) ───────────────────
        if ts := entry.get("timestamp"):
            if first_ts is None or ts < first_ts:
                first_ts = ts
            if last_ts is None or ts > last_ts:
                last_ts = ts

    if total_requests == 0:
        logger.warning("calculate() received zero entries — returning empty StatsResult")
        return StatsResult()

    result = StatsResult(
        total_requests  = total_requests,
        top_ips         = ip_counter.most_common(TOP_N),
        status_counts   = status_counter,
        total_bandwidth = total_bandwidth,
        top_paths       = path_counter.most_common(TOP_N),
        malformed_count = malformed_count,
        unique_ips      = len(ip_counter),
        unique_paths    = len(path_counter),
        first_request   = first_ts,
        last_request    = last_ts,
        method_counts   = method_counter,
    )

    logger.info(
        "calculate: %d requests | %d unique IPs | %d unique paths | "
        "bandwidth=%s | 4xx=%d | 5xx=%d | malformed=%d",
        result.total_requests, result.unique_ips, result.unique_paths,
        result.bandwidth_human(),
        result.status_counts["4xx"], result.status_counts["5xx"],
        result.malformed_count,
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Smoke test  (python stats.py <access.log>)
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    import logging as _logging

    _logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    sys.path.insert(0, ".")
    sys.path.insert(0, "..")

    try:
        from parser import parse_log_file
    except ImportError:
        from analyzer.parser import parse_log_file  # type: ignore

    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <nginx_access.log>")
        sys.exit(1)

    stats = calculate(parse_log_file(sys.argv[1]))

    print(f"\n{'═'*56}")
    print(f"  Nginx Log Summary")
    print(f"{'═'*56}")
    print(f"  Total requests   : {stats.total_requests:>10,}")
    print(f"  Malformed        : {stats.malformed_count:>10,}")
    print(f"  Unique IPs       : {stats.unique_ips:>10,}")
    print(f"  Unique paths     : {stats.unique_paths:>10,}")
    print(f"  Total bandwidth  : {stats.bandwidth_human():>10}")
    if stats.first_request:
        print(f"  From             :  {stats.first_request.isoformat()}")
        print(f"  To               :  {stats.last_request.isoformat()}")  # type: ignore[union-attr]

    print(f"\n  Status Codes")
    for label in ("2xx", "3xx", "4xx", "5xx", "other"):
        if count := stats.status_counts[label]:
            print(f"    {label}  {count:>6,}  {'█' * min(count, 40)}")

    print(f"\n  HTTP Methods")
    for method, count in stats.method_counts.most_common():
        print(f"    {method:<8} {count:>6,}")

    print(f"\n  Top {TOP_N} IPs")
    for rank, (ip, count) in enumerate(stats.top_ips, 1):
        print(f"    {rank:>2}. {ip:<18}  {count:>6,} req")

    print(f"\n  Top {TOP_N} Paths")
    for rank, (path, count) in enumerate(stats.top_paths, 1):
        print(f"    {rank:>2}. {path:<40}  {count:>6,} req")
    print()