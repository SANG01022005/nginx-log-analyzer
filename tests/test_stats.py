"""
tests/test_stats.py
-------------------
Unit tests cho analyzer/stats.py — calculate() và StatsResult.

Quy ước:
- Không cần mock hay file thật: calculate() nhận bất kỳ Iterable[dict].
- Fixture là list[dict] nhỏ, dễ đọc, tạo trực tiếp trong từng test.
- Mỗi TestCase tập trung một trường/tính năng của StatsResult để khi
  fail biết ngay vấn đề ở đâu.

Chạy:
    python -m pytest tests/test_stats.py -v
    python tests/test_stats.py
"""

import json
import os
import sys
import unittest
from collections import Counter
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from analyzer.stats import calculate, StatsResult, TOP_N

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_TZ = timezone.utc
_T1 = datetime(2024, 10, 10,  8, 0, 0, tzinfo=_TZ)   # sớm nhất
_T2 = datetime(2024, 10, 10, 20, 0, 0, tzinfo=_TZ)   # muộn nhất


def e(
    ip:       str,
    path:     str      = "/",
    status:   int      = 200,
    bw:       int      = 0,
    ts:       datetime = _T1,
    method:   str      = "GET",
    malformed: bool    = False,
) -> dict:
    """Tạo entry dict đúng schema parser.py."""
    if malformed:
        return {
            "ip":           ip,
            "status_code":  status,
            "timestamp":    ts,
            "is_malformed": True,
        }
    return {
        "ip":           ip,
        "path":         path,
        "status_code":  status,
        "bytes_sent":   bw,
        "timestamp":    ts,
        "method":       method,
        "referrer":     "-",
        "user_agent":   "-",
        "is_malformed": False,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 1. Empty input
# ─────────────────────────────────────────────────────────────────────────────

class TestEmptyInput(unittest.TestCase):
    """calculate([]) → StatsResult zeroed, không raise."""

    @classmethod
    def setUpClass(cls):
        cls.r = calculate([])

    def test_returns_stats_result(self):
        self.assertIsInstance(self.r, StatsResult)

    def test_total_requests_zero(self):
        self.assertEqual(self.r.total_requests, 0)

    def test_total_bandwidth_zero(self):
        self.assertEqual(self.r.total_bandwidth, 0)

    def test_top_ips_empty(self):
        self.assertEqual(self.r.top_ips, [])

    def test_top_paths_empty(self):
        self.assertEqual(self.r.top_paths, [])

    def test_unique_ips_zero(self):
        self.assertEqual(self.r.unique_ips, 0)

    def test_unique_paths_zero(self):
        self.assertEqual(self.r.unique_paths, 0)

    def test_first_request_none(self):
        self.assertIsNone(self.r.first_request)

    def test_last_request_none(self):
        self.assertIsNone(self.r.last_request)

    def test_malformed_count_zero(self):
        self.assertEqual(self.r.malformed_count, 0)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Total requests
# ─────────────────────────────────────────────────────────────────────────────

class TestTotalRequests(unittest.TestCase):
    """total_requests đếm cả malformed và well-formed."""

    def test_counts_all_entries(self):
        self.assertEqual(calculate([e("1.1.1.1")] * 7).total_requests, 7)

    def test_malformed_included_in_total(self):
        entries = [e("1.1.1.1"), e("2.2.2.2", malformed=True)]
        self.assertEqual(calculate(entries).total_requests, 2)

    def test_malformed_count_field(self):
        entries = [
            e("1.1.1.1"),
            e("2.2.2.2", malformed=True),
            e("3.3.3.3", malformed=True),
        ]
        self.assertEqual(calculate(entries).malformed_count, 2)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Bandwidth
# ─────────────────────────────────────────────────────────────────────────────

class TestBandwidth(unittest.TestCase):
    """total_bandwidth = Σ bytes_sent từ well-formed entries."""

    def test_basic_sum(self):
        entries = [e("1.1.1.1", bw=1000), e("2.2.2.2", bw=2500)]
        self.assertEqual(calculate(entries).total_bandwidth, 3500)

    def test_malformed_excluded(self):
        """Malformed không có bytes_sent → không cộng vào tổng."""
        entries = [e("1.1.1.1", bw=1000), e("2.2.2.2", malformed=True)]
        self.assertEqual(calculate(entries).total_bandwidth, 1000)

    def test_zero_bytes_included(self):
        entries = [e("1.1.1.1", bw=0), e("2.2.2.2", bw=500)]
        self.assertEqual(calculate(entries).total_bandwidth, 500)

    def test_large_value(self):
        entries = [e("1.1.1.1", bw=1_073_741_824)]   # 1 GB
        self.assertEqual(calculate(entries).total_bandwidth, 1_073_741_824)

    # ── bandwidth_human() unit thresholds ────────────────────────────────────
    def test_human_bytes(self):
        r = calculate([e("x", bw=512)])
        label = r.bandwidth_human()
        self.assertTrue(label.endswith(" B"), f"expected B, got: {label!r}")

    def test_human_kilobytes(self):
        r = calculate([e("x", bw=2 * 1024)])
        self.assertIn("KB", r.bandwidth_human())

    def test_human_megabytes(self):
        r = calculate([e("x", bw=2 * 1024 ** 2)])
        self.assertIn("MB", r.bandwidth_human())

    def test_human_gigabytes(self):
        r = calculate([e("x", bw=2 * 1024 ** 3)])
        self.assertIn("GB", r.bandwidth_human())

    def test_human_zero_bytes(self):
        r = calculate([])
        self.assertEqual(r.bandwidth_human(), "0 B")


# ─────────────────────────────────────────────────────────────────────────────
# 4. Top IPs
# ─────────────────────────────────────────────────────────────────────────────

class TestTopIPs(unittest.TestCase):
    """top_ips: list[(ip, count)] desc, capped tại TOP_N."""

    @classmethod
    def setUpClass(cls):
        cls.entries = [
            e("10.0.0.1"),                                            # 1 req
            e("10.0.0.2"), e("10.0.0.2"),                            # 2 req
            e("10.0.0.3"), e("10.0.0.3"), e("10.0.0.3"),            # 3 req
        ]
        cls.r = calculate(cls.entries)

    def test_first_ip_is_most_frequent(self):
        self.assertEqual(self.r.top_ips[0][0], "10.0.0.3")

    def test_first_ip_count(self):
        self.assertEqual(self.r.top_ips[0][1], 3)

    def test_second_ip_and_count(self):
        self.assertEqual(self.r.top_ips[1], ("10.0.0.2", 2))

    def test_third_ip_and_count(self):
        self.assertEqual(self.r.top_ips[2], ("10.0.0.1", 1))

    def test_elements_are_tuples(self):
        for item in self.r.top_ips:
            with self.subTest(item=item):
                self.assertIsInstance(item, tuple)
                self.assertEqual(len(item), 2)

    def test_capped_at_top_n(self):
        many = [e(f"192.168.0.{i}") for i in range(TOP_N + 5)]
        r = calculate(many)
        self.assertLessEqual(len(r.top_ips), TOP_N)

    def test_unique_ips_count(self):
        self.assertEqual(self.r.unique_ips, 3)

    def test_malformed_ip_in_top_ips(self):
        """Malformed entry vẫn có IP → được tính trong top_ips."""
        entries = [e("9.9.9.9", malformed=True)] * 4
        r = calculate(entries)
        self.assertEqual(r.top_ips[0], ("9.9.9.9", 4))


# ─────────────────────────────────────────────────────────────────────────────
# 5. Top Paths
# ─────────────────────────────────────────────────────────────────────────────

class TestTopPaths(unittest.TestCase):
    """top_paths: strip query string, malformed excluded, capped tại TOP_N."""

    def test_most_requested_first(self):
        entries = [
            e("a", path="/api"), e("a", path="/api"),
            e("a", path="/home"),
        ]
        r = calculate(entries)
        self.assertEqual(r.top_paths[0][0], "/api")
        self.assertEqual(r.top_paths[0][1], 2)

    def test_query_string_stripped(self):
        """/search?q=a và /search?q=b → hợp nhất thành /search."""
        entries = [
            e("a", path="/search?q=hello"),
            e("a", path="/search?q=world"),
            e("a", path="/other"),
        ]
        path_dict = dict(calculate(entries).top_paths)
        self.assertEqual(path_dict.get("/search"), 2)
        self.assertNotIn("/search?q=hello", path_dict)

    def test_malformed_excluded_from_paths(self):
        """Malformed entry không có path → không xuất hiện trong top_paths."""
        entries = [e("a", path="/legit"), e("b", malformed=True)]
        r = calculate(entries)
        paths = [p for p, _ in r.top_paths]
        self.assertIn("/legit", paths)
        self.assertNotIn(None, paths)

    def test_unique_paths_count(self):
        entries = [
            e("a", path="/x"), e("a", path="/y"), e("a", path="/x"),
        ]
        self.assertEqual(calculate(entries).unique_paths, 2)

    def test_capped_at_top_n(self):
        entries = [e("a", path=f"/p{i}") for i in range(TOP_N + 5)]
        self.assertLessEqual(len(calculate(entries).top_paths), TOP_N)


# ─────────────────────────────────────────────────────────────────────────────
# 6. Status code grouping
# ─────────────────────────────────────────────────────────────────────────────

class TestStatusCodes(unittest.TestCase):
    """status_counts: Counter với keys "2xx" "3xx" "4xx" "5xx" "other"."""

    @classmethod
    def setUpClass(cls):
        entries = [
            e("a", status=200), e("a", status=201),  # 2×2xx
            e("a", status=301),                       # 1×3xx
            e("a", status=404), e("a", status=404),  # 2×4xx
            e("a", status=500),                       # 1×5xx
        ]
        cls.r = calculate(entries)

    def test_2xx_count(self):
        self.assertEqual(self.r.status_counts["2xx"], 2)

    def test_3xx_count(self):
        self.assertEqual(self.r.status_counts["3xx"], 1)

    def test_4xx_count(self):
        self.assertEqual(self.r.status_counts["4xx"], 2)

    def test_5xx_count(self):
        self.assertEqual(self.r.status_counts["5xx"], 1)

    def test_is_counter(self):
        self.assertIsInstance(self.r.status_counts, Counter)

    def test_missing_key_returns_zero(self):
        """Counter trả về 0 cho key không có — không raise KeyError."""
        self.assertEqual(self.r.status_counts["other"], 0)

    def test_malformed_status_bucketed(self):
        """Status code trong malformed entry vẫn được bucket đúng."""
        r = calculate([e("a", status=400, malformed=True)])
        self.assertEqual(r.status_counts["4xx"], 1)


# ─────────────────────────────────────────────────────────────────────────────
# 7. Method counts
# ─────────────────────────────────────────────────────────────────────────────

class TestMethodCounts(unittest.TestCase):
    """method_counts: Counter theo HTTP method từ well-formed entries."""

    def test_get_counted(self):
        r = calculate([e("a", method="GET")] * 5)
        self.assertEqual(r.method_counts["GET"], 5)

    def test_post_counted(self):
        entries = [e("a", method="GET"), e("a", method="POST"), e("a", method="POST")]
        r = calculate(entries)
        self.assertEqual(r.method_counts["POST"], 2)

    def test_most_common_order(self):
        entries = [e("a", method="GET")] + [e("a", method="POST")] * 3
        r = calculate(entries)
        self.assertEqual(r.method_counts.most_common(1)[0][0], "POST")

    def test_malformed_excluded(self):
        """Malformed không có method → không cộng vào method_counts."""
        entries = [e("a", method="GET"), e("b", malformed=True)]
        r = calculate(entries)
        self.assertEqual(sum(r.method_counts.values()), 1)


# ─────────────────────────────────────────────────────────────────────────────
# 8. Timestamps
# ─────────────────────────────────────────────────────────────────────────────

class TestTimestamps(unittest.TestCase):
    """first_request = min timestamp; last_request = max timestamp."""

    def test_first_request_earliest(self):
        r = calculate([e("a", ts=_T2), e("b", ts=_T1)])
        self.assertEqual(r.first_request, _T1)

    def test_last_request_latest(self):
        r = calculate([e("a", ts=_T1), e("b", ts=_T2)])
        self.assertEqual(r.last_request, _T2)

    def test_none_timestamp_ignored(self):
        """Entry timestamp=None không ảnh hưởng min/max."""
        null_ts = {**e("b"), "timestamp": None}
        r = calculate([e("a", ts=_T1), null_ts])
        self.assertEqual(r.first_request, _T1)
        self.assertEqual(r.last_request,  _T1)

    def test_all_none_timestamps(self):
        null_ts = {**e("a"), "timestamp": None}
        r = calculate([null_ts])
        self.assertIsNone(r.first_request)
        self.assertIsNone(r.last_request)

    def test_single_entry_first_equals_last(self):
        r = calculate([e("a", ts=_T1)])
        self.assertEqual(r.first_request, _T1)
        self.assertEqual(r.last_request,  _T1)


# ─────────────────────────────────────────────────────────────────────────────
# 9. Generator input
# ─────────────────────────────────────────────────────────────────────────────

class TestGeneratorInput(unittest.TestCase):
    """calculate() chấp nhận generator, không chỉ list."""

    def test_generator_total_and_bandwidth(self):
        def gen():
            yield e("a", bw=1000)
            yield e("b", bw=2000)

        r = calculate(gen())
        self.assertEqual(r.total_requests,  2)
        self.assertEqual(r.total_bandwidth, 3000)

    def test_generator_top_ips(self):
        def gen():
            for _ in range(3):
                yield e("a.a.a.a")
            yield e("b.b.b.b")

        r = calculate(gen())
        self.assertEqual(r.top_ips[0], ("a.a.a.a", 3))


# ─────────────────────────────────────────────────────────────────────────────
# 10. as_dict() serialisation
# ─────────────────────────────────────────────────────────────────────────────

class TestAsDict(unittest.TestCase):
    """as_dict() → dict JSON-serialisable với đúng cấu trúc."""

    @classmethod
    def setUpClass(cls):
        entries = [
            e("1.1.1.1", bw=1024, status=200, ts=_T1),
            e("2.2.2.2", bw=512,  status=404, ts=_T2),
        ]
        cls.d = calculate(entries).as_dict()

    def test_required_keys(self):
        required = {
            "total_requests", "malformed_count", "total_bandwidth",
            "bandwidth_human", "unique_ips", "unique_paths",
            "status_counts", "method_counts",
            "top_ips", "top_paths",
            "first_request", "last_request",
        }
        for key in required:
            with self.subTest(key=key):
                self.assertIn(key, self.d)

    def test_top_ips_structure(self):
        for item in self.d["top_ips"]:
            with self.subTest(item=item):
                self.assertIn("ip",    item)
                self.assertIn("count", item)

    def test_top_paths_structure(self):
        for item in self.d["top_paths"]:
            with self.subTest(item=item):
                self.assertIn("path",  item)
                self.assertIn("count", item)

    def test_json_serialisable(self):
        """json.dumps không raise — toàn bộ output phải serialisable."""
        try:
            json.dumps(self.d, default=str)
        except (TypeError, ValueError) as exc:
            self.fail(f"as_dict() is not JSON-serialisable: {exc}")

    def test_bandwidth_human_is_string(self):
        self.assertIsInstance(self.d["bandwidth_human"], str)
        self.assertGreater(len(self.d["bandwidth_human"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)