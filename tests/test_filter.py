"""
tests/test_filter.py
--------------------
Unit tests cho analyzer/filter.py — threat scoring logic.

Quy ước:
- Stub config/dotenv trước khi import filter để không cần file .env thật.
- Dùng unittest.mock.patch("filter.check_ips") để kiểm soát AbuseIPDB
  response mà không thực hiện network call.
- Mỗi TestCase kiểm tra đúng một tín hiệu (Signal) trong score_threats()
  để khi fail biết ngay nguyên nhân.
- helper entry() / abuse() tạo fixture ngắn gọn, đúng schema thật.

Chạy:
    python -m pytest tests/test_filter.py -v
    python tests/test_filter.py
"""

import os
import sys
import types
import unittest
from dataclasses import dataclass, field
from datetime import datetime, timezone
from unittest.mock import patch

# ── Stub config + dotenv trước khi import filter ─────────────────────────────
@dataclass(frozen=True)
class _FakeSettings:
    ABUSEIPDB_API_KEY:   str = "test-key"
    ABUSEIPDB_MAX_AGE:   int = 90
    ABUSEIPDB_THRESHOLD: int = 50
    def is_abuseipdb_configured(self): return True

_config_mod = types.ModuleType("config")
_config_mod.settings = _FakeSettings()
sys.modules["config"] = _config_mod
sys.modules.setdefault("dotenv", types.ModuleType("dotenv"))
sys.modules["dotenv"].load_dotenv = lambda *a, **k: None

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzer.checker import AbuseCheckResult
from analyzer.filter import (
    score_threats,
    filter_errors,
    ThreatLevel,
    ThreatResult,
    THRESHOLDS,
)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_NOW = datetime(2024, 10, 10, 12, 0, 0, tzinfo=timezone.utc)


def entry(
    ip: str,
    path: str = "/",
    status: int = 200,
    bw: int = 512,
    malformed: bool = False,
    method: str = "GET",
    raw: str = "GARBAGE_PAYLOAD",
) -> dict:
    """Tạo entry dict đúng schema parser.py trả về."""
    if malformed:
        return {
            "ip":           ip,
            "status_code":  None,        # salvage thất bại → None
            "timestamp":    _NOW,
            "is_malformed": True,
            "raw_request":  raw,
            "raw_line":     raw,
        }
    return {
        "ip":           ip,
        "path":         path,
        "status_code":  status,
        "bytes_sent":   bw,
        "timestamp":    _NOW,
        "method":       method,
        "referrer":     "-",
        "user_agent":   "TestAgent/1.0",
        "is_malformed": False,
    }


def abuse(
    ip: str,
    score: int,
    isp: str = "TestISP",
    country: str = "XX",
    error: str = "",
) -> AbuseCheckResult:
    """Tạo AbuseCheckResult giả để truyền vào mock check_ips()."""
    return AbuseCheckResult(
        ip=ip,
        abuse_confidence=score,
        is_malicious=(score > 50),
        total_reports=10,
        country_code=country,
        isp=isp,
        error=error,
    )


def scores(entries, blacklist=None, use_abuseipdb=False) -> dict[str, ThreatResult]:
    """Tiện ích: gọi score_threats() và trả về dict ip → ThreatResult."""
    return {r.ip: r for r in score_threats(entries, blacklist or {}, use_abuseipdb)}


# ─────────────────────────────────────────────────────────────────────────────
# 1. Baseline — IP sạch
# ─────────────────────────────────────────────────────────────────────────────

class TestCleanIP(unittest.TestCase):
    """IP không có dấu hiệu bất thường → LOW."""

    def test_level_is_low(self):
        r = scores([entry("1.1.1.1", status=200)])
        self.assertEqual(r["1.1.1.1"].threat_level, ThreatLevel.LOW)

    def test_reason_says_no_anomalies(self):
        r = scores([entry("1.1.1.1")])
        self.assertIn("No anomalies", " ".join(r["1.1.1.1"].reasons))

    def test_all_counters_zero(self):
        r = scores([entry("1.1.1.1", status=200)])
        t = r["1.1.1.1"]
        self.assertEqual(t.error_4xx_count, 0)
        self.assertEqual(t.error_5xx_count, 0)
        self.assertEqual(t.malformed_count, 0)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Signal 1 — Malformed request
# ─────────────────────────────────────────────────────────────────────────────

class TestMalformedSignal(unittest.TestCase):
    """Một request malformed → HIGH ngay lập tức."""

    def test_one_malformed_is_high(self):
        r = scores([entry("2.2.2.2", malformed=True)])
        self.assertEqual(r["2.2.2.2"].threat_level, ThreatLevel.HIGH)

    def test_reason_mentions_malformed(self):
        r = scores([entry("2.2.2.2", malformed=True)])
        joined = " ".join(r["2.2.2.2"].reasons).lower()
        self.assertIn("malformed", joined)

    def test_malformed_count_recorded(self):
        r = scores([entry("2.2.2.2", malformed=True)] * 3)
        self.assertEqual(r["2.2.2.2"].malformed_count, 3)

    def test_threshold_constant_is_one(self):
        """Thiết kế yêu cầu bất kỳ malformed nào cũng → HIGH."""
        self.assertEqual(THRESHOLDS["malformed_for_high"], 1)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Signal 2 — Blacklist nội bộ
# ─────────────────────────────────────────────────────────────────────────────

class TestBlacklistSignal(unittest.TestCase):
    """IP trong blacklist → HIGH, lưu đúng reason và flag."""

    _BL = {"5.5.5.5": "known scanner", "6.6.6.6": ""}

    def test_blacklisted_ip_is_high(self):
        r = scores([entry("5.5.5.5")], blacklist=self._BL)
        self.assertEqual(r["5.5.5.5"].threat_level, ThreatLevel.HIGH)

    def test_in_blacklist_flag_true(self):
        r = scores([entry("5.5.5.5")], blacklist=self._BL)
        self.assertTrue(r["5.5.5.5"].in_blacklist)

    def test_blacklist_reason_stored(self):
        r = scores([entry("5.5.5.5")], blacklist=self._BL)
        self.assertEqual(r["5.5.5.5"].blacklist_reason, "known scanner")

    def test_empty_reason_still_high(self):
        """Blacklist entry không có reason vẫn → HIGH."""
        r = scores([entry("6.6.6.6")], blacklist=self._BL)
        self.assertEqual(r["6.6.6.6"].threat_level, ThreatLevel.HIGH)

    def test_non_blacklisted_unaffected(self):
        r = scores([entry("9.9.9.9")], blacklist=self._BL)
        self.assertFalse(r["9.9.9.9"].in_blacklist)
        self.assertEqual(r["9.9.9.9"].threat_level, ThreatLevel.LOW)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Signal 3 — Lỗi 5xx
# ─────────────────────────────────────────────────────────────────────────────

class TestServerErrorSignal(unittest.TestCase):
    """≥5 lỗi 5xx → HIGH; 2-4 → MEDIUM; <2 → LOW."""

    def test_five_5xx_is_high(self):
        r = scores([entry("7.7.7.7", status=500)] * 5)
        self.assertEqual(r["7.7.7.7"].threat_level, ThreatLevel.HIGH)

    def test_six_5xx_also_high(self):
        r = scores([entry("7.7.7.7", status=503)] * 6)
        self.assertEqual(r["7.7.7.7"].threat_level, ThreatLevel.HIGH)

    def test_two_5xx_is_medium(self):
        r = scores([entry("7.7.7.7", status=502)] * 2)
        self.assertEqual(r["7.7.7.7"].threat_level, ThreatLevel.MEDIUM)

    def test_one_5xx_is_low(self):
        r = scores([entry("7.7.7.7", status=500)])
        self.assertEqual(r["7.7.7.7"].threat_level, ThreatLevel.LOW)

    def test_5xx_count_field(self):
        r = scores([entry("7.7.7.7", status=500)] * 3)
        self.assertEqual(r["7.7.7.7"].error_5xx_count, 3)

    def test_threshold_constants(self):
        self.assertEqual(THRESHOLDS["5xx_for_high"],   5)
        self.assertEqual(THRESHOLDS["5xx_for_medium"], 2)


# ─────────────────────────────────────────────────────────────────────────────
# 5. Signal 4 — Lỗi 4xx
# ─────────────────────────────────────────────────────────────────────────────

class TestClientErrorSignal(unittest.TestCase):
    """≥10 lỗi 4xx → MEDIUM; <10 → LOW."""

    def test_ten_4xx_is_medium(self):
        r = scores([entry("8.8.8.8", status=404)] * 10)
        self.assertEqual(r["8.8.8.8"].threat_level, ThreatLevel.MEDIUM)

    def test_nine_4xx_is_low(self):
        r = scores([entry("8.8.8.8", status=404)] * 9)
        self.assertEqual(r["8.8.8.8"].threat_level, ThreatLevel.LOW)

    def test_4xx_count_field(self):
        r = scores([entry("8.8.8.8", status=403)] * 5)
        self.assertEqual(r["8.8.8.8"].error_4xx_count, 5)

    def test_threshold_constant(self):
        self.assertEqual(THRESHOLDS["4xx_for_medium"], 10)


# ─────────────────────────────────────────────────────────────────────────────
# 6. Signal 5 — Sensitive path detection
# ─────────────────────────────────────────────────────────────────────────────

class TestSensitivePathSignal(unittest.TestCase):
    """Một request đến path nguy hiểm đủ để nâng threat level."""

    # HIGH-severity
    def test_geoserver_is_high(self):
        r = scores([entry("a.a.a.a", path="/geoserver/ows")])
        self.assertEqual(r["a.a.a.a"].threat_level, ThreatLevel.HIGH)

    def test_env_file_is_high(self):
        r = scores([entry("a.a.a.a", path="/.env")])
        self.assertEqual(r["a.a.a.a"].threat_level, ThreatLevel.HIGH)

    def test_etc_passwd_is_high(self):
        r = scores([entry("a.a.a.a", path="/../../etc/passwd")])
        self.assertEqual(r["a.a.a.a"].threat_level, ThreatLevel.HIGH)

    def test_phpunit_is_high(self):
        r = scores([entry("a.a.a.a", path="/vendor/phpunit/phpunit/eval-stdin.php")])
        self.assertEqual(r["a.a.a.a"].threat_level, ThreatLevel.HIGH)

    def test_shell_path_is_high(self):
        r = scores([entry("a.a.a.a", path="/cmd.shell")])
        self.assertEqual(r["a.a.a.a"].threat_level, ThreatLevel.HIGH)

    # MEDIUM-severity
    def test_admin_path_is_medium(self):
        r = scores([entry("b.b.b.b", path="/admin/dashboard")])
        self.assertEqual(r["b.b.b.b"].threat_level, ThreatLevel.MEDIUM)

    def test_wp_login_is_medium(self):
        r = scores([entry("b.b.b.b", path="/wp-login.php")])
        self.assertEqual(r["b.b.b.b"].threat_level, ThreatLevel.MEDIUM)

    def test_phpmyadmin_is_medium(self):
        r = scores([entry("b.b.b.b", path="/phpmyadmin/")])
        self.assertEqual(r["b.b.b.b"].threat_level, ThreatLevel.MEDIUM)

    # HIGH overrides MEDIUM
    def test_high_path_overrides_medium(self):
        entries = [
            entry("c.c.c.c", path="/admin"),       # MEDIUM
            entry("c.c.c.c", path="/etc/passwd"),  # HIGH
        ]
        r = scores(entries)
        self.assertEqual(r["c.c.c.c"].threat_level, ThreatLevel.HIGH)

    # Hit recorded in result
    def test_sensitive_hit_stored_in_result(self):
        r = scores([entry("d.d.d.d", path="/.env")])
        paths = [h[0] for h in r["d.d.d.d"].sensitive_path_hits]
        self.assertIn("/.env", paths)


# ─────────────────────────────────────────────────────────────────────────────
# 7. Signal 6 — AbuseIPDB enrichment
# ─────────────────────────────────────────────────────────────────────────────

class TestAbuseIPDBSignal(unittest.TestCase):
    """AbuseIPDB score > 50 → HIGH; ≤ 50 → không thay đổi; error → graceful."""

    def test_malicious_score_is_high(self):
        with patch("filter.check_ips", return_value=[abuse("10.0.0.1", 87, isp="EvilISP")]):
            r = scores([entry("10.0.0.1")], use_abuseipdb=True)
        self.assertEqual(r["10.0.0.1"].threat_level, ThreatLevel.HIGH)

    def test_reason_contains_score_percent_and_isp(self):
        with patch("filter.check_ips", return_value=[abuse("10.0.0.1", 87, isp="EvilISP")]):
            r = scores([entry("10.0.0.1")], use_abuseipdb=True)
        joined = " ".join(r["10.0.0.1"].reasons)
        self.assertIn("87%",      joined)
        self.assertIn("EvilISP",  joined)
        self.assertIn("AbuseIPDB", joined)

    def test_country_code_stored(self):
        with patch("filter.check_ips", return_value=[abuse("10.0.0.2", 90, country="CN")]):
            r = scores([entry("10.0.0.2")], use_abuseipdb=True)
        self.assertEqual(r["10.0.0.2"].country_code, "CN")

    def test_abuse_confidence_stored(self):
        with patch("filter.check_ips", return_value=[abuse("10.0.0.3", 75)]):
            r = scores([entry("10.0.0.3")], use_abuseipdb=True)
        self.assertEqual(r["10.0.0.3"].abuse_confidence, 75)

    def test_score_exactly_50_not_high(self):
        """score == threshold → KHÔNG phải malicious (dùng '>', không '>=')."""
        clean = AbuseCheckResult(
            ip="10.0.0.4", abuse_confidence=50, is_malicious=False,
            total_reports=0, country_code="US", isp="ISP",
        )
        with patch("filter.check_ips", return_value=[clean]):
            r = scores([entry("10.0.0.4")], use_abuseipdb=True)
        self.assertNotEqual(r["10.0.0.4"].threat_level, ThreatLevel.HIGH)

    def test_score_51_is_high(self):
        """score == threshold + 1 phải vượt ngưỡng."""
        with patch("filter.check_ips", return_value=[abuse("10.0.0.5", 51)]):
            r = scores([entry("10.0.0.5")], use_abuseipdb=True)
        self.assertEqual(r["10.0.0.5"].threat_level, ThreatLevel.HIGH)

    def test_api_error_graceful_degradation(self):
        """Lỗi từ API không crash — level giữ nguyên, không thêm reason."""
        err_result = AbuseCheckResult(ip="10.0.0.6", error="connection timeout")
        with patch("filter.check_ips", return_value=[err_result]):
            r = scores([entry("10.0.0.6")], use_abuseipdb=True)
        self.assertEqual(r["10.0.0.6"].threat_level, ThreatLevel.LOW)
        self.assertFalse(any("AbuseIPDB" in rs for rs in r["10.0.0.6"].reasons))

    def test_disabled_by_default(self):
        """check_ips không được gọi khi use_abuseipdb=False."""
        with patch("filter.check_ips") as mock_fn:
            scores([entry("10.0.0.7")], use_abuseipdb=False)
            mock_fn.assert_not_called()

    def test_stacks_on_existing_signal(self):
        """AbuseIPDB + signal khác → cả hai reason đều xuất hiện."""
        with patch("filter.check_ips", return_value=[abuse("10.0.0.8", 95, isp="BadISP")]):
            r = scores([entry("10.0.0.8", malformed=True)], use_abuseipdb=True)
        joined = " ".join(r["10.0.0.8"].reasons)
        self.assertEqual(r["10.0.0.8"].threat_level, ThreatLevel.HIGH)
        self.assertIn("malformed", joined.lower())
        self.assertIn("AbuseIPDB", joined)


# ─────────────────────────────────────────────────────────────────────────────
# 8. Kết quả nhiều IP — độc lập và được sắp xếp
# ─────────────────────────────────────────────────────────────────────────────

class TestMultipleIPsAndSorting(unittest.TestCase):
    """Mỗi IP được chấm điểm độc lập; kết quả trả về theo thứ tự HIGH > MEDIUM > LOW."""

    def test_ips_scored_independently(self):
        entries = [
            entry("safe.ip",   path="/",           status=200),
            entry("danger.ip", path="/etc/passwd", status=404),
        ]
        r = scores(entries)
        self.assertEqual(r["safe.ip"].threat_level,   ThreatLevel.LOW)
        self.assertEqual(r["danger.ip"].threat_level, ThreatLevel.HIGH)

    def test_result_count_equals_unique_ips(self):
        entries = [
            entry("a.a.a.a"), entry("a.a.a.a"),
            entry("b.b.b.b"),
        ]
        results = score_threats(entries)
        self.assertEqual(len({r.ip for r in results}), 2)

    def test_requests_aggregated_per_ip(self):
        r = scores([entry("x.x.x.x")] * 7)
        self.assertEqual(r["x.x.x.x"].total_requests, 7)

    def test_sorted_high_first(self):
        entries = [
            entry("lo.ip", path="/",            status=200),
            entry("hi.ip", path="/etc/passwd",  status=404),
            entry("md.ip", path="/admin",       status=403),
        ]
        results = score_threats(entries)
        self.assertEqual(results[0].threat_level, ThreatLevel.HIGH)
        self.assertEqual(results[1].threat_level, ThreatLevel.MEDIUM)
        self.assertEqual(results[2].threat_level, ThreatLevel.LOW)

    def test_tiebreak_by_request_count_desc(self):
        """Cùng level → IP có nhiều request hơn lên trước."""
        entries = [
            entry("heavy.ip", path="/.env"),
            entry("heavy.ip", path="/.env"),  # 2 requests
            entry("light.ip", path="/.env"),  # 1 request
        ]
        results = score_threats(entries)
        highs = [r for r in results if r.threat_level == ThreatLevel.HIGH]
        self.assertEqual(highs[0].ip, "heavy.ip")


# ─────────────────────────────────────────────────────────────────────────────
# 9. filter_errors() — hành vi thực tế
# ─────────────────────────────────────────────────────────────────────────────

class TestFilterErrors(unittest.TestCase):
    """
    filter_errors() giữ lại:
      - entries có status 4xx hoặc 5xx (bất kể is_malformed)
      - malformed entries có status_code=None (status không xác định → suspicious)

    Loại bỏ:
      - 2xx, 3xx
      - malformed entries đã salvage được status code nằm ngoài 4xx/5xx
    """

    def _run(self, entries):
        return {e["ip"]: e for e in filter_errors(entries)}

    def test_2xx_excluded(self):
        r = self._run([entry("a.a.a.a", status=200)])
        self.assertNotIn("a.a.a.a", r)

    def test_3xx_excluded(self):
        r = self._run([entry("b.b.b.b", status=301)])
        self.assertNotIn("b.b.b.b", r)

    def test_4xx_included(self):
        r = self._run([entry("c.c.c.c", status=404)])
        self.assertIn("c.c.c.c", r)

    def test_5xx_included(self):
        r = self._run([entry("d.d.d.d", status=500)])
        self.assertIn("d.d.d.d", r)

    def test_malformed_with_none_status_included(self):
        """
        Malformed entry với status_code=None (salvage thất bại) → suspicious,
        phải được giữ lại.
        """
        e = entry("e.e.e.e", malformed=True)          # helper đặt status_code=None
        self.assertIsNone(e["status_code"])            # kiểm tra đúng fixture
        r = self._run([e])
        self.assertIn("e.e.e.e", r)

    def test_malformed_with_salvaged_4xx_included(self):
        """Malformed entry đã salvage được status 400 cũng phải được giữ lại."""
        e = {
            "ip": "f.f.f.f", "status_code": 400,
            "is_malformed": True, "timestamp": _NOW,
            "raw_request": "GARBAGE", "raw_line": "GARBAGE",
        }
        r = self._run([e])
        self.assertIn("f.f.f.f", r)

    def test_empty_input(self):
        self.assertEqual(filter_errors([]), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)