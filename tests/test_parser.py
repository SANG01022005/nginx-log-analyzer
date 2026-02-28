"""
tests/test_parser.py
====================
Unit tests cho ``analyzer/parser.py`` — hàm ``parse_log_file()``.

Chiến lược
----------
* Không mock bất kỳ internal nào — test qua public API để đảm bảo
  toàn bộ luồng (regex → parse → build entry) hoạt động đúng.
* Mỗi file tạm được ghi bằng ``tempfile`` và xoá trong ``tearDownClass``.
* Mỗi ``TestCase`` tập trung đúng một khía cạnh.

Cách chạy
---------
    python -m unittest tests/test_parser.py -v
    pytest tests/test_parser.py -v
"""

import os
import sys
import tempfile
import unittest
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from analyzer.parser import parse_log_file   # noqa: E402


# ─────────────────────────────────────────────────────────────────────────────
# Các dòng log mẫu dùng chung
# ─────────────────────────────────────────────────────────────────────────────

_LINE_200 = (
    '203.0.113.42 - frank [10/Oct/2024:13:55:36 -0700] '
    '"GET /index.html HTTP/1.1" 200 2326 '
    '"http://example.com/" "Mozilla/5.0 (X11; Linux x86_64)"'
)
_LINE_404 = (
    '198.51.100.7 - - [10/Oct/2024:14:00:01 +0000] '
    '"GET /missing.html HTTP/1.1" 404 512 "-" "curl/7.88.1"'
)
_LINE_NO_BODY = (
    '10.0.0.1 - - [10/Oct/2024:14:01:00 +0000] '
    '"HEAD /health HTTP/1.0" 200 - "-" "-"'
)
_LINE_POST_500 = (
    '10.0.0.2 - - [10/Oct/2024:14:02:00 +0000] '
    '"POST /api/submit HTTP/1.1" 500 0 "-" "python-requests/2.28"'
)
# Malformed: TCP scanner gửi payload rác, nginx vẫn log được IP + timestamp
_LINE_MALFORMED = (
    '42.96.43.186 - - [10/Oct/2024:15:00:00 +0000] '
    '"MGLNDD_42.96.43.186_8080" 400 0 "-" "-"'
)
# Dòng hoàn toàn vô nghĩa — salvage cũng thất bại
_LINE_GARBAGE = "!!!! this_has_no_nginx_structure_at_all !!!!"


def _write(lines: list) -> str:
    """Ghi danh sách dòng ra file tạm UTF-8, trả về đường dẫn."""
    fd, path = tempfile.mkstemp(suffix=".log")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


# ─────────────────────────────────────────────────────────────────────────────
# 1. Parsing dòng well-formed
# ─────────────────────────────────────────────────────────────────────────────

class TestWellFormedParsing(unittest.TestCase):
    """parse_log_file() tách đúng từng trường của Combined Log Format."""

    @classmethod
    def setUpClass(cls):
        cls.path    = _write([_LINE_200, _LINE_404])
        cls.entries = parse_log_file(cls.path)

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.path)

    def test_two_entries_returned(self):
        self.assertEqual(len(self.entries), 2)

    def test_none_marked_malformed(self):
        self.assertTrue(all(not e["is_malformed"] for e in self.entries))

    # ip
    def test_ip_first_entry(self):
        self.assertEqual(self.entries[0]["ip"], "203.0.113.42")

    def test_ip_second_entry(self):
        self.assertEqual(self.entries[1]["ip"], "198.51.100.7")

    # status_code
    def test_status_200(self):
        self.assertEqual(self.entries[0]["status_code"], 200)

    def test_status_404(self):
        self.assertEqual(self.entries[1]["status_code"], 404)

    def test_status_is_int(self):
        for entry in self.entries:
            with self.subTest(ip=entry["ip"]):
                self.assertIsInstance(entry["status_code"], int)

    # method
    def test_method_uppercased(self):
        self.assertEqual(self.entries[0]["method"], "GET")

    # path
    def test_path_first_entry(self):
        self.assertEqual(self.entries[0]["path"], "/index.html")

    def test_path_second_entry(self):
        self.assertEqual(self.entries[1]["path"], "/missing.html")

    # bytes_sent
    def test_bytes_sent_is_int(self):
        self.assertIsInstance(self.entries[0]["bytes_sent"], int)

    def test_bytes_sent_value(self):
        self.assertEqual(self.entries[0]["bytes_sent"], 2326)

    # timestamp
    def test_timestamp_is_datetime(self):
        self.assertIsInstance(self.entries[0]["timestamp"], datetime)

    def test_timestamp_timezone_aware(self):
        self.assertIsNotNone(self.entries[0]["timestamp"].tzinfo)

    def test_timestamp_date(self):
        ts = self.entries[0]["timestamp"]
        self.assertEqual((ts.year, ts.month, ts.day), (2024, 10, 10))

    # well-formed không có key của malformed
    def test_no_raw_request_key(self):
        self.assertNotIn("raw_request", self.entries[0])

    def test_no_raw_line_key(self):
        self.assertNotIn("raw_line", self.entries[0])


# ─────────────────────────────────────────────────────────────────────────────
# 2. bytes_sent = "-"
# ─────────────────────────────────────────────────────────────────────────────

class TestBytesSentDash(unittest.TestCase):
    """bytes_sent='-' (response không có body) phải trả về 0."""

    @classmethod
    def setUpClass(cls):
        cls.path  = _write([_LINE_NO_BODY])
        cls.entry = parse_log_file(cls.path)[0]

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.path)

    def test_bytes_sent_zero(self):
        self.assertEqual(self.entry["bytes_sent"], 0)

    def test_not_malformed(self):
        self.assertFalse(self.entry["is_malformed"])

    def test_method_head(self):
        self.assertEqual(self.entry["method"], "HEAD")


# ─────────────────────────────────────────────────────────────────────────────
# 3. Malformed — salvage path
# ─────────────────────────────────────────────────────────────────────────────

class TestMalformedSalvage(unittest.TestCase):
    """
    Dòng không khớp Combined Log Format không bị loại bỏ.
    Parser salvage IP, timestamp, status_code và raw_request.
    """

    @classmethod
    def setUpClass(cls):
        cls.path  = _write([_LINE_MALFORMED])
        cls.entry = parse_log_file(cls.path)[0]

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.path)

    def test_entry_returned(self):
        self.assertEqual(len(parse_log_file(self.path)), 1)

    def test_is_malformed_true(self):
        self.assertTrue(self.entry["is_malformed"])

    def test_ip_salvaged(self):
        self.assertEqual(self.entry["ip"], "42.96.43.186")

    def test_status_code_salvaged(self):
        # Nginx ghi "400" vào cuối dòng — salvage regex phải bắt được
        self.assertEqual(self.entry["status_code"], 400)

    def test_timestamp_salvaged_as_datetime(self):
        self.assertIsInstance(self.entry["timestamp"], datetime)

    def test_raw_request_preserved(self):
        self.assertIn("raw_request", self.entry)
        self.assertIn("MGLNDD", self.entry["raw_request"])

    def test_raw_line_preserved(self):
        self.assertIn("raw_line", self.entry)
        self.assertIsInstance(self.entry["raw_line"], str)

    def test_no_method_field(self):
        self.assertNotIn("method", self.entry)

    def test_no_path_field(self):
        self.assertNotIn("path", self.entry)


# ─────────────────────────────────────────────────────────────────────────────
# 4. File hỗn hợp (well-formed + malformed)
# ─────────────────────────────────────────────────────────────────────────────

class TestMixedLog(unittest.TestCase):
    """Mỗi dòng xử lý độc lập; thứ tự entries khớp thứ tự dòng trong file."""

    @classmethod
    def setUpClass(cls):
        cls.path    = _write([_LINE_200, _LINE_MALFORMED, _LINE_404])
        cls.entries = parse_log_file(cls.path)

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.path)

    def test_total_three(self):
        self.assertEqual(len(self.entries), 3)

    def test_one_malformed(self):
        self.assertEqual(sum(1 for e in self.entries if e["is_malformed"]), 1)

    def test_two_well_formed(self):
        self.assertEqual(sum(1 for e in self.entries if not e["is_malformed"]), 2)

    def test_order_preserved(self):
        self.assertFalse(self.entries[0]["is_malformed"])
        self.assertTrue (self.entries[1]["is_malformed"])
        self.assertFalse(self.entries[2]["is_malformed"])

    def test_all_ips_present(self):
        ips = {e["ip"] for e in self.entries}
        self.assertIn("203.0.113.42", ips)
        self.assertIn("42.96.43.186", ips)
        self.assertIn("198.51.100.7", ips)


# ─────────────────────────────────────────────────────────────────────────────
# 5. Edge cases
# ─────────────────────────────────────────────────────────────────────────────

class TestEdgeCases(unittest.TestCase):
    """File rỗng, dòng trắng, và dòng không salvage được."""

    def _run(self, lines):
        path = _write(lines)
        try:
            return parse_log_file(path)
        finally:
            os.unlink(path)

    def test_empty_file_returns_empty_list(self):
        self.assertEqual(self._run([]), [])

    def test_blank_lines_skipped(self):
        entries = self._run(["", "   ", _LINE_200, ""])
        self.assertEqual(len(entries), 1)

    def test_total_salvage_failure_still_returns_entry(self):
        entries = self._run([_LINE_GARBAGE])
        self.assertEqual(len(entries), 1)
        self.assertTrue(entries[0]["is_malformed"])

    def test_ip_always_str_on_salvage_failure(self):
        # ip phải luôn là str — "unknown" nếu không tìm được
        entries = self._run([_LINE_GARBAGE])
        self.assertIsInstance(entries[0]["ip"], str)


# ─────────────────────────────────────────────────────────────────────────────
# 6. Error handling
# ─────────────────────────────────────────────────────────────────────────────

class TestErrorHandling(unittest.TestCase):
    """parse_log_file() raise đúng exception khi path có vấn đề."""

    def test_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            parse_log_file("/no/such/path/access.log")

    def test_directory_raises_value_error(self):
        with self.assertRaises(ValueError):
            parse_log_file(tempfile.gettempdir())


# ─────────────────────────────────────────────────────────────────────────────
# 7. Key schema contract
# ─────────────────────────────────────────────────────────────────────────────

class TestKeySchema(unittest.TestCase):
    """Mọi entry phải có đúng tập keys như docstring quy định."""

    _CORE      = {"ip", "timestamp", "status_code", "is_malformed"}
    _NORMAL    = {"method", "path", "bytes_sent", "referrer", "user_agent"}
    _MALFORMED = {"raw_request", "raw_line"}

    @classmethod
    def setUpClass(cls):
        path             = _write([_LINE_200, _LINE_MALFORMED])
        entries          = parse_log_file(path)
        os.unlink(path)
        cls.normal_e     = entries[0]
        cls.malformed_e  = entries[1]

    def test_core_keys_in_normal(self):
        for k in self._CORE:
            with self.subTest(key=k):
                self.assertIn(k, self.normal_e)

    def test_extra_keys_in_normal(self):
        for k in self._NORMAL:
            with self.subTest(key=k):
                self.assertIn(k, self.normal_e)

    def test_core_keys_in_malformed(self):
        for k in self._CORE:
            with self.subTest(key=k):
                self.assertIn(k, self.malformed_e)

    def test_extra_keys_in_malformed(self):
        for k in self._MALFORMED:
            with self.subTest(key=k):
                self.assertIn(k, self.malformed_e)


if __name__ == "__main__":
    unittest.main(verbosity=2)