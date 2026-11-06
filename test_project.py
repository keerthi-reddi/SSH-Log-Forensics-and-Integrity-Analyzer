
import tempfile
import unittest
from pathlib import Path

from src.log_reader import read_log_file
from src.log_parser import parse_log_line, parse_log_lines
from src.log_analyzer import analyze_events
from src.hash_checker import calculate_sha256, compare_hashes


SAMPLE = (
    "Nov 03 09:00:01 server sshd[1001]: Failed password for admin "
    "from 192.168.1.10 port 5001 ssh2"
)


class TestSSHLogAnalyzer(unittest.TestCase):

    def test_log_file_reading(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.log"
            path.write_text(SAMPLE + "\n", encoding="utf-8")
            self.assertEqual(len(read_log_file(path)), 1)

    def test_log_parsing(self):
        event = parse_log_line(SAMPLE)
        self.assertEqual(event["event"], "failed")
        self.assertEqual(event["username"], "admin")
        self.assertEqual(event["source_ip"], "192.168.1.10")
        self.assertTrue(event["valid_ip"])

    def test_failed_login_count(self):
        events = parse_log_lines([SAMPLE])
        self.assertEqual(analyze_events(events)["failed_logins"], 1)

    def test_successful_login_count(self):
        success = SAMPLE.replace(
            "Failed password", "Accepted password"
        )
        events = parse_log_lines([success])
        self.assertEqual(
            analyze_events(events)["successful_logins"], 1
        )

    def test_suspicious_ip_detection(self):
        events = parse_log_lines([SAMPLE] * 4)
        result = analyze_events(events, threshold=3)
        self.assertEqual(
            result["suspicious_ips"]["192.168.1.10"], 4
        )

    def test_sha256_hash(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.log"
            path.write_text("test", encoding="utf-8")
            digest = calculate_sha256(path)
            self.assertEqual(len(digest), 64)

    def test_hash_comparison(self):
        self.assertTrue(compare_hashes("ABC123", "abc123"))
        self.assertFalse(compare_hashes("abc123", "def456"))


if __name__ == "__main__":
    unittest.main()
