import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

# Add project root directory to sys.path so 'src' can be resolved cleanly
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from log_parser import determine_user_status, parse_log_line, parse_timestamp  # noqa: E402


class TestLogParser(unittest.TestCase):
    """Test suite covering OpenSSH authentication log parsing and semantics."""

    def setUp(self) -> None:
        """Define standard test fixtures matching Ubuntu/OpenSSH log telemetry."""
        self.successful_log = (
            "2026-09-17T15:44:30.823176+00:00 ubuntu25 sshd-session[5353]: "
            "Accepted password for vboxuser from ::1 port 37226 ssh2"
        )
        self.failed_invalid_user_log = (
            "2026-09-17T15:53:20.071784+00:00 ubuntu25 sshd-session[5681]: "
            "Failed password for invalid user wronguser from ::1 port 39038 ssh2"
        )
        self.failed_without_invalid_marker_log = (
            "2026-09-17T16:10:05.123456+00:00 ubuntu25 sshd-session[6102]: "
            "Failed password for root from 192.168.1.50 port 45210 ssh2"
        )
        self.unrelated_log = (
            "2026-09-17T15:40:01.102938+00:00 ubuntu25 systemd[1]: "
            "Started Daily apt download activities."
        )

    def test_successful_login_parsing(self) -> None:
        """Ensure accepted authentications are classified correctly with valid user status."""
        event = parse_log_line(self.successful_log)

        self.assertIsNotNone(event)
        self.assertEqual(event["event_type"], "successful_login")
        self.assertEqual(event["auth_result"], "Accepted")
        self.assertEqual(event["auth_method"], "password")
        self.assertEqual(event["username"], "vboxuser")
        self.assertEqual(event["user_status"], "valid")
        self.assertEqual(event["source_ip"], "::1")
        self.assertEqual(event["source_port"], 37226)
        self.assertEqual(event["hostname"], "ubuntu25")
        self.assertEqual(event["process"], "sshd-session")
        self.assertEqual(event["pid"], 5353)
        self.assertEqual(event["ssh_protocol"], "ssh2")

    def test_failed_login_invalid_user(self) -> None:
        """Ensure explicit 'invalid user' log lines assign the 'invalid' status."""
        event = parse_log_line(self.failed_invalid_user_log)

        self.assertIsNotNone(event)
        self.assertEqual(event["event_type"], "failed_login")
        self.assertEqual(event["auth_result"], "Failed")
        self.assertEqual(event["username"], "wronguser")
        self.assertEqual(event["user_status"], "invalid")
        self.assertEqual(event["source_ip"], "::1")
        self.assertEqual(event["source_port"], 39038)
        self.assertEqual(event["pid"], 5681)

    def test_failed_login_unknown_user_status(self) -> None:
        """
        Verify semantic requirement:
        Missing 'invalid user' on a failed login must result in 'unknown',
        never assumed to be 'valid'.
        """
        event = parse_log_line(self.failed_without_invalid_marker_log)

        self.assertIsNotNone(event)
        self.assertEqual(event["event_type"], "failed_login")
        self.assertEqual(event["auth_result"], "Failed")
        self.assertEqual(event["username"], "root")
        self.assertEqual(event["user_status"], "unknown")
        self.assertEqual(event["source_ip"], "192.168.1.50")
        self.assertEqual(event["source_port"], 45210)

    def test_determine_user_status_direct(self) -> None:
        """Directly verify the three distinct user status outcomes."""
        self.assertEqual(determine_user_status("Failed", "invalid user"), "invalid")
        self.assertEqual(determine_user_status("Accepted", None), "valid")
        self.assertEqual(determine_user_status("Failed", None), "unknown")

    def test_unrelated_log_ignored(self) -> None:
        """Ensure non-SSH lines return None cleanly."""
        event = parse_log_line(self.unrelated_log)
        self.assertIsNone(event)

    def test_malformed_and_empty_input_handling(self) -> None:
        """Ensure malformed strings, corrupt data, or empty lines do not raise unhandled exceptions."""
        malformed_cases = [
            "",
            "   ",
            "Not a valid syslog line at all",
            "2026-09-17T15:53:20.071784+00:00 ubuntu25 sshd-session[bad_pid]: Failed password for user from ::1 port bad_port ssh2",
            "9999-99-99T99:99:99 ubuntu25 sshd-session[5681]: Failed password for user from 10.0.0.1 port 22 ssh2",
        ]
        for bad_line in malformed_cases:
            with self.subTest(bad_line=bad_line):
                self.assertIsNone(parse_log_line(bad_line))

    def test_timestamp_parsing_valid(self) -> None:
        """Validate accurate ISO 8601 parsing into a timezone-aware datetime object."""
        raw_ts = "2026-09-17T15:44:30.823176+00:00"
        parsed_dt = parse_timestamp(raw_ts)

        self.assertIsInstance(parsed_dt, datetime)
        self.assertEqual(parsed_dt.year, 2026)
        self.assertEqual(parsed_dt.month, 9)
        self.assertEqual(parsed_dt.day, 17)
        self.assertEqual(parsed_dt.hour, 15)
        self.assertEqual(parsed_dt.minute, 44)
        self.assertEqual(parsed_dt.second, 30)
        self.assertEqual(parsed_dt.microsecond, 823176)
        self.assertEqual(parsed_dt.tzinfo, timezone.utc)

    def test_timestamp_parsing_invalid(self) -> None:
        """Ensure invalid timestamps fail gracefully returning None."""
        self.assertIsNone(parse_timestamp("invalid-date-string"))
        self.assertIsNone(parse_timestamp(""))


if __name__ == "__main__":
    unittest.main()