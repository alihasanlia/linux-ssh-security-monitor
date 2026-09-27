import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

# Add project root directory to sys.path so 'src' can be resolved cleanly
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from detector import SSHBruteForceDetector  # noqa: E402


class TestSSHBruteForceDetector(unittest.TestCase):
    """Test suite covering sliding temporal window detection logic."""

    def setUp(self) -> None:
        """Set up standard baseline timestamps and a detector instance."""
        self.base_time = datetime(2026, 9, 17, 15, 0, 0, tzinfo=timezone.utc)
        # Default: 5-minute window, 5 failures for detection (MEDIUM), 15 for HIGH
        self.detector = SSHBruteForceDetector(
            time_window_minutes=5,
            failure_threshold=5,
            high_threshold=15,
        )

    def _create_event(
        self,
        source_ip: str = "192.168.1.100",
        event_type: str = "failed_login",
        offset_seconds: int = 0,
        username: str = "root",
        auth_result: str = "Failed",
    ) -> Dict[str, Any]:
        """Helper utility to generate structured log event dictionaries."""
        return {
            "timestamp": self.base_time + timedelta(seconds=offset_seconds),
            "source_ip": source_ip,
            "event_type": event_type,
            "auth_result": auth_result,
            "username": username,
            "source_port": 40000 + offset_seconds,
            "process": "sshd-session",
            "pid": 5000 + offset_seconds,
        }

    def test_single_failed_login_no_detection(self) -> None:
        """Ensure an isolated single failure does not trigger an alert."""
        events = [self._create_event()]
        detections = self.detector.detect(events)

        self.assertEqual(len(detections), 0)

    def test_failures_below_threshold_no_detection(self) -> None:
        """Ensure failure counts below the threshold (e.g., 4 < 5) do not alert."""
        events = [self._create_event(offset_seconds=i * 10) for i in range(4)]
        detections = self.detector.detect(events)

        self.assertEqual(len(detections), 0)

    def test_failures_reaching_threshold_triggers_detection(self) -> None:
        """Ensure reaching the failure threshold within the time window triggers an alert."""
        events = [self._create_event(offset_seconds=i * 15) for i in range(5)]
        detections = self.detector.detect(events)

        self.assertEqual(len(detections), 1)
        incident = detections[0]
        self.assertEqual(incident["detection_type"], "ssh_brute_force_suspected")
        self.assertEqual(incident["source_ip"], "192.168.1.100")
        self.assertEqual(incident["failed_attempts"], 5)
        self.assertEqual(incident["severity"], "MEDIUM")
        self.assertIn("root", incident["affected_usernames"])

    def test_independent_ip_tracking(self) -> None:
        """Ensure failed logins from distinct IPs are evaluated independently."""
        # 3 failures from IP A, 3 failures from IP B (total 6, but neither hits threshold 5)
        events = []
        for i in range(3):
            events.append(self._create_event(source_ip="192.168.1.10", offset_seconds=i * 5))
            events.append(self._create_event(source_ip="192.168.1.20", offset_seconds=i * 5))

        detections = self.detector.detect(events)
        self.assertEqual(len(detections), 0)

    def test_window_expiration_prevents_false_positives(self) -> None:
        """Ensure attempts spaced beyond the temporal window do not trigger an alert."""
        # 5 failures spaced 2 minutes apart across 8 minutes total.
        # Window is 5 minutes, so at most 3 failures fall within any single 5-minute interval.
        events = [self._create_event(offset_seconds=i * 120) for i in range(5)]
        detections = self.detector.detect(events)

        self.assertEqual(len(detections), 0)

    def test_successful_logins_ignored(self) -> None:
        """Ensure accepted authentications do not increment failure counters."""
        events = [
            self._create_event(offset_seconds=0, event_type="failed_login", auth_result="Failed"),
            self._create_event(offset_seconds=10, event_type="failed_login", auth_result="Failed"),
            self._create_event(offset_seconds=20, event_type="successful_login", auth_result="Accepted"),
            self._create_event(offset_seconds=30, event_type="successful_login", auth_result="Accepted"),
            self._create_event(offset_seconds=40, event_type="failed_login", auth_result="Failed"),
        ]
        detections = self.detector.detect(events)

        self.assertEqual(len(detections), 0)

    def test_ipv6_loopback_handling(self) -> None:
        """Validate that IPv6 addresses (such as ::1) correlate and alert properly."""
        events = [
            self._create_event(source_ip="::1", offset_seconds=i * 5, username=f"user_{i}")
            for i in range(6)
        ]
        detections = self.detector.detect(events)

        self.assertEqual(len(detections), 1)
        incident = detections[0]
        self.assertEqual(incident["source_ip"], "::1")
        self.assertEqual(incident["failed_attempts"], 6)
        self.assertEqual(len(incident["affected_usernames"]), 6)

    def test_high_severity_threshold(self) -> None:
        """Verify that reaching the high threshold escalates severity from MEDIUM to HIGH."""
        events = [self._create_event(offset_seconds=i * 2) for i in range(15)]
        detections = self.detector.detect(events)

        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["severity"], "HIGH")
        self.assertEqual(detections[0]["failed_attempts"], 15)

    def test_malformed_or_incomplete_events_handled_safely(self) -> None:
        """Ensure missing keys, None objects, or corrupt structures are skipped without crashing."""
        malformed_events = [
            {},
            {"event_type": "failed_login"},  # Missing timestamp and source_ip
            {"source_ip": "10.0.0.1"},        # Missing event_type and timestamp
            {"source_ip": "10.0.0.1", "timestamp": self.base_time},  # Missing event_type
            {"event_type": "failed_login", "source_ip": "10.0.0.1"},  # Missing timestamp
        ]

        # Should handle gracefully and return zero detections without raising KeyErrors
        detections = self.detector.detect(malformed_events)
        self.assertEqual(len(detections), 0)


if __name__ == "__main__":
    unittest.main()