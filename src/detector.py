from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Set


class SSHBruteForceDetector:
    """
    Evaluates authentication event streams to detect patterns consistent
    with SSH brute-force or high-frequency credential stuffing.
    """

    def __init__(
        self,
        time_window_minutes: int = 5,
        failure_threshold: int = 5,
        high_threshold: int = 15,
    ) -> None:
        """
        Initializes the detector with configurable detection thresholds.

        Args:
            time_window_minutes: Duration of the sliding evaluation window in minutes.
            failure_threshold: Minimum failed attempts inside the window to trigger MEDIUM severity.
            high_threshold: Minimum failed attempts inside the window to trigger HIGH severity.
        """
        self.time_window = timedelta(minutes=time_window_minutes)
        self.failure_threshold = failure_threshold
        self.high_threshold = high_threshold

    def _determine_severity(self, attempt_count: int) -> str:
        """
        Determines calibrated severity based on event velocity.

        Args:
            attempt_count: Number of failed attempts within the sliding window.

        Returns:
            Severity string: 'HIGH' or 'MEDIUM'.
        """
        if attempt_count >= self.high_threshold:
            return "HIGH"
        return "MEDIUM"

    def _build_detection_record(
        self,
        source_ip: str,
        matching_events: List[Dict[str, Any]],
        severity: str,
    ) -> Dict[str, Any]:
        """
        Constructs a structured detection payload for SOC triage.

        Args:
            source_ip: Originating client IP address (IPv4 or IPv6).
            matching_events: List of failed event dictionaries correlated inside the window.
            severity: Assigned alert severity rating ('MEDIUM' or 'HIGH').

        Returns:
            Structured dictionary containing alert metadata.
        """
        # Collect all targeted usernames, omitting empty or missing values
        usernames: List[str] = sorted(
            {
                e["username"]
                for e in matching_events
                if e.get("username")
            }
        )

        first_timestamp: datetime = matching_events[0]["timestamp"]
        last_timestamp: datetime = matching_events[-1]["timestamp"]
        attempt_count: int = len(matching_events)
        window_minutes: int = int(self.time_window.total_seconds() // 60)

        description = (
            f"Observed {attempt_count} failed SSH authentication attempts from {source_ip} "
            f"within a {window_minutes}-minute window targeting {len(usernames)} account(s). "
            f"This activity is consistent with automated credential guessing or SSH brute-force behavior."
        )

        return {
            "detection_type": "ssh_brute_force_suspected",
            "severity": severity,
            "source_ip": source_ip,
            "failed_attempts": attempt_count,
            "first_attempt_timestamp": first_timestamp.isoformat(),
            "last_attempt_timestamp": last_timestamp.isoformat(),
            "time_window_minutes": window_minutes,
            "affected_usernames": usernames,
            "description": description,
        }

    def detect(self, events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Processes an iterable of parsed log events and identifies candidate brute-force patterns.

        Args:
            events: Iterable of structured dictionaries produced by log_parser.py.

        Returns:
            A list of structured detection records.
        """
        # Step 1: Bucket failures by source IP address
        failures_by_ip: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for event in events:
            # Check for failure indications across standardized fields
            is_failure = (
                event.get("event_type") == "failed_login"
                or event.get("auth_result") == "Failed"
                or event.get("status") == "FAILED"
            )

            if is_failure and "source_ip" in event and "timestamp" in event:
                failures_by_ip[str(event["source_ip"])].append(event)

        detections: List[Dict[str, Any]] = []

        # Step 2: Evaluate sliding window per source IP
        for source_ip, ip_events in failures_by_ip.items():
            # Ensure chronological order for sliding-window arithmetic
            ip_events.sort(key=lambda item: item["timestamp"])

            idx = 0
            num_events = len(ip_events)

            while idx < num_events:
                anchor_time: datetime = ip_events[idx]["timestamp"]
                window_end: datetime = anchor_time + self.time_window

                # Collect all attempts falling inside the current temporal window
                window_events = [
                    event
                    for event in ip_events[idx:]
                    if anchor_time <= event["timestamp"] <= window_end
                ]

                count = len(window_events)

                if count >= self.failure_threshold:
                    severity = self._determine_severity(count)
                    record = self._build_detection_record(source_ip, window_events, severity)
                    detections.append(record)

                    # Suppress overlapping alerts inside the same active burst window
                    idx += count
                else:
                    idx += 1

        return detections