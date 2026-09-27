from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable , Optional


class AlertManager:
    """
    Transforms detection outputs from detector.py into actionable console summaries
    and structured JSON reports.
    """

    def __init__(self, tool_name: str = "Linux SSH Security Monitor") -> None:
        """
        Initializes the AlertManager.

        Args:
            tool_name: The reporting sensor name included in structured payloads.
        """
        self.tool_name = tool_name

    def _generate_recommendation(self, severity: str, source_ip: str) -> str:
        """
        Produces standardized SOC triage recommendations based on severity tier.

        Args:
            severity: Assigned alert level ('HIGH' or 'MEDIUM').
            source_ip: Evaluated source IP address.

        Returns:
            Actionable triage advice string.
        """
        if severity == "HIGH":
            return (
                f"Urgent: Consider temporary host firewall block (iptables/ufw) for {source_ip}. "
                "Audit target user accounts for unexpected successful authentications."
            )
        return (
            f"Monitor: Review perimeter logs for {source_ip}. "
            "Validate whether source address belongs to authorized personnel."
        )

    def enrich_detection(self, detection: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalizes and enriches a single detection record for structured reporting.

        Args:
            detection: Raw detection dictionary produced by detector.py.

        Returns:
            JSON-serializable dictionary enriched with SOC metadata.
        """
        severity = detection.get("severity", "MEDIUM")
        source_ip = str(detection.get("source_ip", "UNKNOWN"))

        # Preserve ISO format strings; cast datetime objects if passed directly
        first_seen = detection.get("first_attempt_timestamp")
        if isinstance(first_seen, datetime):
            first_seen = first_seen.isoformat()

        last_seen = detection.get("last_attempt_timestamp")
        if isinstance(last_seen, datetime):
            last_seen = last_seen.isoformat()

        return {
            "sensor": self.tool_name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "severity": severity,
            "attack_type": "SSH Brute-Force",
            "detection_type": detection.get("detection_type", "ssh_brute_force_suspected"),
            "source_ip": source_ip,
            "failed_attempts": int(detection.get("failed_attempts", 0)),
            "time_window_minutes": int(detection.get("time_window_minutes", 0)),
            "first_attempt_timestamp": first_seen,
            "last_attempt_timestamp": last_seen,
            "affected_usernames": list(detection.get("affected_usernames", [])),
            "description": detection.get("description", ""),
            "recommendation": self._generate_recommendation(severity, source_ip),
        }

    def format_console_alert(self, detection: Dict[str, Any]) -> str:
        """
        Renders a high-visibility, human-readable terminal alert banner.

        Args:
            detection: Raw or enriched detection dictionary.

        Returns:
            Formatted multiline string.
        """
        alert = self.enrich_detection(detection)
        border = "=" * 60
        sub_border = "-" * 60

        usernames_str = ", ".join(alert["affected_usernames"]) or "None identified"

        return (
            f"\n{border}\n"
            f"[!] SECURITY INCIDENT ALERT: {alert['severity']}\n"
            f"{sub_border}\n"
            f"Source IP        : {alert['source_ip']}\n"
            f"Failed Attempts  : {alert['failed_attempts']}\n"
            f"Time Window      : {alert['time_window_minutes']} minute(s)\n"
            f"First Seen       : {alert['first_attempt_timestamp']}\n"
            f"Last Seen        : {alert['last_attempt_timestamp']}\n"
            f"Target Users     : {usernames_str}\n"
            f"Description      : {alert['description']}\n"
            f"Recommendation   : {alert['recommendation']}\n"
            f"{border}\n"
        )

    def format_console_info(self, message: str) -> str:
        """
        Renders an informational status line without alert markers.

        Args:
            message: Informational message text.

        Returns:
            Prefixed log string.
        """
        return f"[*] [INFO] {message}"

    def build_report_data(
        self,
        detections: Iterable[Dict[str, Any]],
        source_log: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Packages an iterable of detections into a top-level report structure.

        Args:
            detections: Iterable of detection records from detector.py.
            source_log: Optional path string of the analyzed log file.

        Returns:
            JSON-serializable report dictionary containing incident collections and metadata.
        """
        enriched_alerts = [self.enrich_detection(det) for det in detections]

        high_count = sum(1 for a in enriched_alerts if a["severity"] == "HIGH")
        medium_count = sum(1 for a in enriched_alerts if a["severity"] == "MEDIUM")

        return {
            "report_metadata": {
                "generator": self.tool_name,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "source_file": source_log or "stream",
                "total_alerts": len(enriched_alerts),
                "severity_summary": {
                    "HIGH": high_count,
                    "MEDIUM": medium_count,
                },
            },
            "alerts": enriched_alerts,
        }

    def export_json_report(
        self,
        detections: Iterable[Dict[str, Any]],
        source_log: Optional[str] = None,
        indent: int = 2,
    ) -> str:
        """
        Serializes detection report data into an RFC 8259-compliant JSON string.

        Args:
            detections: Iterable of detection records from detector.py.
            source_log: Optional log source identifier.
            indent: JSON indentation spacing (default: 2).

        Returns:
            Formatted JSON string.
        """
        report_data = self.build_report_data(detections, source_log=source_log)
        return json.dumps(report_data, indent=indent, ensure_ascii=False)