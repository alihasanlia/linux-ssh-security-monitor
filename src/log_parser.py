from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, Optional

# Regular expression matching modern Ubuntu / OpenSSH session authentication logs.
# Handles both IPv4 and IPv6 source addresses, process identifiers, and user flags.
SSH_AUTH_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>sshd(?:-session)?)\[(?P<pid>\d+)\]:\s+"
    r"(?P<auth_result>Accepted|Failed)\s+"
    r"(?P<auth_method>\S+)\s+for\s+"
    r"(?:(?P<invalid_marker>invalid\s+user)\s+)?"
    r"(?P<username>\S+)\s+from\s+"
    r"(?P<source_ip>\S+)\s+port\s+"
    r"(?P<source_port>\d+)\s+"
    r"(?P<ssh_proto>\S+)"
)


def parse_timestamp(ts_string: str) -> Optional[datetime]:
    """
    Safely converts an ISO 8601 / RFC 3339 timestamp string to a datetime object.

    Args:
        ts_string: The raw timestamp string from the log.

    Returns:
        datetime object if parsing succeeds, None otherwise.
    """
    try:
        return datetime.fromisoformat(ts_string)
    except (ValueError, TypeError):
        return None


def determine_user_status(auth_result: str, invalid_marker: Optional[str]) -> str:
    """
    Determines user validity state according to defensive security assumptions.

    Rules:
    - If OpenSSH explicitly states 'invalid user', the user status is 'invalid'.
    - If the login succeeded ('Accepted'), the user status is 'valid'.
    - If the login failed but 'invalid user' was not emitted, status is 'unknown'
      (absence of evidence is not evidence of validity).

    Args:
        auth_result: Either 'Accepted' or 'Failed'.
        invalid_marker: String match if 'invalid user' pattern appeared, else None.

    Returns:
        One of 'valid', 'invalid', or 'unknown'.
    """
    if invalid_marker:
        return "invalid"
    if auth_result == "Accepted":
        return "valid"
    return "unknown"


def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parses a single log line into a normalized security event dictionary.

    Args:
        line: Raw log line string.

    Returns:
        A dictionary containing extracted audit primitives, or None if the
        line does not match an OpenSSH authentication event.
    """
    line = line.strip()
    if not line:
        return None

    # Pre-filter for performance: quickly skip non-relevant entries
    if "sshd" not in line:
        return None
    if "Accepted" not in line and "Failed" not in line:
        return None

    match = SSH_AUTH_PATTERN.match(line)
    if not match:
        return None

    extracted = match.groupdict()

    parsed_dt = parse_timestamp(extracted["timestamp"])
    if parsed_dt is None:
        return None

    auth_result = extracted["auth_result"]
    event_type = "successful_login" if auth_result == "Accepted" else "failed_login"
    user_status = determine_user_status(auth_result, extracted.get("invalid_marker"))

    try:
        pid = int(extracted["pid"])
        source_port = int(extracted["source_port"])
    except (ValueError, TypeError):
        return None

    return {
        "timestamp": parsed_dt,
        "raw_timestamp": extracted["timestamp"],
        "hostname": extracted["hostname"],
        "process": extracted["process"],
        "pid": pid,
        "auth_result": auth_result,
        "event_type": event_type,
        "auth_method": extracted["auth_method"],
        "username": extracted["username"],
        "user_status": user_status,
        "source_ip": extracted["source_ip"],
        "source_port": source_port,
        "ssh_protocol": extracted["ssh_proto"],
    }


def parse_log_file(file_path: str | Path) -> Generator[Dict[str, Any], None, None]:
    """
    Streams and parses a log file line-by-line, yielding structured events.

    Args:
        file_path: Path to the target log file.

    Yields:
        Parsed event dictionaries.
    """
    path = Path(file_path)
    if not path.is_file():
        return

    # errors='replace' prevents UTF-8 decoding crashes from malformed characters
    with open(path, mode="r", encoding="utf-8", errors="replace") as file_handle:
        for line in file_handle:
            event = parse_log_line(line)
            if event is not None:
                yield event