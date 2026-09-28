from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict

# Coordinate the decoupled pipeline components
from src.alert_manager import AlertManager
from src.detector import SSHBruteForceDetector
from src.log_parser import parse_log_file

DEFAULT_CONFIG_PATH = Path("config/config.json")


def load_configuration(config_path: Path) -> Dict[str, Any]:
    """
    Loads runtime configuration from a JSON file if present.

    Args:
        config_path: Path to the target configuration JSON file.

    Returns:
        Dictionary of loaded configuration settings or an empty dict on fallback.
    """
    if not config_path.is_file():
        return {}

    try:
        with open(config_path, mode="r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except (json.JSONDecodeError, OSError) as err:
        print(f"[!] Warning: Could not read config file '{config_path}': {err}. Using defaults.", file=sys.stderr)

    return {}


def parse_arguments(config: Dict[str, Any]) -> argparse.Namespace:
    """
    Configures and parses command-line arguments, applying loaded config defaults.

    Args:
        config: Configuration dictionary loaded from JSON.

    Returns:
        argparse.Namespace containing runtime arguments.
    """
    parser = argparse.ArgumentParser(
        prog="ssh-security-monitor",
        description="Lightweight defensive analyzer for Linux SSH authentication logs.",
    )

    parser.add_argument(
        "--config",
        type=str,
        default=str(DEFAULT_CONFIG_PATH),
        help="Path to configuration JSON file (default: config/config.json)",
    )
    parser.add_argument(
        "--log",
        type=str,
        default=config.get("log_file_path", "/var/log/auth.log"),
        help="Path to the SSH authentication log file (default from config or /var/log/auth.log)",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=config.get("time_window_minutes", 5),
        help="Sliding evaluation window in minutes (default from config or 5)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=config.get("failure_threshold", 5),
        help="Minimum failed attempts within the window to trigger an alert (default from config or 5)",
    )
    parser.add_argument(
        "--high-threshold",
        type=int,
        default=config.get("high_threshold", 15),
        help="Minimum failed attempts within the window to trigger HIGH severity (default from config or 15)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Optional destination path to save the RFC 8259 JSON alert report",
    )

    return parser.parse_args()


def main() -> int:
    """
    Coordinates the log parsing, threat detection, and alerting workflows.

    Returns:
        Exit status code (0 on success, 1 on input error, 2 on file I/O error).
    """
    # Pre-parse specifically for --config flag if user passed a custom config path
    temp_parser = argparse.ArgumentParser(add_help=False)
    temp_parser.add_argument("--config", type=str, default=str(DEFAULT_CONFIG_PATH))
    temp_args, _ = temp_parser.parse_known_args()

    config_data = load_configuration(Path(temp_args.config))
    args = parse_arguments(config_data)

    log_path = Path(args.log)
    alert_mgr = AlertManager()

    # Step 1: Validate target log file accessibility
    if not log_path.exists():
        print(f"[!] Error: Target log file '{args.log}' does not exist.", file=sys.stderr)
        return 1

    if not log_path.is_file():
        print(f"[!] Error: Target path '{args.log}' is not a regular file.", file=sys.stderr)
        return 1

    print(alert_mgr.format_console_info(f"Target log: {log_path.resolve()}"))
    print(alert_mgr.format_console_info(
        f"Window: {args.window} min | Threshold: {args.threshold} (Medium), {args.high_threshold} (High)"
    ))

    # Step 2: Ingest and parse log events line-by-line
    print(alert_mgr.format_console_info("Parsing log records..."))
    try:
        parsed_events = list(parse_log_file(log_path))
    except PermissionError:
        print(f"[!] Error: Permission denied reading '{args.log}'. Run with appropriate permissions.", file=sys.stderr)
        return 2
    except OSError as err:
        print(f"[!] Error: Failed reading '{args.log}': {err}", file=sys.stderr)
        return 2

    print(alert_mgr.format_console_info(f"Successfully extracted {len(parsed_events)} SSH authentication event(s)."))

    # Step 3: Correlate failed attempts using the sliding temporal window
    detector = SSHBruteForceDetector(
        time_window_minutes=args.window,
        failure_threshold=args.threshold,
        high_threshold=args.high_threshold,
    )

    detections = detector.detect(parsed_events)

    # Step 4: Render results and output alerts
    if not detections:
        print(alert_mgr.format_console_info("No suspicious brute-force activity identified across evaluation windows."))
    else:
        print(alert_mgr.format_console_info(f"Identified {len(detections)} suspicious activity pattern(s):"))
        for incident in detections:
            print(alert_mgr.format_console_alert(incident))

    # Step 5: Export JSON report if requested
    if args.output:
        output_path = Path(args.output)
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            report_content = alert_mgr.export_json_report(detections, source_log=str(log_path.resolve()))
            output_path.write_text(report_content, encoding="utf-8")
            print(alert_mgr.format_console_info(f"JSON incident report exported to: {output_path.resolve()}"))
        except OSError as err:
            print(f"[!] Error: Failed writing report to '{args.output}': {err}", file=sys.stderr)
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())