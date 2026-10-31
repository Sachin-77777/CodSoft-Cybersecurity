#!/usr/bin/env python3
"""
Network Intrusion Detection System (log monitor)
================================================
CodSoft Cyber Security Internship - Task 3

A lightweight, dependency-free NIDS that watches one or more log files (or a
log stream on stdin) and raises real-time alerts when a detection rule matches.

Detections
----------
    NIDS-001  Brute-force login attempt    - >= N failed logons from one source
                                             inside a sliding time window
    NIDS-002  Directory traversal attempt  - ``../../etc/passwd`` and friends
    NIDS-003  SQL injection attempt        - ``UNION SELECT``, ``' OR '1'='1``, ...

Alerts are printed to the terminal as they happen, tagged ``WARNING`` or
``HIGH``. A summary is printed when the run finishes.

Quick start
-----------
    # Scan the bundled sample logs once and exit
    python nids.py -f sample_logs/apache_access.log -f sample_logs/auth.log

    # Replay a log at reading pace so the alerts appear over time
    python nids.py -f sample_logs/auth.log --delay 0.4

    # Follow a live log (tail -f style) until Ctrl+C
    python nids.py -f sample_logs/live_access.log --follow

    # Read a stream from stdin
    python nids.py -f -  <  /var/log/apache2/access.log

Only the Python standard library is required.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Iterable, Optional, TextIO

from log_parser import parse_line
from rules import HIGH, WARNING, Alert, build_rules

STDIN_MARKER = "-"


# --------------------------------------------------------------------------- #
# Terminal colour
# --------------------------------------------------------------------------- #
class Colour:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"


SEVERITY_COLOUR = {
    HIGH: Colour.RED + Colour.BOLD,
    WARNING: Colour.YELLOW + Colour.BOLD,
}


def _enable_windows_ansi() -> bool:
    """Turn on ANSI escape processing in the Windows console, if possible."""
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def supports_colour(force_off: bool = False) -> bool:
    if force_off or os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if not sys.stdout.isatty():
        return False
    return _enable_windows_ansi()


# --------------------------------------------------------------------------- #
# Alert rendering
# --------------------------------------------------------------------------- #
def format_alert(alert: Alert, colour: bool = True) -> str:
    """Render one alert as a small, readable block."""
    indent = " " * 10

    head = f"[{alert.severity}]"
    if colour:
        head = f"{SEVERITY_COLOUR.get(alert.severity, '')}{head}{Colour.RESET}"

    # Pad manually: colour codes must not count towards the visible width.
    pad = " " * max(1, 10 - (len(alert.severity) + 2))
    stamp = alert.event.timestamp.strftime("%Y-%m-%d %H:%M:%S")

    lines = [f"{head}{pad}{stamp}  {alert.rule_id}  {alert.rule_name}"]
    lines.append(f"{indent}detail   : {alert.summary}")
    lines.append(f"{indent}source   : {alert.event.src_ip}")
    if alert.evidence:
        lines.append(f"{indent}evidence : {alert.evidence}")
    lines.append(f"{indent}where    : {alert.event.location}")
    lines.append(f"{indent}raw      : {alert.event.raw}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Monitor
# --------------------------------------------------------------------------- #
class Monitor:
    """Feeds log lines through the rule set and prints alerts."""

    def __init__(
        self,
        rules: list,
        fmt: str = "auto",
        colour: bool = True,
        quiet: bool = False,
        stream: TextIO = sys.stdout,
    ) -> None:
        self.rules = rules
        self.fmt = fmt
        self.colour = colour
        self.quiet = quiet
        self.stream = stream

        self.alerts: list[Alert] = []
        self.parsed = 0
        self.skipped = 0

    def _write(self, text: str) -> None:
        print(text, file=self.stream, flush=True)

    def feed(self, raw: str, source: str, line_no: int) -> Optional[Alert]:
        """Parse and inspect a single line. Returns the last alert raised."""
        event = parse_line(raw, source, line_no, self.fmt)
        if event is None:
            self.skipped += 1
            return None

        self.parsed += 1
        last: Optional[Alert] = None
        for rule in self.rules:
            for alert in rule.inspect(event):
                self.alerts.append(alert)
                last = alert
                self._write(format_alert(alert, self.colour))
        return last

    # -- input modes ------------------------------------------------------ #
    def process(self, sources: list[str], delay: float = 0.0) -> None:
        """Read each source from start to end (``--once`` / ``--delay``)."""
        for source in sources:
            if source == STDIN_MARKER:
                for line_no, line in enumerate(sys.stdin, start=1):
                    self.feed(line, "<stdin>", line_no)
                    if delay:
                        time.sleep(delay)
                continue

            with open(source, "r", encoding="utf-8", errors="replace") as handle:
                for line_no, line in enumerate(handle, start=1):
                    self.feed(line, source, line_no)
                    if delay:
                        time.sleep(delay)

    def follow(self, sources: list[str], interval: float = 0.5) -> None:
        """Tail each source, alerting on lines as they are appended.

        Files are read in binary so ``tell()`` is an exact byte offset, which
        makes log rotation (the file shrinking) detectable.
        """
        handles = {}
        line_numbers = {}
        try:
            for source in sources:
                handle = open(source, "rb")
                handles[source] = handle
                line_numbers[source] = 0

            while True:
                idle = True
                for source, handle in handles.items():
                    while True:
                        position = handle.tell()
                        raw = handle.readline()
                        if not raw:
                            break
                        if not raw.endswith(b"\n"):
                            # Partial line - a writer is mid-flush. Rewind and
                            # wait for the rest rather than parsing half a line.
                            handle.seek(position)
                            break
                        idle = False
                        line_numbers[source] += 1
                        self.feed(
                            raw.decode("utf-8", errors="replace"),
                            source,
                            line_numbers[source],
                        )

                    # Log rotation: the file is now smaller than our offset.
                    try:
                        if os.path.getsize(source) < handle.tell():
                            handle.seek(0)
                            line_numbers[source] = 0
                            self._write(f"[nids] {source} was truncated - re-reading from the start")
                    except OSError:
                        pass

                if idle:
                    time.sleep(interval)
        except KeyboardInterrupt:
            self._write("\n[nids] monitoring stopped by user")
        finally:
            for handle in handles.values():
                handle.close()

    # -- reporting -------------------------------------------------------- #
    def print_summary(self) -> None:
        by_severity = Counter(alert.severity for alert in self.alerts)
        by_rule = Counter(f"{a.rule_id} {a.rule_name}" for a in self.alerts)
        offenders = Counter(
            a.event.src_ip for a in self.alerts if a.event.src_ip not in ("", "-")
        )

        lines = [
            "-" * 74,
            "Summary",
            f"  lines parsed      : {self.parsed}",
            f"  lines ignored     : {self.skipped}",
            f"  alerts raised     : {len(self.alerts)}"
            f"  (HIGH: {by_severity.get(HIGH, 0)}, WARNING: {by_severity.get(WARNING, 0)})",
        ]

        if by_rule:
            lines.append("  alerts by rule    :")
            for label, count in by_rule.most_common():
                lines.append(f"      {label:<40} {count}")

        if offenders:
            lines.append("  top source IPs    :")
            for ip, count in offenders.most_common(5):
                lines.append(f"      {ip:<40} {count}")

        lines.append("-" * 74)
        self._write("\n".join(lines))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def print_banner(rules: Iterable, sources: list[str], follow: bool) -> None:
    print("Network Intrusion Detection System - log monitor")
    print("Rules loaded:")
    for rule in rules:
        print(f"    {rule.describe()}")
    mode = "following (tail -f)" if follow else "single pass"
    print(f"Monitoring ({mode}): " + ", ".join(sources))
    print("-" * 74)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nids.py",
        description="Lightweight log-monitoring intrusion detection system.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python nids.py -f sample_logs/apache_access.log -f sample_logs/auth.log\n"
            "  python nids.py -f sample_logs/auth.log --delay 0.4\n"
            "  python nids.py -f sample_logs/live_access.log --follow\n"
            "  python nids.py -f - < access.log\n"
        ),
    )
    parser.add_argument(
        "-f", "--file", dest="sources", action="append", metavar="PATH",
        help=f"log file to monitor (repeatable). Use '{STDIN_MARKER}' for stdin.",
    )
    parser.add_argument(
        "--follow", action="store_true",
        help="keep watching the files and alert on new lines (tail -f style)",
    )
    parser.add_argument(
        "--delay", type=float, default=0.0, metavar="SECONDS",
        help="pause between lines when reading a file, to replay it at reading pace",
    )
    parser.add_argument(
        "--interval", type=float, default=0.5, metavar="SECONDS",
        help="poll interval used by --follow (default: 0.5)",
    )
    parser.add_argument(
        "--format", choices=("auto", "apache", "auth"), default="auto",
        help="log format; 'auto' detects per line (default: auto)",
    )
    parser.add_argument(
        "--brute-warn", type=int, default=3, metavar="N",
        help="failed logons within the window that raise a WARNING (default: 3)",
    )
    parser.add_argument(
        "--brute-high", type=int, default=5, metavar="N",
        help="failed logons within the window that raise a HIGH alert (default: 5)",
    )
    parser.add_argument(
        "--brute-window", type=int, default=60, metavar="SECONDS",
        help="sliding window for the brute-force rule (default: 60)",
    )
    parser.add_argument("--no-colour", "--no-color", dest="no_colour",
                        action="store_true", help="disable coloured output")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="print alerts only - no banner, no summary")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    sources = args.sources or []
    if not sources:
        print("Error: no log source given. Use -f PATH (or -f - for stdin).", file=sys.stderr)
        return 2

    if args.follow and STDIN_MARKER in sources:
        print("Error: --follow cannot be used with stdin.", file=sys.stderr)
        return 2

    missing = [s for s in sources if s != STDIN_MARKER and not Path(s).is_file()]
    if missing:
        for path in missing:
            print(f"Error: log file not found: {path}", file=sys.stderr)
        return 1

    try:
        rules = build_rules(
            warn_threshold=args.brute_warn,
            high_threshold=args.brute_high,
            window_seconds=args.brute_window,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    monitor = Monitor(
        rules=rules,
        fmt=args.format,
        colour=supports_colour(args.no_colour),
        quiet=args.quiet,
    )

    if not args.quiet:
        print_banner(rules, sources, args.follow)

    if args.follow:
        monitor.follow(sources, interval=args.interval)
    else:
        try:
            monitor.process(sources, delay=args.delay)
        except KeyboardInterrupt:
            print("\n[nids] interrupted by user", file=sys.stderr)

    if not args.quiet:
        monitor.print_summary()

    return 0


if __name__ == "__main__":
    sys.exit(main())
