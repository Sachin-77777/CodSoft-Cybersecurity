#!/usr/bin/env python3
"""
Live traffic simulator
======================
CodSoft Cyber Security Internship - Task 3 (Network Intrusion Detection System)

Appends a scripted sequence of log lines to a pair of log files at a steady
pace, so the NIDS can be seen raising alerts on a *growing* log in real time.

Use it in two terminals:

    # terminal 1 - start the monitor first
    python nids.py -f sample_logs/live_access.log -f sample_logs/live_auth.log --follow

    # terminal 2 - then generate the traffic
    python simulate_attack.py

The scripted sequence contains normal browsing, then a brute-force burst, then
SQL injection and directory traversal probes, so every rule fires.

Options:
    --interval SECONDS   delay between lines (default: 0.8)
    --access PATH        access log to append to
    --auth PATH          auth log to append to
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# (target, template) pairs. {ts} is an Apache timestamp, {iso} an ISO-8601 one.
SCRIPT: list[tuple[str, str]] = [
    # --- normal traffic ------------------------------------------------- #
    ("access", '198.51.100.23 - - [{ts}] "GET /index.html HTTP/1.1" 200 1043 "-" "Mozilla/5.0"'),
    ("auth", "{iso} LOGIN_SUCCESS user=alice src=192.168.1.20"),
    ("access", '198.51.100.23 - - [{ts}] "GET /products?category=shoes HTTP/1.1" 200 8821 "-" "Mozilla/5.0"'),

    # --- NIDS-001: brute-force burst, six failures from one address ----- #
    ("auth", "{iso} LOGIN_FAILED user=admin src=203.0.113.201 reason=bad_password"),
    ("auth", "{iso} LOGIN_FAILED user=admin src=203.0.113.201 reason=bad_password"),
    ("auth", "{iso} LOGIN_FAILED user=root src=203.0.113.201 reason=bad_password"),
    ("auth", "{iso} LOGIN_FAILED user=admin src=203.0.113.201 reason=bad_password"),
    ("auth", "{iso} LOGIN_FAILED user=root src=203.0.113.201 reason=bad_password"),
    ("auth", "{iso} LOGIN_FAILED user=oracle src=203.0.113.201 reason=bad_password"),

    # --- NIDS-003: SQL injection --------------------------------------- #
    ("access", '203.0.113.45 - - [{ts}] "GET /index.php?id=1 UNION SELECT username,password FROM users HTTP/1.1" 200 512 "-" "sqlmap/1.7"'),
    ("access", '203.0.113.45 - - [{ts}] "GET /login?user=admin\' OR \'1\'=\'1 HTTP/1.1" 200 3312 "-" "sqlmap/1.7"'),

    # --- NIDS-002: directory traversal ---------------------------------- #
    ("access", '203.0.113.66 - - [{ts}] "GET /download?file=../../../../etc/passwd HTTP/1.1" 400 226 "-" "curl/8.4.0"'),
    ("access", '203.0.113.66 - - [{ts}] "GET /download?file=..%2f..%2f..%2fetc%2fpasswd HTTP/1.1" 200 4096 "-" "curl/8.4.0"'),

    # --- back to normal -------------------------------------------------- #
    ("access", '198.51.100.23 - - [{ts}] "GET /about HTTP/1.1" 200 2210 "-" "Mozilla/5.0"'),
    ("auth", "{iso} LOGIN_SUCCESS user=alice src=192.168.1.20"),
]


def render(template: str, moment: datetime) -> str:
    """Fill in the timestamp placeholders for one line."""
    return template.format(
        ts=moment.strftime("%d/%b/%Y:%H:%M:%S +0000"),
        iso=moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Append simulated traffic to the demo logs.")
    parser.add_argument("--interval", type=float, default=0.8, metavar="SECONDS",
                        help="delay between lines (default: 0.8)")
    parser.add_argument("--access", default="sample_logs/live_access.log",
                        help="access log to append to")
    parser.add_argument("--auth", default="sample_logs/live_auth.log",
                        help="auth log to append to")
    args = parser.parse_args(argv)

    targets = {"access": Path(args.access), "auth": Path(args.auth)}
    for path in targets.values():
        path.parent.mkdir(parents=True, exist_ok=True)

    # Start from a clean slate so repeated runs are identical.
    for path in targets.values():
        path.write_text("", encoding="utf-8")

    print("Simulating traffic. Start the monitor with --follow to watch it live.")
    print(f"  access log: {targets['access']}")
    print(f"  auth log  : {targets['auth']}")
    print("-" * 74)

    start = datetime.now(timezone.utc)
    for index, (kind, template) in enumerate(SCRIPT):
        moment = start + timedelta(seconds=index)
        line = render(template, moment)
        path = targets[kind]
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        print(f"{path.name:<16} {line}")
        time.sleep(args.interval)

    print("-" * 74)
    print(f"Done - wrote {len(SCRIPT)} lines.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
