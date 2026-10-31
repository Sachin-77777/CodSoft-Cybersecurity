"""
Detection rules for the NIDS
============================
CodSoft Cyber Security Internship - Task 3 (Network Intrusion Detection System)

Three detections are implemented, matching the required feature set:

    NIDS-001  Brute-force login attempt      - threshold based
    NIDS-002  Directory traversal attempt    - signature based
    NIDS-003  SQL injection attempt          - signature based

Every rule exposes :meth:`Rule.inspect`, which takes one :class:`LogEvent` and
returns a list of :class:`Alert` objects (usually empty).

Severity
--------
Two levels are used, matching the required "Warning / High" alerting:

* ``HIGH``    - a real attack signature, or a signature the server *served*
                (HTTP status < 400), or a brute-force threshold being exceeded.
* ``WARNING`` - a suspicious attempt that was rejected by the server (HTTP
                status >= 400), or repeated failures still below the
                brute-force threshold.

That distinction matters: a traversal payload answered with ``403`` is a probe
worth watching, whereas the same payload answered with ``200`` means a file was
actually read.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import unquote

from log_parser import AUTH, HTTP, LogEvent

# Severity levels
WARNING = "WARNING"
HIGH = "HIGH"


@dataclass
class Alert:
    """A single detection produced by a rule."""

    severity: str        # WARNING or HIGH
    rule_id: str         # e.g. NIDS-003
    rule_name: str       # short human readable name
    summary: str         # one-line explanation of what was detected
    event: LogEvent      # the log event that triggered it
    evidence: str = ""   # matched signature / attempt count


def _decode(value: str) -> str:
    """URL-decode a value, twice, so double-encoded payloads are also caught."""
    decoded = value
    for _ in range(2):
        updated = unquote(decoded)
        if updated == decoded:
            break
        decoded = updated
    return decoded


def _severity_from_outcome(event: LogEvent, default: str = HIGH) -> str:
    """Rate a signature by whether the server actually served the request."""
    if event.kind == HTTP and event.status:
        return HIGH if event.status < 400 else WARNING
    return default


class Rule:
    """Base class for every detection rule."""

    rule_id = "NIDS-000"
    name = "rule"

    def inspect(self, event: LogEvent) -> list[Alert]:  # pragma: no cover
        raise NotImplementedError

    def describe(self) -> str:
        """One-line description used in the startup banner."""
        return f"{self.rule_id}  {self.name} (signature)"


# --------------------------------------------------------------------------- #
# NIDS-001 - Brute-force login attempt (threshold based)
# --------------------------------------------------------------------------- #
class BruteForceRule(Rule):
    """Flags a source address that produces too many failed logons too quickly.

    State is kept per source IP as a sliding window of failure timestamps, so a
    slow trickle of failures across many addresses is not flagged while a burst
    from one address is.

    Escalation avoids alert spam: an address is reported once at ``WARNING``
    when it reaches ``warn_threshold`` and once again at ``HIGH`` when it
    reaches ``high_threshold``. The level resets once the window drains below
    the warning threshold, so a later burst raises fresh alerts.
    """

    rule_id = "NIDS-001"
    name = "Brute-force login attempt"

    # Any of these substrings in the event name marks the event as a failure.
    FAILURE_MARKERS = ("FAIL", "INVALID", "DENIED", "REJECT", "LOCKED")

    def __init__(
        self,
        warn_threshold: int = 3,
        high_threshold: int = 5,
        window_seconds: int = 60,
    ) -> None:
        if warn_threshold < 1:
            raise ValueError("warn_threshold must be at least 1")
        if high_threshold < warn_threshold:
            raise ValueError("high_threshold must be >= warn_threshold")
        if window_seconds < 1:
            raise ValueError("window_seconds must be at least 1")

        self.warn_threshold = warn_threshold
        self.high_threshold = high_threshold
        self.window = timedelta(seconds=window_seconds)
        self.window_seconds = window_seconds

        self._attempts: dict[str, deque[datetime]] = defaultdict(deque)
        self._level: dict[str, str] = {}

    def describe(self) -> str:
        return (
            f"{self.rule_id}  {self.name} (threshold: >={self.warn_threshold} "
            f"failures in {self.window_seconds}s = WARNING, "
            f">={self.high_threshold} = HIGH)"
        )

    @classmethod
    def _is_failure(cls, event: LogEvent) -> bool:
        return any(marker in event.event for marker in cls.FAILURE_MARKERS)

    def inspect(self, event: LogEvent) -> list[Alert]:
        if event.kind != AUTH or not self._is_failure(event):
            return []
        ip = event.src_ip
        if not ip or ip == "-":
            return []

        # Slide the window forward and count recent failures from this address.
        attempts = self._attempts[ip]
        attempts.append(event.timestamp)
        cutoff = event.timestamp - self.window
        while attempts and attempts[0] < cutoff:
            attempts.popleft()

        count = len(attempts)

        # Window drained - forget the previous level so a new burst alerts again.
        if count < self.warn_threshold:
            self._level.pop(ip, None)
            return []

        if count >= self.high_threshold and self._level.get(ip) != HIGH:
            self._level[ip] = HIGH
            return [
                Alert(
                    severity=HIGH,
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    summary=(
                        f"{count} failed logons from {ip} within "
                        f"{self.window_seconds}s - brute-force suspected"
                    ),
                    event=event,
                    evidence=f"{count} failures in {self.window_seconds}s window",
                )
            ]

        if self._level.get(ip) is None:
            self._level[ip] = WARNING
            return [
                Alert(
                    severity=WARNING,
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    summary=(
                        f"{count} failed logons from {ip} within "
                        f"{self.window_seconds}s - watching this source"
                    ),
                    event=event,
                    evidence=f"{count} failures in {self.window_seconds}s window",
                )
            ]

        return []


# --------------------------------------------------------------------------- #
# NIDS-002 - Directory traversal attempt (signature based)
# --------------------------------------------------------------------------- #
class DirectoryTraversalRule(Rule):
    """Detects path-traversal payloads such as ``../../etc/passwd``.

    The request is URL-decoded (twice) before matching so that encoded forms
    like ``..%2f..%2fetc%2fpasswd`` are caught too.
    """

    rule_id = "NIDS-002"
    name = "Directory traversal attempt"

    PATTERNS = [
        (re.compile(r"\.\.[/\\]"), "parent directory sequence"),
        (re.compile(r"%2e%2e[/\\%]", re.IGNORECASE), "encoded parent sequence"),
        (re.compile(r"(?:^|[/\\])etc/(?:passwd|shadow|hosts)\b", re.IGNORECASE),
         "unix sensitive file"),
        (re.compile(r"(?:^|[/\\])proc/self/", re.IGNORECASE), "proc filesystem access"),
        (re.compile(r"\b(?:boot|win)\.ini\b", re.IGNORECASE), "windows sensitive file"),
        (re.compile(r"\.\.;", re.IGNORECASE), "IIS-style traversal"),
    ]

    def inspect(self, event: LogEvent) -> list[Alert]:
        target = _decode(event.haystack)
        for pattern, label in self.PATTERNS:
            if pattern.search(target):
                return [
                    Alert(
                        severity=_severity_from_outcome(event),
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        summary=f"directory traversal payload in request from {event.src_ip}",
                        event=event,
                        evidence=f'matched "{label}"',
                    )
                ]
        return []


# --------------------------------------------------------------------------- #
# NIDS-003 - SQL injection attempt (signature based)
# --------------------------------------------------------------------------- #
class SqlInjectionRule(Rule):
    """Detects common SQL injection payloads.

    Covers the UNION-based and boolean-tautology families named in the task
    brief plus a few high-signal extras (time-based, schema enumeration and
    command execution).

    Only the first matching signature is reported per event, to keep one alert
    per request instead of one per pattern.
    """

    rule_id = "NIDS-003"
    name = "SQL injection attempt"

    PATTERNS = [
        (re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE), "UNION SELECT"),
        (re.compile(r"'\s*(?:or|and)\s*'?\w+'?\s*=\s*'?\w+", re.IGNORECASE),
         "boolean tautology (quoted)"),
        (re.compile(r"\b(?:or|and)\s+\d+\s*=\s*\d+", re.IGNORECASE),
         "boolean tautology (numeric)"),
        (re.compile(r";\s*(?:--|#)"), "stacked query terminator"),
        (re.compile(r"\b(?:sleep|pg_sleep|benchmark|waitfor)\s*\(", re.IGNORECASE),
         "time-based injection"),
        (re.compile(r"\binformation_schema\b", re.IGNORECASE), "schema enumeration"),
        (re.compile(r"\b(?:xp_cmdshell|load_file)\b", re.IGNORECASE),
         "command execution / file read"),
    ]

    def inspect(self, event: LogEvent) -> list[Alert]:
        target = _decode(event.haystack)
        for pattern, label in self.PATTERNS:
            if pattern.search(target):
                return [
                    Alert(
                        severity=_severity_from_outcome(event),
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        summary=f"SQL injection payload in request from {event.src_ip}",
                        event=event,
                        evidence=f'matched "{label}"',
                    )
                ]
        return []


# --------------------------------------------------------------------------- #
def build_rules(
    warn_threshold: int = 3,
    high_threshold: int = 5,
    window_seconds: int = 60,
) -> list[Rule]:
    """Instantiate the default rule set.

    Rules are stateless apart from the brute-force window, so each call returns
    a fresh, independent set.
    """
    return [
        BruteForceRule(warn_threshold, high_threshold, window_seconds),
        DirectoryTraversalRule(),
        SqlInjectionRule(),
    ]
