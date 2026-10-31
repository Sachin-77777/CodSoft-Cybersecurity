"""
Log parsing for the NIDS
========================
CodSoft Cyber Security Internship - Task 3 (Network Intrusion Detection System)

Turns a raw log line into a normalised :class:`LogEvent` that the detection
rules can inspect without caring which format it came from.

Two formats are understood:

* ``apache`` - the Apache / Nginx "combined" access log format::

      203.0.113.45 - - [31/Oct/2026:10:15:22 +0000] "GET /index.php?id=1 HTTP/1.1" 200 512 "-" "sqlmap/1.7"

* ``auth`` - a compact ``key=value`` authentication log::

      2026-10-31T10:15:22Z LOGIN_FAILED user=admin src=192.168.1.50 reason=bad_password

:func:`parse_line` auto-detects which one it is looking at, so a single
monitor can watch both kinds of log at the same time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

# Event kinds
HTTP = "http"
AUTH = "auth"

# 203.0.113.45 - - [31/Oct/2026:10:15:22 +0000] "GET /path HTTP/1.1" 200 512 ...
_APACHE_RE = re.compile(
    r'^(?P<src>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
)

# 2026-10-31T10:15:22Z LOGIN_FAILED user=admin src=192.168.1.50 reason=bad_password
_AUTH_RE = re.compile(
    r'^(?P<timestamp>\S+)\s+(?P<event>[A-Za-z_]+)(?:\s+(?P<fields>.*))?$'
)

# key=value pairs inside an auth log line
_FIELD_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')


@dataclass
class LogEvent:
    """A single normalised log entry."""

    raw: str                 # the original line, unchanged
    source: str              # file (or stream) the line came from
    line_no: int             # 1-based line number within that source
    timestamp: datetime      # event time (falls back to now if unparseable)
    kind: str                # HTTP or AUTH
    src_ip: str              # originating address, "-" when unknown
    haystack: str            # the portion the detection rules inspect

    # HTTP-only fields
    method: str = ""
    path: str = ""
    status: int = 0

    # AUTH-only fields
    event: str = ""
    user: str = ""
    reason: str = ""

    @property
    def location(self) -> str:
        """Human readable ``file:line`` reference for alerts."""
        return f"{self.source}:{self.line_no}"


def _parse_apache_time(text: str) -> Optional[datetime]:
    """Parse ``31/Oct/2026:10:15:22 +0000``."""
    try:
        return datetime.strptime(text.strip(), "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


def _parse_iso_time(text: str) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp, with or without a trailing ``Z``."""
    value = text.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _split_request(request: str) -> tuple[str, str]:
    """Split ``GET /index.php?id=1 HTTP/1.1`` into method and target."""
    parts = request.split()
    if not parts:
        return "", ""
    if len(parts) == 1:
        return "", parts[0]
    return parts[0], parts[1]


def parse_line(
    raw: str,
    source: str = "<stream>",
    line_no: int = 0,
    fmt: str = "auto",
) -> Optional[LogEvent]:
    """Parse one log line into a :class:`LogEvent`.

    ``fmt`` may be ``"auto"``, ``"apache"`` or ``"auth"``. Returns ``None`` when
    the line is blank, is a comment, or matches no known format.
    """
    line = raw.rstrip("\r\n")
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    if fmt in ("auto", "apache"):
        event = _parse_apache_line(line, source, line_no)
        if event is not None:
            return event

    if fmt in ("auto", "auth"):
        event = _parse_auth_line(line, source, line_no)
        if event is not None:
            return event

    return None


def _parse_apache_line(line: str, source: str, line_no: int) -> Optional[LogEvent]:
    match = _APACHE_RE.match(line)
    if not match:
        return None

    method, path = _split_request(match.group("request"))
    try:
        status = int(match.group("status"))
    except ValueError:
        status = 0

    timestamp = _parse_apache_time(match.group("timestamp")) or datetime.now()

    return LogEvent(
        raw=line,
        source=source,
        line_no=line_no,
        timestamp=timestamp,
        kind=HTTP,
        src_ip=match.group("src"),
        # Rules inspect the request line only - that is where traversal and
        # injection payloads surface.
        haystack=match.group("request"),
        method=method,
        path=path,
        status=status,
    )


def _parse_auth_line(line: str, source: str, line_no: int) -> Optional[LogEvent]:
    match = _AUTH_RE.match(line)
    if not match:
        return None

    fields = {}
    for key, value in _FIELD_RE.findall(match.group("fields") or ""):
        fields[key.lower()] = value.strip('"')

    timestamp = _parse_iso_time(match.group("timestamp")) or datetime.now()

    return LogEvent(
        raw=line,
        source=source,
        line_no=line_no,
        timestamp=timestamp,
        kind=AUTH,
        src_ip=fields.get("src") or fields.get("ip") or "-",
        # For authentication events the whole line is worth inspecting; a
        # malicious username can itself carry a payload.
        haystack=line,
        event=match.group("event").upper(),
        user=fields.get("user", ""),
        reason=fields.get("reason", ""),
    )
