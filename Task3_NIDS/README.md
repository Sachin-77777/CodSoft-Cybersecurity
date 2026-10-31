# Task 3 — Network Intrusion Detection System (NIDS)

A lightweight, **dependency-free** log-monitoring NIDS written in Python. It
watches one or more log files (or a log stream on `stdin`) and raises real-time
`WARNING` / `HIGH` alerts the moment a detection rule matches.

Ships with sample Apache access logs and a custom auth log, plus a traffic
simulator, so everything below is runnable immediately — no server, no network,
no root privileges required.

---

## Features (mapped to the task brief)

| # | Requirement | Where it lives |
|---|-------------|----------------|
| 1 | Monitor a simulated log file or system log stream (Apache access / custom auth) | `nids.py` — single-pass, `--follow` (tail -f) and `stdin` modes |
| 2 | Signature & threshold detection for brute-force, directory traversal, SQL injection | `rules.py` — `NIDS-001`, `NIDS-002`, `NIDS-003` |
| 3 | Real-time terminal alerts tagged `Warning` / `High` | `nids.py` — `format_alert()`, ANSI colour per severity |
| 4 | Sample log data so the script can be tested immediately | `sample_logs/apache_access.log`, `sample_logs/auth.log` |

Extras: log-format auto-detection, sliding-window brute-force threshold,
URL double-decoding (catches `%2e%2e` and double-encoded payloads), per-source
severity so an alert is only repeated on escalation, and a run summary.

---

## Files

```
Task3_NIDS/
├── nids.py               <- CLI entry point: monitoring modes, alert rendering, summary
├── rules.py              <- the three detection rules (NIDS-001/002/003)
├── log_parser.py         <- parses Apache combined + auth key=value lines
├── simulate_attack.py    <- appends scripted traffic so --follow can be demoed live
├── sample_logs/
│   ├── apache_access.log <- 14 lines: normal traffic + SQLi + traversal probes
│   └── auth.log          <- 12 lines: includes a 6-failure brute-force burst
├── requirements.txt      <- (stdlib only — nothing to install)
└── README.md
```

---

## Quick start

No installation needed — everything uses the Python standard library.

```bash
cd Task3_NIDS

# 1. Single pass over both sample logs — prints every alert, then a summary
python nids.py -f sample_logs/apache_access.log -f sample_logs/auth.log

# 2. Replay a log at reading pace, so alerts appear over time
python nids.py -f sample_logs/auth.log --delay 0.4

# 3. Live tail (tail -f style) — Ctrl+C to stop
python nids.py -f sample_logs/live_access.log --follow

# 4. Read a stream from stdin (e.g. a real access log)
python nids.py -f - < /var/log/apache2/access.log
```

### Live demo (two terminals)

```bash
# terminal 1 — start the monitor first
python nids.py -f sample_logs/live_access.log -f sample_logs/live_auth.log --follow

# terminal 2 — then generate the simulated attack traffic
python simulate_attack.py
```

Alerts stream into terminal 1 as the simulator appends lines to the logs.

---

## Sample output

Running `python nids.py -f sample_logs/apache_access.log -f sample_logs/auth.log --no-colour`:

```
Network Intrusion Detection System - log monitor
Rules loaded:
    NIDS-001  Brute-force login attempt (threshold: >=3 failures in 60s = WARNING, >=5 = HIGH)
    NIDS-002  Directory traversal attempt (signature)
    NIDS-003  SQL injection attempt (signature)
Monitoring (single pass): sample_logs/apache_access.log, sample_logs/auth.log
--------------------------------------------------------------------------
[HIGH]    2026-10-31 10:15:22  NIDS-003  SQL injection attempt
          detail   : SQL injection payload in request from 203.0.113.45
          source   : 203.0.113.45
          evidence : matched "UNION SELECT"
          where    : sample_logs/apache_access.log:4
          raw      : 203.0.113.45 - - [31/Oct/2026:10:15:22 +0000] "GET /index.php?id=1 UNION SELECT username,password FROM users HTTP/1.1" 200 512 "-" "sqlmap/1.7"
[WARNING] 2026-10-31 10:15:40  NIDS-002  Directory traversal attempt
          detail   : directory traversal payload in request from 203.0.113.66
          source   : 203.0.113.66
          evidence : matched "parent directory sequence"
          where    : sample_logs/apache_access.log:7
          raw      : 203.0.113.66 - - [31/Oct/2026:10:15:40 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 400 226 "-" "Mozilla/5.0 (X11; Linux x86_64)"
[HIGH]    2026-10-31 10:15:15  NIDS-001  Brute-force login attempt
          detail   : 5 failed logons from 203.0.113.77 within 60s - brute-force suspected
          source   : 203.0.113.77
          evidence : 5 failures in 60s window
          where    : sample_logs/auth.log:7
          raw      : 2026-10-31T10:15:15Z LOGIN_FAILED user=root src=203.0.113.77 reason=bad_password
--------------------------------------------------------------------------
Summary
  lines parsed      : 26
  lines ignored     : 0
  alerts raised     : 8  (HIGH: 4, WARNING: 4)
  alerts by rule    :
      NIDS-003 SQL injection attempt           3
      NIDS-002 Directory traversal attempt     3
      NIDS-001 Brute-force login attempt       2
  top source IPs    :
      203.0.113.45                             3
      203.0.113.66                             3
      203.0.113.77                             2
--------------------------------------------------------------------------
```

(Alerts shown abridged above for readability; the tool prints the full block for
each one. Output is coloured by default and falls back to plain text when the
terminal does not support ANSI.)

---

## Detection rules

### NIDS-001 — Brute-force login attempt *(threshold based)*

Flags a single source address that produces too many failed logons too quickly.

- Counts failures per source IP in a **sliding window** (default 60 s), so a slow
  trickle spread across many addresses is ignored while a burst from one address
  is caught.
- `WARNING` at **3** failures, `HIGH` at **5** failures (both configurable).
- Alerts once per escalation — not once per line — and resets when the window
  drains, so a later burst raises fresh alerts.
- A failure is any auth line whose event name contains `FAIL`, `INVALID`,
  `DENIED`, `REJECT` or `LOCKED`.

### NIDS-002 — Directory traversal attempt *(signature based)*

Matches path-traversal payloads after **URL-decoding twice** (so `..%2f..%2f`
and double-encoded forms are caught):

| Signature | Example |
|-----------|---------|
| parent directory sequence | `../../etc/passwd` |
| encoded parent sequence | `..%2f..%2fetc%2fpasswd` |
| unix sensitive file | `.../etc/shadow`, `/etc/hosts` |
| proc filesystem access | `/proc/self/environ` |
| windows sensitive file | `boot.ini`, `win.ini` |
| IIS-style traversal | `..;/` |

### NIDS-003 — SQL injection attempt *(signature based)*

| Signature | Example |
|-----------|---------|
| `UNION SELECT` | `1 UNION SELECT username,password FROM users` |
| boolean tautology (quoted) | `' OR '1'='1` |
| boolean tautology (numeric) | `1 OR 1=1` |
| stacked query terminator | `; --` |
| time-based injection | `SLEEP(5)`, `pg_sleep`, `WAITFOR DELAY` |
| schema enumeration | `information_schema` |
| command execution / file read | `xp_cmdshell`, `load_file` |

### Severity model

Both signature rules rate the attempt by the server's response:

- **HIGH** — the server *served* the payload (HTTP status `< 400`), i.e. it may
  have succeeded.
- **WARNING** — the server rejected it (HTTP status `>= 400`), i.e. a probe
  worth watching.

This is why the same traversal payload is `HIGH` at `200` but `WARNING` at `403`.

---

## Supported log formats

Format is auto-detected per line (`--format auto`, the default) or forced with
`--format apache` / `--format auth`.

**Apache combined** — source IP, timestamp, request, status:

```
203.0.113.45 - - [31/Oct/2026:10:15:22 +0000] "GET /index.php?id=1 UNION SELECT ... HTTP/1.1" 200 512 "-" "sqlmap/1.7"
```

**Auth (custom key=value)** — ISO-8601 timestamp, event name, `key=value` fields:

```
2026-10-31T10:15:15Z LOGIN_FAILED user=root src=203.0.113.77 reason=bad_password
```

Lines that match neither format are counted as *ignored* in the summary rather
than treated as errors.

---

## Command-line options

| Option | Description |
|--------|-------------|
| `-f, --file PATH` | Log file to monitor. Repeatable. Use `-` for stdin. **Required.** |
| `--follow` | Keep watching and alert on new lines (tail -f style). Not valid with stdin. |
| `--delay SECONDS` | Pause between lines when reading a file, to replay it at reading pace. |
| `--interval SECONDS` | Poll interval used by `--follow` (default: `0.5`). |
| `--format {auto,apache,auth}` | Log format; `auto` detects per line (default: `auto`). |
| `--brute-warn N` | Failed logons in the window that raise `WARNING` (default: `3`). |
| `--brute-high N` | Failed logons in the window that raise `HIGH` (default: `5`). |
| `--brute-window SECONDS` | Sliding window for the brute-force rule (default: `60`). |
| `--no-colour` / `--no-color` | Disable coloured output. |
| `-q, --quiet` | Print alerts only — no banner, no summary. |

`--follow` is Linux `tail -f` for Windows: it reads files in binary for exact
byte offsets and detects log rotation (the file shrinking), re-reading from the
start when the log is rotated.

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Completed successfully (alerts may or may not have fired). |
| `1` | A log file was not found. |
| `2` | Usage error — no `-f` source, invalid thresholds, or `--follow` with stdin. |

---

## Environment

- Python 3.8+ (developed and tested on Python 3.13.7, Windows).
- Standard library only — nothing to `pip install`.
- ANSI colours are enabled on Windows via Virtual Terminal Processing and
  degrade gracefully to plain text where unsupported.

---

## Legal notice

Only monitor log files and systems you own or are explicitly authorised to test.
The sample logs and simulator contain **synthetic** attacker traffic for
demonstration purposes only.
