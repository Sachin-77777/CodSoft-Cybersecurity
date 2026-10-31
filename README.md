# CodSoft Cyber Security Internship

> **Status:** Tasks 1, 2 and 3 are complete and tested.

A collection of cyber security tooling and assessments built in Python for the
CodSoft Cyber Security internship. Each task lives in its own folder with its own
source, documentation and dependencies.

---

## Repository layout

```
CodSoft-Cybersecurity/
├── README.md                          <- this file: how to run each tool
├── .gitignore  
├── requirements.txt                   <- shared dependencies
├── Task1_PacketAnalyzer/
│   ├── packet_analyzer.py             <- packet capture & parsing CLI
│   ├── generate_sample_pcap.py        <- builds sample.pcap for offline demos
│   ├── sample.pcap                    <- generated demo capture
│   ├── requirements.txt
│   └── README.md
├── Task2_SecureCodeAssessment/
│   ├── vulnerability_assessment_report.md    <- completed assessment (SQLi + XSS)
│   ├── VULNERABILITY_REPORT_TEMPLATE.md      <- reusable blank report template
│   ├── insecure_app.py                       <- deliberately vulnerable Flask app
│   ├── secure_app.py                         <- remediated Flask app
│   ├── demo_exploit.py                       <- proof-of-concept harness
│   ├── requirements.txt
│   └── README.md
└── Task3_NIDS/
    ├── nids.py                        <- NIDS CLI: monitoring modes + alerting
    ├── rules.py                       <- detection rules (brute-force, traversal, SQLi)
    ├── log_parser.py                  <- Apache access + auth log parsing
    ├── simulate_attack.py             <- appends scripted traffic for live demos
    ├── sample_logs/
    │   ├── apache_access.log          <- sample access log with attack probes
    │   └── auth.log                   <- sample auth log with a brute-force burst
    ├── requirements.txt
    └── README.md
```

## Tasks

| # | Task | Folder | Status |
|---|------|--------|--------|
| 1 | Network Packet Analyzer | `Task1_PacketAnalyzer/` | Done |
| 2 | Secure Code Assessment & Remediation | `Task2_SecureCodeAssessment/` | Done |
| 3 | Network Intrusion Detection System (NIDS) | `Task3_NIDS/` | Done |

---

## How to run each tool

### Setup (once)

```bash
pip install -r requirements.txt
```

Per-task dependencies are also listed in each folder's own `requirements.txt`.

### Task 1 — Network Packet Analyzer

Captures live traffic (or reads a `.pcap`) with Scapy, parses Source IP,
Destination IP, Protocol and a payload snippet, and prints a formatted summary to
the terminal and/or a log file.

```bash
cd Task1_PacketAnalyzer

# Offline demo — no admin rights required
python generate_sample_pcap.py sample.pcap
python packet_analyzer.py -r sample.pcap

# Live capture (needs root / Administrator + libpcap/Npcap)
python packet_analyzer.py --list-interfaces
python packet_analyzer.py -i "Wi-Fi" -c 20 -o capture.log
```

Full options and sample output: [Task1 README](Task1_PacketAnalyzer/README.md)

### Task 2 — Secure Code Assessment & Remediation

A vulnerability assessment of a sample Flask app with a working
insecure-to-secure demonstration. Covers **SQL Injection** (CWE-89) and
**Reflected XSS** (CWE-79).

```bash
cd Task2_SecureCodeAssessment

# Prove the vulnerabilities and the fixes — no server or browser needed
python demo_exploit.py

# Explore the vulnerable app by hand
python insecure_app.py            # http://127.0.0.1:5001
#   /search?q=' OR '1'='1
#   /search?q=nobody' UNION SELECT 1, username, password FROM users--
#   /profile?name=<script>alert(document.cookie)</script>

# Confirm the fixes hold
python secure_app.py              # http://127.0.0.1:5002
```

Read the assessment: [vulnerability_assessment_report.md](Task2_SecureCodeAssessment/vulnerability_assessment_report.md)
Full details: [Task2 README](Task2_SecureCodeAssessment/README.md)

> `insecure_app.py` is deliberately vulnerable. It binds to `127.0.0.1` only —
> never expose it publicly.

### Task 3 — Network Intrusion Detection System (NIDS)

A lightweight, stdlib-only log-monitoring NIDS. Watches one or more log files (or
`stdin`) and raises real-time `WARNING` / `HIGH` alerts for brute-force bursts,
directory traversal and SQL injection. Ships with sample logs and a traffic
simulator.

```bash
cd Task3_NIDS

# Scan the bundled sample logs once (no install needed — stdlib only)
python nids.py -f sample_logs/apache_access.log -f sample_logs/auth.log

# Replay a log at reading pace so alerts appear over time
python nids.py -f sample_logs/auth.log --delay 0.4

# Live tail (tail -f style) — run simulate_attack.py in a second terminal
python nids.py -f sample_logs/live_access.log --follow

# Read a stream from stdin
python nids.py -f - < /var/log/apache2/access.log
```

Full options, detection rules and sample output: [Task3 README](Task3_NIDS/README.md)

---

## Environment

- Python 3.8+ (developed and tested on Python 3.13.7, Windows)
- Task 1: Scapy 2.5+
- Task 2: Flask 3.x
- Task 3: standard library only (nothing to install)

---

## Legal notice

Only capture traffic on networks and devices you own or are explicitly
authorised to test. The vulnerable application in Task 2 exists for training and
assessment demonstration only; its payloads must only ever be run against
systems you own or are authorised to test.
