# Task 2 — Secure Code Assessment & Remediation

A professional vulnerability assessment of a sample Flask web application,
paired with a working insecure-to-secure code demonstration. This task includes
two functional web portals designed with a modern Bootstrap UI to showcase real
vulnerabilities and their fixes.

---

## Deliverables

| File | What it is |
|---|---|
| [vulnerability_assessment_report.md](vulnerability_assessment_report.md) | **The report.** Completed assessment of the sample app: 2 findings with severity, CVSS vectors, CWE IDs, risk, impact, PoC and fix |
| [VULNERABILITY_REPORT_TEMPLATE.md](VULNERABILITY_REPORT_TEMPLATE.md) | **The template.** Reusable blank professional report structure for future assessments |
| [insecure_app.py](insecure_app.py) | **Vulnerable Portal** (Red Theme) — Deliberately flawed for demonstration |
| [secure_app.py](secure_app.py) | **Secure Portal** (Blue Theme) — Hardened against attacks |
| [demo_exploit.py](demo_exploit.py) | **Automated PoC** — Harness that proves the vulnerabilities and the fixes |

---

## Features (mapped to the task brief)

| # | Requirement | Delivered by |
|---|---|---|
| 1 | Structured vulnerability report covering SQLi + XSS | `vulnerability_assessment_report.md` |
| 2 | Insecure Python/Flask snippet (raw SQL query) | `insecure_app.py` (Red Theme) |
| 3 | Corresponding secure remediation snippet | `secure_app.py` (Blue Theme) |
| 4 | Clear explanations of risk, impact and fix | Assessment Report Sections 6 and 7 |

---

## How to run

### 1. Automated Verification (Recommended)

Run the exploit harness to verify that the vulnerabilities are present in the
insecure app and blocked in the secure app:

```bash
cd Task2_SecureCodeAssessment
python demo_exploit.py
```

**Result:** You should see `8/8 checks passed`.

### 2. Manual Exploration (Web Browser)

Both apps now feature a professional **Bootstrap UI** and a **Home Page** for
easier navigation.

#### **A. The Insecure Portal (Red Theme)**
```bash
python insecure_app.py        # http://127.0.0.1:5001
```
- **Home:** `http://127.0.0.1:5001/`
- **SQL Injection Hack:** Go to search and enter `' OR '1'='1`. It will dump all users.
- **XSS Hack:** Visit `http://127.0.0.1:5001/profile?name=<script>alert('Hacked!')</script>`.

#### **B. The Secure Portal (Blue Theme)**
```bash
python secure_app.py          # http://127.0.0.1:5002
```
- **Home:** `http://127.0.0.1:5002/`
- **Verification:** Try the same hacks above. The SQL injection will return "No users found" and the XSS script will be safely printed as text on the page.

---

## Vulnerability Details

### FINDING-001 — SQL Injection (CWE-89)
**Vulnerable:** Input is concatenated directly into the SQL string.
```python
sql = "SELECT id, username, bio FROM users WHERE username = '" + query + "'"
```
**Secure:** Input is passed as a bound parameter to the database driver.
```python
sql = "SELECT id, username, bio FROM users WHERE username = ?"
conn.execute(sql, (query,))
```

### FINDING-002 — Reflected XSS (CWE-79)
**Vulnerable:** Input is concatenated into the template source before compilation.
```python
page = "<html><body><h2>Welcome, " + name + "!</h2></body></html>"
return render_template_string(page)
```
**Secure:** Input is passed as context data, and Jinja auto-escapes it.
```python
PROFILE_TEMPLATE = "<html><body><h2>Welcome, {{ name }}!</h2></body></html>"
return render_template_string(PROFILE_TEMPLATE, name=name)
```

---

## Legal notice

`insecure_app.py` is deliberately vulnerable. It binds to `127.0.0.1` only — never
expose it publicly. These payloads must only ever be run against systems you own
or are explicitly authorised to test.
