#!/usr/bin/env python3
"""
INSECURE Flask application - DELIBERATELY VULNERABLE
====================================================
CodSoft Cyber Security Internship - Task 2 (Secure Code Assessment)

This file exists ONLY to demonstrate real, exploitable vulnerabilities for the
accompanying assessment report. It is the "before" half of the insecure-to-secure
comparison. The remediated version is ``secure_app.py``.

Deliberate flaws:
    1. SQL Injection (CWE-89) - the ``/search`` endpoint concatenates user input
       straight into a raw SQL string.
    2. Reflected XSS (CWE-79) - the ``/profile`` endpoint concatenates user input
       into the Jinja template *source*, so any markup is rendered verbatim.

DO NOT DEPLOY THIS FILE. Never run it on a public interface.

Run (for local demonstration only):
    python insecure_app.py        -> http://127.0.0.1:5001
"""

from __future__ import annotations

import os
import sqlite3

from flask import Flask, request, render_template_string

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "insecure_app.db")

SEED_USERS = [
    (1, "alice", "s3cr3t-Alice!", "Security engineer. Collects packet captures."),
    (2, "bob", "hunter2", "Backend developer. Owns the billing service."),
    (3, "admin", "Adm1n-Sup3r-S3cret", "Platform administrator."),
]

app = Flask(__name__)

# Shared Bootstrap Layout for a "Professional" look
LAYOUT_START = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>CodSoft - Insecure Portal (Demo)</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .navbar { background-color: #dc3545 !important; }
        .hero { background: white; padding: 2rem; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark mb-4">
        <div class="container">
            <a class="navbar-brand" href="/">Insecure Portal</a>
            <div class="navbar-nav">
                <a class="nav-link" href="/">Home</a>
                <a class="nav-link" href="/search">Search</a>
            </div>
        </div>
    </nav>
    <div class="container">
"""

LAYOUT_END = """
    </div>
    <footer class="mt-5 py-3 text-center text-muted">
        <small>Internship Demo - CodSoft Task 2</small>
    </footer>
</body>
</html>
"""

# --------------------------------------------------------------------------- #
# Database helpers
# --------------------------------------------------------------------------- #
def init_db(path: str = DB_PATH) -> None:
    conn = sqlite3.connect(path)
    conn.execute("DROP TABLE IF EXISTS users")
    conn.execute(
        "CREATE TABLE users ("
        "  id INTEGER PRIMARY KEY,"
        "  username TEXT NOT NULL,"
        "  password TEXT NOT NULL,"
        "  bio TEXT"
        ")"
    )
    conn.executemany("INSERT INTO users VALUES (?, ?, ?, ?)", SEED_USERS)
    conn.commit()
    conn.close()

def get_connection() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH, check_same_thread=False)

# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    page = LAYOUT_START + """
    <div class="hero">
        <h1>Welcome to the Insecure Portal</h1>
        <p class="lead">This portal is deliberately built with security flaws for demonstration.</p>
        <hr>
        <div class="row mt-4">
            <div class="col-md-6">
                <h3>Test Search</h3>
                <form action="/search" method="GET" class="d-flex">
                    <input type="text" name="q" class="form-control me-2" placeholder="Search user...">
                    <button type="submit" class="btn btn-danger">Search</button>
                </form>
            </div>
            <div class="col-md-6">
                <h3>Test Profile</h3>
                <a href="/profile?name=Intern" class="btn btn-outline-danger">View Profile</a>
            </div>
        </div>
    </div>
    """ + LAYOUT_END
    return render_template_string(page)

@app.route("/search")
def search():
    query = request.args.get("q", "")
    sql = "SELECT id, username, bio FROM users WHERE username = '" + query + "'"
    
    conn = get_connection()
    try:
        rows = conn.execute(sql).fetchall()
    except sqlite3.Error as exc:
        return f"<pre class='alert alert-danger'>SQL error: {exc}\n\nQuery was: {sql}</pre>", 500
    finally:
        conn.close()

    rows_html = "".join(
        f"<tr><td>{row[0]}</td><td>{row[1]}</td><td>{row[2]}</td></tr>" for row in rows
    )

    # VULNERABLE: `query` is spliced into the template SOURCE
    page = LAYOUT_START + f"""
    <div class="hero">
        <h2>User Search Results</h2>
        <p>You searched for: <strong>{query}</strong></p>
        <table class="table table-striped mt-3">
            <thead class="table-dark">
                <tr><th>ID</th><th>Username</th><th>Bio</th></tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
        <a href="/" class="btn btn-secondary">Back</a>
    </div>
    """ + LAYOUT_END
    return render_template_string(page)

@app.route("/profile")
def profile():
    name = request.args.get("name", "guest")
    # VULNERABLE: `name` is concatenated into template source
    page = LAYOUT_START + f"""
    <div class="hero">
        <h2>Welcome, {name}!</h2>
        <p>This page demonstrates Reflected XSS.</p>
        <a href="/" class="btn btn-secondary">Back</a>
    </div>
    """ + LAYOUT_END
    return render_template_string(page)

if __name__ == "__main__":
    init_db()
    print("INSECURE app running on http://127.0.0.1:5001")
    app.run(host="127.0.0.1", port=5001, debug=False)
