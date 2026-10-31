#!/usr/bin/env python3
"""
SECURE Flask application - REMEDIATED
=====================================
CodSoft Cyber Security Internship - Task 2 (Secure Code Assessment)

The "after" half of the comparison. Same functionality as ``insecure_app.py``,
same routes and same seed data, but every flaw identified in the assessment
report has been fixed:

    FINDING-001  SQL Injection   -> parameterised queries (bound parameters)
    FINDING-002  Reflected XSS   -> Jinja autoescaping, input never enters the
                                    template source
    Hardening    Error leakage   -> generic client message, detail goes to the
                                    server log only
    Hardening    Input size      -> reject oversized input before it is used

Run:
    python secure_app.py          -> http://127.0.0.1:5002
"""

from __future__ import annotations

import logging
import os
import sqlite3

from flask import Flask, request, render_template_string

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "secure_app.db")

SEED_USERS = [
    (1, "alice", "s3cr3t-Alice!", "Security engineer. Collects packet captures."),
    (2, "bob", "hunter2", "Backend developer. Owns the billing service."),
    (3, "admin", "Adm1n-Sup3r-S3cret", "Platform administrator."),
]

MAX_INPUT_LENGTH = 64

app = Flask(__name__)
app.jinja_env.autoescape = True

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Shared Bootstrap Layout for a "Professional" look
LAYOUT_START = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>CodSoft - Secure Portal (Hardened)</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .navbar { background-color: #0d6efd !important; }
        .hero { background: white; padding: 2rem; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark mb-4">
        <div class="container">
            <a class="navbar-brand" href="/">Secure Portal</a>
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
        <small>Internship Demo - CodSoft Task 2 (Remediated)</small>
    </footer>
</body>
</html>
"""

# Static templates for security.
INDEX_TEMPLATE = LAYOUT_START + """
<div class="hero">
    <h1>Welcome to the Secure Portal</h1>
    <p class="lead">This portal has been hardened against SQL Injection and XSS attacks.</p>
    <hr>
    <div class="row mt-4">
        <div class="col-md-6">
            <h3>Secure Search</h3>
            <form action="/search" method="GET" class="d-flex">
                <input type="text" name="q" class="form-control me-2" placeholder="Search user...">
                <button type="submit" class="btn btn-primary">Search</button>
            </form>
        </div>
        <div class="col-md-6">
            <h3>Secure Profile</h3>
            <a href="/profile?name=Intern" class="btn btn-outline-primary">View Profile</a>
        </div>
    </div>
</div>
""" + LAYOUT_END

SEARCH_TEMPLATE = LAYOUT_START + """
<div class="hero">
    <h2>User Search Results</h2>
    <p>You searched for: <strong>{{ query }}</strong></p>
    <table class="table table-striped mt-3">
        <thead class="table-dark">
            <tr><th>ID</th><th>Username</th><th>Bio</th></tr>
        </thead>
        <tbody>
            {% for row in rows %}
            <tr><td>{{ row[0] }}</td><td>{{ row[1] }}</td><td>{{ row[2] }}</td></tr>
            {% else %}
            <tr><td colspan="3" class="text-center">No users found.</td></tr>
            {% endfor %}
        </tbody>
    </table>
    <a href="/" class="btn btn-secondary">Back</a>
</div>
""" + LAYOUT_END

PROFILE_TEMPLATE = LAYOUT_START + """
<div class="hero">
    <h2>Welcome, {{ name }}!</h2>
    <p>This page is protected against Reflected XSS.</p>
    <a href="/" class="btn btn-secondary">Back</a>
</div>
""" + LAYOUT_END

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

def is_acceptable(value: str) -> bool:
    return len(value) <= MAX_INPUT_LENGTH and not any(ord(ch) < 32 for ch in value)

# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    return render_template_string(INDEX_TEMPLATE)

@app.route("/search")
def search():
    query = request.args.get("q", "")
    if not is_acceptable(query):
        return render_template_string(SEARCH_TEMPLATE, query="(invalid input)", rows=[]), 400

    sql = "SELECT id, username, bio FROM users WHERE username = ?"
    conn = get_connection()
    try:
        rows = conn.execute(sql, (query,)).fetchall()
    except sqlite3.Error:
        logger.exception("database error while handling /search")
        return render_template_string(SEARCH_TEMPLATE, query="(error)", rows=[]), 500
    finally:
        conn.close()

    return render_template_string(SEARCH_TEMPLATE, query=query, rows=rows)

@app.route("/profile")
def profile():
    name = request.args.get("name", "guest")
    if not is_acceptable(name):
        name = "guest"
    return render_template_string(PROFILE_TEMPLATE, name=name)

if __name__ == "__main__":
    init_db()
    print("SECURE app running on http://127.0.0.1:5002")
    app.run(host="127.0.0.1", port=5002, debug=False)
