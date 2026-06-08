import hashlib
import os
import pickle
import random
import secrets
import sqlite3
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

# ============================================================
# VULNÉRABILITÉS SAST — Lab DevSecOps Free Mobile
# Objectif : détecter ces vulnérabilités avec Semgrep
# Outils    : semgrep --config p/python --config .semgrep.yml
# ============================================================

DB_PATH = "netops.db"


def get_db():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS equipment (
            id      INTEGER PRIMARY KEY,
            hostname TEXT,
            ip      TEXT,
            type    TEXT,
            site    TEXT,
            status  TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS auth_users (
            id       INTEGER PRIMARY KEY,
            username TEXT,
            password_hash TEXT,
            role     TEXT
        )
    """)
    if not conn.execute("SELECT 1 FROM equipment LIMIT 1").fetchone():
        conn.executemany("INSERT INTO equipment VALUES (?,?,?,?,?,?)", [
            (1, "rtr-paris-01", "10.10.1.1",  "router", "Paris-CDG",  "active"),
            (2, "bts-lyon-07",  "10.20.7.3",  "bts",    "Lyon-Part",  "active"),
            (3, "nas-mars-04",  "10.30.4.11", "nas",    "Marseille",  "maintenance"),
            (4, "rtr-bord-02",  "10.40.2.5",  "router", "Bordeaux",   "active"),
        ])
        # Mots de passe hashés en MD5 — VULN #3
        conn.executemany("INSERT INTO auth_users VALUES (?,?,?,?)", [
            (1, "admin",    hashlib.md5(b"netops2024!").hexdigest(), "admin"),
            (2, "operator", hashlib.md5(b"fr33mobile").hexdigest(),  "operator"),
        ])
        conn.commit()
    conn.close()


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "freemobile-netops-api"})


@app.route("/api/v1/equipment")
def equipment_list():
    conn = get_db()
    rows = conn.execute("SELECT * FROM equipment").fetchall()
    conn.close()
    return jsonify([
        {"id": r[0], "hostname": r[1], "ip": r[2], "type": r[3], "site": r[4], "status": r[5]}
        for r in rows
    ])


# VULN #1 — SQL Injection
# Semgrep : python.lang.security.audit.formatted-sql-query
@app.route("/api/v1/equipment/search")
def equipment_search():
    query = request.args.get("q", "")
    conn = get_db()
    # Concaténation directe → injection SQL possible
    # Essayez : ?q=' OR '1'='1
    rows = conn.execute(
        f"SELECT * FROM equipment WHERE hostname LIKE '%{query}%' OR site LIKE '%{query}%'"
    ).fetchall()
    conn.close()
    return jsonify([
        {"id": r[0], "hostname": r[1], "ip": r[2], "type": r[3], "site": r[4], "status": r[5]}
        for r in rows
    ])


# VULN #2 — OS Command Injection
# Semgrep : python.lang.security.audit.subprocess-shell-true.subprocess-shell-true
@app.route("/api/v1/equipment/ping", methods=["POST"])
def equipment_ping():
    data = request.get_json() or {}
    ip = data.get("ip", "")
    # shell=True + input utilisateur → injection de commandes OS
    # Essayez : {"ip": "10.10.1.1; cat /etc/passwd"}
    result = subprocess.run(
        f"ping -c 2 {ip}",
        shell=True,
        capture_output=True,
        text=True,
        timeout=10
    )
    return jsonify({"stdout": result.stdout, "returncode": result.returncode})


# VULN #3 — Weak Cryptography (MD5 pour authentification)
# Semgrep : règle custom freemobile-no-md5 dans .semgrep.yml
@app.route("/api/v1/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")
    # MD5 sans sel → cassable par rainbow tables
    hashed = hashlib.md5(password.encode()).hexdigest()
    conn = get_db()
    row = conn.execute(
        "SELECT role FROM auth_users WHERE username = ? AND password_hash = ?",
        (username, hashed)
    ).fetchone()
    conn.close()
    if row:
        return jsonify({"status": "ok", "role": row[0]})
    return jsonify({"status": "unauthorized"}), 401


# VULN #4 — Insecure Deserialization (pickle)
# Semgrep : python.lang.security.audit.pickle.use-of-pickle
@app.route("/api/v1/config/restore", methods=["POST"])
def config_restore():
    raw = request.data
    # pickle.loads sur données HTTP → RCE (Remote Code Execution) possible
    # Un attaquant peut exécuter du code arbitraire via un payload pickle
    config = pickle.loads(raw)
    return jsonify({"status": "restored", "keys": list(config.keys()) if isinstance(config, dict) else []})


# VULN #5 — Code Injection (eval)
# Semgrep : règle custom freemobile-no-eval dans .semgrep.yml
@app.route("/api/v1/alerts/evaluate", methods=["POST"])
def alert_evaluate():
    data = request.get_json() or {}
    rule = data.get("rule", "")
    # eval() sur input utilisateur → exécution arbitraire de code Python
    # Essayez : {"rule": "__import__('os').system('id')"}
    result = eval(rule)
    return jsonify({"result": str(result)})


# VULN #6 — Insecure Random (token de session)
# Semgrep : python.lang.security.audit.insecure-random-usage.use-of-random
@app.route("/api/v1/token/generate")
def token_generate():
    # random.randint() n'est pas cryptographiquement sûr
    # Prévisible → attaque par brute force ou prédiction de token
    token = str(random.randint(100000, 999999))
    return jsonify({"token": token, "expires_in": 3600})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
