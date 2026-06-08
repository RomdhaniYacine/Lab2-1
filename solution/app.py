import ast
import hashlib
import ipaddress
import json
import os
import secrets
import sqlite3
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

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
        # SHA-256 avec sel — pas de MD5
        def make_hash(password):
            salt = os.urandom(16).hex()
            h = hashlib.sha256((salt + password).encode()).hexdigest()
            return f"{salt}:{h}"

        conn.executemany("INSERT INTO auth_users VALUES (?,?,?,?)", [
            (1, "admin",    make_hash("netops2024!"), "admin"),
            (2, "operator", make_hash("fr33mobile"),  "operator"),
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


# CORRIGÉ #1 — SQL Injection → requête paramétrée
@app.route("/api/v1/equipment/search")
def equipment_search():
    query = request.args.get("q", "")
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM equipment WHERE hostname LIKE ? OR site LIKE ?",
        (f"%{query}%", f"%{query}%")
    ).fetchall()
    conn.close()
    return jsonify([
        {"id": r[0], "hostname": r[1], "ip": r[2], "type": r[3], "site": r[4], "status": r[5]}
        for r in rows
    ])


# CORRIGÉ #2 — Command Injection → liste d'args + validation IP
@app.route("/api/v1/equipment/ping", methods=["POST"])
def equipment_ping():
    data = request.get_json() or {}
    ip = data.get("ip", "")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "Adresse IP invalide"}), 400
    result = subprocess.run(
        ["ping", "-c", "2", ip],
        capture_output=True,
        text=True,
        timeout=10
    )
    return jsonify({"stdout": result.stdout, "returncode": result.returncode})


# CORRIGÉ #3 — MD5 → SHA-256 avec sel
@app.route("/api/v1/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")
    conn = get_db()
    row = conn.execute(
        "SELECT password_hash, role FROM auth_users WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()
    if row:
        stored = row[0]
        salt, expected_hash = stored.split(":", 1)
        actual_hash = hashlib.sha256((salt + password).encode()).hexdigest()
        if secrets.compare_digest(actual_hash, expected_hash):
            return jsonify({"status": "ok", "role": row[1]})
    return jsonify({"status": "unauthorized"}), 401


# CORRIGÉ #4 — pickle → json
@app.route("/api/v1/config/restore", methods=["POST"])
def config_restore():
    try:
        config = json.loads(request.data)
    except json.JSONDecodeError:
        return jsonify({"error": "JSON invalide"}), 400
    return jsonify({"status": "restored", "keys": list(config.keys()) if isinstance(config, dict) else []})


# CORRIGÉ #5 — eval() → ast.literal_eval()
@app.route("/api/v1/alerts/evaluate", methods=["POST"])
def alert_evaluate():
    data = request.get_json() or {}
    rule = data.get("rule", "")
    try:
        result = ast.literal_eval(rule)
    except (ValueError, SyntaxError):
        return jsonify({"error": "Expression invalide — seuls les types Python simples sont acceptés"}), 400
    return jsonify({"result": str(result)})



if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
