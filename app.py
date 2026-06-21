"""
=============================================================================
Cyber Threat Intelligence Platform for Dark Web Data Leaks
=============================================================================
Author      : Your Name
Version     : 1.0.0
Description : AI-based cybersecurity platform that monitors dark web leak
              sources, detects sensitive data, classifies threats, generates
              reports, and supports legal complaint filing.

IEEE Reference Format:
    This system implements a modular threat intelligence architecture using
    Flask microframework, SQLite persistence, and heuristic AI scoring.
=============================================================================
"""

from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session
from datetime import datetime
import sqlite3
import os
import json

# Internal module imports
from modules.tor_crawler import fetch_darkweb_data, store_raw_findings
from modules.threat_detector import detect_sensitive_data, classify_severity, generate_alert, ai_risk_score
from modules.report_generator import generate_pdf_report, generate_excel_report, generate_summary_report
from modules.email_sender import send_email_report
from modules.legal_support import get_complaint_template, get_evidence_checklist
from modules.export_module import export_report

# ─── App Configuration ──────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = "CTI_PLATFORM_SECRET_2024"

DB_PATH = "database.db"
ADMIN_USER = "admin"
ADMIN_PASS = "admin@123"

# ─── Database Initialization ─────────────────────────────────────────────────
def init_db():
    """Initialize SQLite database with required tables."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     TEXT,
            source      TEXT,
            data_type   TEXT,
            sample_data TEXT,
            severity    TEXT,
            risk_score  INTEGER,
            alert_msg   TEXT,
            timestamp   TEXT,
            status      TEXT DEFAULT 'new'
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     TEXT,
            report_type TEXT,
            file_path   TEXT,
            created_at  TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    # Default settings
    defaults = [
        ("scan_frequency", "manual"),
        ("threat_sensitivity", "medium"),
        ("email_alerts", "off"),
        ("alert_email", ""),
        ("smtp_host", "smtp.gmail.com"),
        ("smtp_port", "587"),
        ("smtp_user", ""),
        ("smtp_pass", ""),
        ("export_format", "both"),
        ("admin_user", ADMIN_USER),
        ("admin_pass", ADMIN_PASS),
    ]
    for key, val in defaults:
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, val))

    conn.commit()
    conn.close()


# ─── Helper ──────────────────────────────────────────────────────────────────
def get_setting(key):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key=?", (key,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else ""


def get_db_stats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM scan_results")
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM scan_results WHERE severity='Critical'")
    critical = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM scan_results WHERE severity='High'")
    high = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM scan_results WHERE severity='Medium'")
    medium = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM scan_results WHERE severity='Low'")
    low = c.fetchone()[0]
    c.execute("SELECT AVG(risk_score) FROM scan_results")
    avg_risk = c.fetchone()[0] or 0
    c.execute("SELECT * FROM scan_results ORDER BY id DESC LIMIT 10")
    recent = c.fetchall()
    conn.close()
    return {
        "total": total, "critical": critical, "high": high,
        "medium": medium, "low": low,
        "avg_risk": round(avg_risk, 1),
        "recent": recent
    }


# ─── Auth Routes ─────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username")
        p = request.form.get("password")
        admin_user = get_setting("admin_user")
        admin_pass = get_setting("admin_pass")
        if u == admin_user and p == admin_pass:
            session["logged_in"] = True
            session["username"] = u
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ─── Main Routes ─────────────────────────────────────────────────────────────
@app.route("/")
@login_required
def dashboard():
    stats = get_db_stats()
    return render_template("dashboard.html", stats=stats, username=session.get("username"))


@app.route("/scan")
@login_required
def scan_page():
    return render_template("scan.html")


@app.route("/api/run_scan", methods=["POST"])
@login_required
def run_scan():
    """
    Core scan endpoint.
    1. Fetch simulated dark web data
    2. Detect sensitive patterns
    3. Score & classify
    4. Persist results
    5. Return JSON summary
    """
    try:
        scan_id = f"SCAN-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        raw_data = fetch_darkweb_data()
        findings = []

        for item in raw_data:
            detected = detect_sensitive_data(item["content"])
            if detected["found"]:
                severity = classify_severity(detected["types"])
                score    = ai_risk_score(detected["types"], item.get("source_trust", 5))
                alert    = generate_alert(severity, detected["types"])
                store_raw_findings(scan_id, item, detected, severity, score, alert)
                findings.append({
                    "source":    item["source"],
                    "types":     detected["types"],
                    "severity":  severity,
                    "risk_score":score,
                    "alert":     alert,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })

        return jsonify({
            "status":   "success",
            "scan_id":  scan_id,
            "findings": len(findings),
            "results":  findings
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/report")
@login_required
def report_page():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM scan_results ORDER BY id DESC")
    results = c.fetchall()
    conn.close()
    return render_template("report.html", results=results)


@app.route("/api/generate_report", methods=["POST"])
@login_required
def generate_report():
    data = request.json or {}
    rtype = data.get("type", "pdf")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM scan_results ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()

    if not rows:
        return jsonify({"status": "error", "message": "No scan data found"}), 400

    if rtype == "pdf":
        path = generate_pdf_report(rows)
    elif rtype == "excel":
        path = generate_excel_report(rows)
    else:
        path = generate_summary_report(rows)

    return jsonify({"status": "success", "file": path})


@app.route("/api/download/<path:filename>")
@login_required
def download_file(filename):
    full = os.path.join(os.getcwd(), filename)
    if os.path.exists(full):
        return send_file(full, as_attachment=True)
    return jsonify({"status": "error", "message": "File not found"}), 404


@app.route("/respond")
@login_required
def respond_page():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM scan_results WHERE severity IN ('Critical','High') ORDER BY id DESC LIMIT 20")
    threats = c.fetchall()
    conn.close()
    return render_template("respond.html", threats=threats)


@app.route("/legal")
@login_required
def legal_page():
    template   = get_complaint_template()
    checklist  = get_evidence_checklist()
    return render_template("legal.html", template=template, checklist=checklist)


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings_page():
    message = ""
    if request.method == "POST":
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        fields = ["scan_frequency","threat_sensitivity","email_alerts","alert_email",
                  "smtp_host","smtp_port","smtp_user","smtp_pass","export_format",
                  "admin_user","admin_pass"]
        for f in fields:
            val = request.form.get(f, "")
            c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)", (f, val))
        conn.commit()
        conn.close()
        message = "Settings saved successfully."

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT key, value FROM settings")
    s = {r[0]: r[1] for r in c.fetchall()}
    conn.close()
    return render_template("settings.html", s=s, message=message)


@app.route("/api/send_email", methods=["POST"])
@login_required
def send_email():
    data = request.json or {}
    to   = data.get("to", get_setting("alert_email"))
    if not to:
        return jsonify({"status": "error", "message": "No recipient email configured"}), 400
    result = send_email_report(to)
    return jsonify(result)


@app.route("/api/clear_data", methods=["POST"])
@login_required
def clear_data():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM scan_results")
    c.execute("DELETE FROM reports")
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": "All scan data cleared."})


@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify(get_db_stats())


# ─── Entry Point ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("\n" + "="*60)
    print("  Cyber Threat Intelligence Platform")
    print("  Running at: http://127.0.0.1:5000")
    print("  Admin Login: admin / admin@123")
    print("="*60 + "\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
