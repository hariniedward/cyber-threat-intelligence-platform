"""
seed_data.py
============
Run this ONCE after first launch to populate the database with
realistic-looking demo scan data so the dashboard isn't empty.

Usage:
    python seed_data.py
"""

import sqlite3, random
from datetime import datetime, timedelta

DB = "database.db"

SOURCES   = ["LeakDB-Mirror-01","DataBreach-Forum-02","ThreatFeed-Alpha",
             "DarkPaste-Node-07","Breach-Archive-99","ShadowLeaks-v2","OSINT-Aggregate-03"]
TYPES     = [
    ("email",                        5,  "Low"),
    ("email,password",               30, "Medium"),
    ("email,password,aadhaar",       75, "Critical"),
    ("bank_account,credit_card,cvv", 90, "Critical"),
    ("aadhaar,pan",                  65, "High"),
    ("vpn_credentials,internal_network", 85, "Critical"),
    ("phone,personal_identity",      45, "Medium"),
    ("password,personal_identity",   60, "High"),
    ("email,password,bank_account",  80, "Critical"),
    ("aadhaar",                      55, "High"),
]
ALERTS = {
    "Critical": "🔴 CRITICAL: Immediate containment required. High-risk exposure of sensitive credentials.",
    "High":     "🟠 HIGH: Urgent response needed. Sensitive personal data found on dark web source.",
    "Medium":   "🟡 MEDIUM: Moderate exposure detected. Review and harden affected accounts.",
    "Low":      "🟢 LOW: Minor data exposure. Monitor for unusual activity.",
}

conn = sqlite3.connect(DB)
c    = conn.cursor()
c.execute("""
    CREATE TABLE IF NOT EXISTS scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT, source TEXT, data_type TEXT,
        sample_data TEXT, severity TEXT, risk_score INTEGER,
        alert_msg TEXT, timestamp TEXT, status TEXT DEFAULT 'new'
    )""")

for i in range(25):
    delta    = timedelta(hours=random.randint(0, 72))
    ts       = (datetime.now() - delta).strftime("%Y-%m-%d %H:%M:%S")
    dtype, score, sev = random.choice(TYPES)
    score   += random.randint(-5, 5)
    scan_id  = f"SCAN-DEMO-{i+1:03d}"
    source   = random.choice(SOURCES)
    sample   = f"[DEMO] email:user{random.randint(100,999)}@example.com | {dtype.split(',')[0]}:***REDACTED***"
    c.execute("""INSERT INTO scan_results
        (scan_id,source,data_type,sample_data,severity,risk_score,alert_msg,timestamp)
        VALUES (?,?,?,?,?,?,?,?)""",
        (scan_id, source, dtype, sample, sev, min(100,max(0,score)), ALERTS[sev], ts))

conn.commit()
conn.close()
print(f"✓ Seeded 25 demo scan records into database.db")
print("  Open http://127.0.0.1:5000 to see the populated dashboard.")
