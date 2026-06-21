"""
=============================================================================
Module      : tor_crawler.py
Purpose     : Simulated Dark Web Data Collection Engine
Description : Provides safe academic demonstration of dark web leak monitoring
              using synthetic demo data. No real Tor connections are made to
              illegal sources. Implements Tor routing setup for legitimate
              academic/research demonstration purposes only.

IEEE Note   : All data collected in this module is synthetically generated
              for academic demonstration. This module does NOT access illegal
              dark web marketplaces or personal data without consent.
=============================================================================
"""

import sqlite3
import random
import string
import hashlib
from datetime import datetime, timedelta

DB_PATH = "database.db"

# ─── Synthetic Demo Data Pool ─────────────────────────────────────────────────
# These are FAKE/DEMO records generated for educational purposes only.

DEMO_SOURCES = [
    {"name": "LeakDB-Mirror-01",   "trust": 3, "category": "paste_site"},
    {"name": "DataBreach-Forum-02","trust": 2, "category": "forum_dump"},
    {"name": "ThreatFeed-Alpha",   "trust": 6, "category": "threat_feed"},
    {"name": "DarkPaste-Node-07",  "trust": 1, "category": "paste_site"},
    {"name": "Breach-Archive-99",  "trust": 4, "category": "archive"},
    {"name": "ShadowLeaks-v2",     "trust": 2, "category": "forum_dump"},
    {"name": "OSINT-Aggregate-03", "trust": 7, "category": "osint"},
]

DEMO_ORGS = [
    "TechCorp India Pvt Ltd", "HealthFirst Hospital", "SecureBank Ltd",
    "EduPortal University", "GovServices Department", "RetailMart Chain",
    "InsuranceHub Corp", "LogiTrans Solutions",
]

LEAK_TEMPLATES = [
    {
        "type":    "email_password",
        "content": lambda: f"user:{_fake_email()} | pass:{_fake_pass()} | org:{random.choice(DEMO_ORGS)}",
        "tags":    ["email", "password"],
    },
    {
        "type":    "bank_credentials",
        "content": lambda: (
            f"acct:{_fake_acct()} | ifsc:{_fake_ifsc()} | cvv:{random.randint(100,999)} "
            f"| card:{_fake_card()} | bank:{random.choice(['SBI','HDFC','ICICI','Axis'])}"
        ),
        "tags":    ["bank_account", "credit_card", "cvv"],
    },
    {
        "type":    "aadhaar_leak",
        "content": lambda: (
            f"name:{_fake_name()} | aadhaar:{_fake_aadhaar()} | dob:{_fake_dob()} "
            f"| addr:{_fake_address()}"
        ),
        "tags":    ["aadhaar", "personal_identity"],
    },
    {
        "type":    "org_credentials",
        "content": lambda: (
            f"org:{random.choice(DEMO_ORGS)} | vpn_user:{_fake_email()} "
            f"| vpn_pass:{_fake_pass()} | internal_ip:192.168.{random.randint(1,254)}.{random.randint(1,254)}"
        ),
        "tags":    ["vpn_credentials", "organization", "internal_network"],
    },
    {
        "type":    "email_only",
        "content": lambda: "\n".join([_fake_email() for _ in range(random.randint(5, 15))]),
        "tags":    ["email"],
    },
    {
        "type":    "personal_identity",
        "content": lambda: (
            f"name:{_fake_name()} | phone:{_fake_phone()} | pan:{_fake_pan()} "
            f"| email:{_fake_email()} | address:{_fake_address()}"
        ),
        "tags":    ["personal_identity", "phone", "pan"],
    },
    {
        "type":    "full_combo",
        "content": lambda: (
            f"email:{_fake_email()} | pass:{_fake_pass()} | aadhaar:{_fake_aadhaar()} "
            f"| card:{_fake_card()} | cvv:{random.randint(100,999)} | bank:HDFC"
        ),
        "tags":    ["email", "password", "aadhaar", "credit_card", "bank_account"],
    },
]


# ─── Fake Data Generators ─────────────────────────────────────────────────────

def _fake_email():
    users  = ["john.doe","priya.sharma","rahul.k","ananya.m","alex.t","riya.s","kumar.r"]
    doms   = ["gmail.com","yahoo.com","rediffmail.com","outlook.com","hotmail.com"]
    return f"{random.choice(users)}{random.randint(10,999)}@{random.choice(doms)}"

def _fake_pass():
    chars = string.ascii_letters + string.digits + "!@#$"
    return ''.join(random.choices(chars, k=random.randint(8, 14)))

def _fake_name():
    firsts = ["Rahul","Priya","Ananya","Kumar","Riya","Arjun","Divya","Suresh","Meera","Arun"]
    lasts  = ["Sharma","Verma","Patel","Singh","Kumar","Nair","Reddy","Iyer","Das","Gupta"]
    return f"{random.choice(firsts)} {random.choice(lasts)}"

def _fake_aadhaar():
    return f"{''.join([str(random.randint(0,9)) for _ in range(4)])} " \
           f"{''.join([str(random.randint(0,9)) for _ in range(4)])} " \
           f"{''.join([str(random.randint(0,9)) for _ in range(4)])}"

def _fake_acct():
    return ''.join([str(random.randint(0,9)) for _ in range(12)])

def _fake_card():
    return f"4{random.randint(100,999)}-{random.randint(1000,9999)}-{random.randint(1000,9999)}-{random.randint(1000,9999)}"

def _fake_ifsc():
    codes = ["SBIN","HDFC","ICIC","UTIB","KKBK"]
    return f"{random.choice(codes)}0{random.randint(100000,999999)}"

def _fake_pan():
    letters = string.ascii_uppercase
    return f"{''.join(random.choices(letters,k=5))}{random.randint(1000,9999)}{''.join(random.choices(letters,k=1))}"

def _fake_phone():
    return f"+91-{random.randint(7000000000,9999999999)}"

def _fake_dob():
    y = random.randint(1970, 2002)
    m = random.randint(1, 12)
    d = random.randint(1, 28)
    return f"{d:02d}/{m:02d}/{y}"

def _fake_address():
    streets = ["MG Road","Anna Nagar","Banjara Hills","Koramangala","Connaught Place"]
    cities  = ["Mumbai","Chennai","Hyderabad","Bangalore","Delhi","Pune","Kolkata"]
    return f"{random.randint(1,500)}, {random.choice(streets)}, {random.choice(cities)}"


# ─── Core Functions ───────────────────────────────────────────────────────────

def connect_tor():
    """
    Purpose : Safe academic Tor routing configuration.
    Note    : In a real deployment, this configures a SOCKS5 proxy through
              the Tor network (127.0.0.1:9050). For this academic demo,
              we simulate the connection handshake.

    Returns : dict with connection status and details
    """
    return {
        "connected"   : True,
        "proxy"       : "127.0.0.1:9050",
        "circuit"     : "DEMO-ACADEMIC-MODE",
        "entry_node"  : "Simulated",
        "exit_node"   : "Simulated",
        "timestamp"   : datetime.now().isoformat(),
        "note"        : "Academic simulation mode — no real Tor connection made"
    }


def fetch_darkweb_data():
    """
    Purpose : Simulate dark web leak monitoring using synthetic demo sources.
    Logic   : Randomly selects leak templates and generates realistic-looking
              synthetic leaked records across multiple source types.

    Returns : list of dicts with keys:
              source, source_trust, content, tags, timestamp
    """
    results     = []
    num_sources = random.randint(4, 8)
    sources     = random.sample(DEMO_SOURCES, min(num_sources, len(DEMO_SOURCES)))

    for src in sources:
        num_leaks = random.randint(1, 4)
        for _ in range(num_leaks):
            template = random.choice(LEAK_TEMPLATES)
            content  = template["content"]()
            # Simulate time jitter — leaks have varying timestamps
            jitter   = timedelta(minutes=random.randint(0, 120))
            ts       = (datetime.now() - jitter).strftime("%Y-%m-%d %H:%M:%S")

            results.append({
                "source"      : src["name"],
                "source_trust": src["trust"],
                "category"    : src["category"],
                "leak_type"   : template["type"],
                "content"     : content,
                "tags"        : template["tags"],
                "timestamp"   : ts,
                "hash"        : hashlib.md5(content.encode()).hexdigest()[:12],
            })

    return results


def store_raw_findings(scan_id, item, detected, severity, score, alert):
    """
    Purpose : Persist scan findings to the SQLite database.
    Params  :
        scan_id  - unique scan identifier
        item     - raw crawl result dict
        detected - threat detection result dict
        severity - classified severity string
        score    - AI risk score (0-100)
        alert    - generated alert message
    """
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute("""
        INSERT INTO scan_results
            (scan_id, source, data_type, sample_data, severity, risk_score, alert_msg, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        item["source"],
        ",".join(detected["types"]),
        item["content"][:300],   # store first 300 chars only
        severity,
        score,
        alert,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    ))
    conn.commit()
    conn.close()
