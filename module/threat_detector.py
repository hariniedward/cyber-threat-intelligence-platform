"""
=============================================================================
Module      : threat_detector.py
Purpose     : AI-Based Threat Detection and Classification Engine
Description : Implements heuristic pattern matching combined with a weighted
              multi-factor risk scoring algorithm to detect, classify, and
              alert on sensitive data leaks.

Algorithm   : Weighted Severity Index (WSI)
              score = Σ(weight_i × factor_i) normalized to 0–100
              Factors: data_type_weight, source_trust, volume, combination_risk
=============================================================================
"""

import re
import random
from datetime import datetime

# ─── Pattern Registry ─────────────────────────────────────────────────────────
# Each entry: (label, regex_pattern, base_weight, description)

PATTERNS = [
    ("email",           r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",          5,  "Email address"),
    ("password",        r"(?:pass(?:word)?|pwd)\s*[:=]\s*\S+",                        20, "Password credential"),
    ("aadhaar",         r"\b\d{4}\s?\d{4}\s?\d{4}\b",                                30, "Aadhaar number (12-digit)"),
    ("pan",             r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",                                25, "PAN card number"),
    ("credit_card",     r"\b(?:\d[ -]?){13,16}\b",                                   35, "Credit/Debit card number"),
    ("cvv",             r"\bcvv\s*[:=]\s*\d{3,4}\b",                                 25, "CVV code"),
    ("bank_account",    r"(?:acct|account)\s*[:=]\s*\d{9,18}",                       30, "Bank account number"),
    ("ifsc",            r"\b[A-Z]{4}0[A-Z0-9]{6}\b",                                 20, "IFSC bank code"),
    ("phone",           r"(?:\+91[-\s]?)?[6-9]\d{9}",                                15, "Indian phone number"),
    ("vpn_credentials", r"(?:vpn_user|vpn_pass|internal_ip)\s*[:=]\s*\S+",           35, "VPN/Internal credentials"),
    ("organization",    r"org\s*[:=]\s*[^\|]+",                                       10, "Organization reference"),
    ("personal_identity",r"(?:name|dob|addr(?:ess)?)\s*[:=]\s*[^\|]+",              20, "PII data field"),
    ("internal_network",r"192\.168\.\d{1,3}\.\d{1,3}",                               25, "Internal network IP"),
]

# ─── Severity Matrix ──────────────────────────────────────────────────────────
# Maps combinations of data types → severity level
# Ordered from most to least critical

SEVERITY_RULES = [
    # (required_types_subset, severity)
    ({"password", "bank_account"},                          "Critical"),
    ({"password", "credit_card"},                          "Critical"),
    ({"aadhaar", "credit_card"},                           "Critical"),
    ({"aadhaar", "bank_account"},                          "Critical"),
    ({"vpn_credentials", "internal_network"},              "Critical"),
    ({"password", "aadhaar"},                              "Critical"),
    ({"email", "password", "aadhaar"},                     "Critical"),
    ({"bank_account", "cvv", "credit_card"},               "Critical"),
    ({"aadhaar"},                                          "High"),
    ({"bank_account"},                                     "High"),
    ({"credit_card"},                                      "High"),
    ({"vpn_credentials"},                                  "High"),
    ({"password", "personal_identity"},                    "High"),
    ({"pan", "personal_identity"},                         "High"),
    ({"password", "email"},                                "Medium"),
    ({"pan"},                                              "Medium"),
    ({"phone", "personal_identity"},                       "Medium"),
    ({"internal_network"},                                 "Medium"),
    ({"email"},                                            "Low"),
    ({"organization"},                                     "Low"),
]

# Weight map for AI risk scoring
TYPE_WEIGHTS = {
    "email":            5,
    "password":         20,
    "aadhaar":          35,
    "pan":              25,
    "credit_card":      30,
    "cvv":              20,
    "bank_account":     30,
    "ifsc":             10,
    "phone":            10,
    "vpn_credentials":  35,
    "organization":     8,
    "personal_identity":15,
    "internal_network": 20,
}


# ─── Core Detection Functions ─────────────────────────────────────────────────

def detect_sensitive_data(text: str) -> dict:
    """
    Purpose : Scan raw text for sensitive data patterns using regex matching.
    Params  : text — raw string from leak source
    Returns : dict {
                found:   bool,
                types:   list[str],
                matches: dict{type: [matched_values]},
                count:   int
              }
    """
    found_types = []
    match_details = {}

    for label, pattern, weight, desc in PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            if label not in found_types:
                found_types.append(label)
            match_details[label] = matches[:3]   # store up to 3 samples

    # Cross-validate: if 'tags' key was added upstream, honor it
    return {
        "found":   len(found_types) > 0,
        "types":   found_types,
        "matches": match_details,
        "count":   len(found_types),
    }


def classify_severity(data_types: list) -> str:
    """
    Purpose : Classify threat severity based on combination of detected data types.
    Logic   : Applies SEVERITY_RULES in priority order. Returns highest matching level.
    Params  : data_types — list of detected sensitive data type labels
    Returns : "Critical" | "High" | "Medium" | "Low"
    """
    type_set = set(data_types)
    for required_set, severity in SEVERITY_RULES:
        if required_set.issubset(type_set):
            return severity
    return "Low"


def ai_risk_score(data_types: list, source_trust: int = 5) -> int:
    """
    Purpose : Calculate AI-based risk score using Weighted Severity Index (WSI).

    Algorithm:
        base_score    = Σ(TYPE_WEIGHTS[t]) for t in data_types
        combo_bonus   = (count of types - 1) × 5   # combination risk multiplier
        trust_penalty = (10 - source_trust) × 2    # lower trust = higher risk
        raw_score     = base_score + combo_bonus + trust_penalty
        final_score   = min(100, raw_score)

    Params  :
        data_types   — list of detected sensitive data types
        source_trust — source reliability (1=very low, 10=very high)
    Returns : int in range [0, 100]
    """
    if not data_types:
        return 0

    base_score    = sum(TYPE_WEIGHTS.get(t, 5) for t in data_types)
    combo_bonus   = max(0, (len(data_types) - 1)) * 5
    trust_penalty = (10 - min(max(source_trust, 1), 10)) * 2

    raw_score = base_score + combo_bonus + trust_penalty
    return min(100, raw_score)


def generate_alert(severity: str, data_types: list) -> str:
    """
    Purpose : Generate a professional threat alert message.
    Params  :
        severity   — severity level string
        data_types — list of detected data type labels
    Returns : Formatted alert string
    """
    types_str = ", ".join([t.replace("_", " ").title() for t in data_types])
    ts        = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    templates = {
        "Critical": (
            f"[🔴 CRITICAL ALERT] [{ts}] "
            f"Highly sensitive data exposure detected: {types_str}. "
            f"Immediate containment required. Risk of financial fraud and identity theft is HIGH."
        ),
        "High": (
            f"[🟠 HIGH ALERT] [{ts}] "
            f"Sensitive data breach confirmed: {types_str}. "
            f"Urgent action needed. Notify security team and affected parties immediately."
        ),
        "Medium": (
            f"[🟡 MEDIUM ALERT] [{ts}] "
            f"Moderate data exposure detected: {types_str}. "
            f"Review affected accounts and enable additional authentication."
        ),
        "Low": (
            f"[🟢 LOW ALERT] [{ts}] "
            f"Minor data exposure: {types_str}. "
            f"Monitor for suspicious activity. No immediate action required."
        ),
    }

    return templates.get(severity, templates["Low"])


def get_recommendations(severity: str, data_types: list) -> list:
    """
    Purpose : Return actionable security recommendations based on severity and types.
    Returns : list of recommendation strings
    """
    recs = []

    if "password" in data_types:
        recs.append("Change all compromised passwords immediately and enable 2FA.")
    if "aadhaar" in data_types:
        recs.append("Lock your Aadhaar biometrics at resident.uidai.gov.in.")
    if "bank_account" in data_types or "credit_card" in data_types:
        recs.append("Contact your bank immediately. Request account freeze and new card.")
    if "pan" in data_types:
        recs.append("Monitor credit report and report PAN misuse to income tax department.")
    if "vpn_credentials" in data_types:
        recs.append("Revoke all VPN access tokens. Audit internal network access logs.")
    if "email" in data_types:
        recs.append("Enable 2FA on email. Scan for unauthorized logins in activity log.")
    if severity in ("Critical", "High"):
        recs.append("File a cybercrime complaint at cybercrime.gov.in.")
        recs.append("Report to CERT-In at incident@cert-in.org.in.")

    return recs
