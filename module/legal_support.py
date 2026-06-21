"""
=============================================================================
Module      : legal_support.py
Purpose     : Legal Complaint Support and Documentation System
Description : Provides structured legal guidance, complaint templates, FIR
              preparation, and evidence checklists aligned with Indian cyber
              law (IT Act 2000, DPDP Act 2023, IPC sections).
=============================================================================
"""

from datetime import datetime


def get_complaint_template() -> dict:
    return {
        "title": "Cybercrime Complaint Template",
        "portal": "https://cybercrime.gov.in",
        "cert_in": "https://www.cert-in.org.in",
        "cert_email": "incident@cert-in.org.in",
        "helpline": "1800-11-4949",
        "sections": [
            {
                "name": "Complainant Details",
                "fields": ["Full Name", "Address", "Phone Number", "Email ID", "Aadhaar Number (last 4 digits)"]
            },
            {
                "name": "Incident Details",
                "fields": [
                    "Date and Time of Incident",
                    "Type of Cybercrime (Data Breach / Identity Theft / Financial Fraud)",
                    "Platform/Website involved",
                    "Brief description of incident",
                    "Financial loss (if any)"
                ]
            },
            {
                "name": "Evidence Details",
                "fields": [
                    "Screenshots of leak",
                    "URLs where data was found",
                    "Email/message evidence",
                    "Transaction records (if financial fraud)",
                    "System logs"
                ]
            }
        ],
        "applicable_laws": [
            {"section": "IT Act 2000 — Section 43A", "desc": "Compensation for failure to protect sensitive personal data"},
            {"section": "IT Act 2000 — Section 66",  "desc": "Computer related offences — up to 3 years imprisonment"},
            {"section": "IT Act 2000 — Section 66C", "desc": "Identity theft — up to 3 years + fine"},
            {"section": "IT Act 2000 — Section 66D", "desc": "Cheating by personation using computer — up to 3 years"},
            {"section": "IT Act 2000 — Section 72A", "desc": "Disclosure of information in breach of lawful contract"},
            {"section": "DPDP Act 2023 — Section 8", "desc": "Obligations of data fiduciary to protect personal data"},
            {"section": "IPC Section 420",            "desc": "Cheating and dishonestly inducing delivery of property"},
            {"section": "IPC Section 468",            "desc": "Forgery for purpose of cheating"},
        ],
        "fir_steps": [
            "Step 1: Document all evidence — screenshots, URLs, emails.",
            "Step 2: Visit cybercrime.gov.in and register complaint online.",
            "Step 3: Note your complaint reference number.",
            "Step 4: Visit nearest police station with printed complaint.",
            "Step 5: Request FIR under IT Act Section 66/66C as applicable.",
            "Step 6: Simultaneously report to CERT-In via email.",
            "Step 7: Consult a cybercrime attorney for legal proceedings.",
            "Step 8: Follow up with police within 7 working days.",
        ]
    }


def get_evidence_checklist() -> list:
    return [
        {"item": "Screenshots of leaked data on dark web / paste site",     "priority": "Essential"},
        {"item": "Full URL(s) where leaked data was discovered",             "priority": "Essential"},
        {"item": "Timestamp and date of discovery",                          "priority": "Essential"},
        {"item": "Type of data leaked (email, password, Aadhaar, bank)",    "priority": "Essential"},
        {"item": "Platform/organization affected by the breach",             "priority": "Essential"},
        {"item": "CTI Platform scan report (PDF/Excel)",                     "priority": "Essential"},
        {"item": "Browser activity logs or network capture (PCAP)",          "priority": "High"},
        {"item": "Email/message evidence of threat actors",                  "priority": "High"},
        {"item": "Financial transaction records (if monetary loss)",         "priority": "High"},
        {"item": "Identity documents (Aadhaar, PAN for verification)",       "priority": "Medium"},
        {"item": "Notarized copy of complaint",                              "priority": "Medium"},
        {"item": "Cyber insurance policy documents (if applicable)",         "priority": "Low"},
    ]
