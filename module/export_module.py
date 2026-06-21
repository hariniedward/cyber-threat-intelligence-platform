"""
=============================================================================
Module      : export_module.py
Purpose     : Unified Export Interface
Description : Routes export requests to appropriate generators (PDF/Excel).
=============================================================================
"""

from modules.report_generator import generate_pdf_report, generate_excel_report
import sqlite3

DB_PATH = "database.db"


def export_report(report_type: str = "pdf") -> str:
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute("SELECT * FROM scan_results ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()

    if not rows:
        return ""

    if report_type == "excel":
        return generate_excel_report(rows)
    return generate_pdf_report(rows)
