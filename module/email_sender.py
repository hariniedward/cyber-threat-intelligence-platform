"""
=============================================================================
Module      : email_sender.py
Purpose     : Email Notification and Report Delivery System
Description : Sends threat intelligence reports via SMTP with PDF/Excel
              attachments. Supports Gmail SMTP with TLS encryption.
=============================================================================
"""

import smtplib
import sqlite3
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text       import MIMEText
from email.mime.base       import MIMEBase
from email              import encoders
from datetime           import datetime

DB_PATH = "database.db"


def _get_setting(key):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key=?", (key,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else ""


def send_email_report(recipient: str, attachment_path: str = None) -> dict:
    """
    Purpose : Send threat intelligence report via SMTP.
    Params  :
        recipient       — destination email address
        attachment_path — optional path to PDF/Excel attachment
    Returns : dict {status, message}
    """
    smtp_host = _get_setting("smtp_host") or "smtp.gmail.com"
    smtp_port = int(_get_setting("smtp_port") or 587)
    smtp_user = _get_setting("smtp_user")
    smtp_pass = _get_setting("smtp_pass")

    if not smtp_user or not smtp_pass:
        return {
            "status":  "error",
            "message": "SMTP credentials not configured. Please set them in Settings panel."
        }

    # Build email
    msg             = MIMEMultipart("alternative")
    msg["From"]     = smtp_user
    msg["To"]       = recipient
    msg["Subject"]  = f"[CTI Alert] Threat Intelligence Report — {datetime.now().strftime('%d %b %Y')}"

    body_html = f"""
    <html><body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:20px;">
      <div style="max-width:600px;margin:auto;background:#fff;border-radius:8px;overflow:hidden;">
        <div style="background:#0f1428;padding:20px;text-align:center;">
          <h1 style="color:#00d4aa;margin:0;font-size:22px;">CYBER THREAT INTELLIGENCE PLATFORM</h1>
          <p style="color:#aaa;margin:5px 0 0;">Automated Threat Alert</p>
        </div>
        <div style="padding:25px;">
          <h2 style="color:#0f1428;">⚠️ Threat Intelligence Report</h2>
          <p>A new threat scan has completed. Please review the attached report for full details.</p>
          <p><b>Report Generated:</b> {datetime.now().strftime('%d %B %Y, %H:%M:%S IST')}</p>
          <hr/>
          <h3>Immediate Actions Required:</h3>
          <ol>
            <li>Review all Critical and High severity findings.</li>
            <li>Change compromised credentials immediately.</li>
            <li>Notify affected users and stakeholders.</li>
            <li>File a cybercrime complaint if necessary.</li>
          </ol>
          <hr/>
          <p style="font-size:12px;color:#888;">
            Report Cybercrime: <a href="https://cybercrime.gov.in">cybercrime.gov.in</a> |
            CERT-In: <a href="mailto:incident@cert-in.org.in">incident@cert-in.org.in</a>
          </p>
        </div>
      </div>
    </body></html>
    """

    msg.attach(MIMEText(body_html, "html"))

    # Attach file if provided
    if attachment_path and os.path.exists(attachment_path):
        with open(attachment_path, "rb") as f:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f"attachment; filename={os.path.basename(attachment_path)}")
        msg.attach(part)

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        return {"status": "success", "message": f"Report sent to {recipient}"}
    except Exception as e:
        return {"status": "error", "message": f"SMTP Error: {str(e)}"}


def attach_pdf(msg, path):
    return _attach_file(msg, path)

def attach_excel(msg, path):
    return _attach_file(msg, path)

def _attach_file(msg, path):
    if not os.path.exists(path):
        return False
    with open(path, "rb") as f:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(f.read())
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", f"attachment; filename={os.path.basename(path)}")
    msg.attach(part)
    return True
