# 🛡️ Cyber Threat Intelligence Platform for Dark Web Data Leaks

> **AI-Based Cybersecurity Web Application — Portfolio / Resume Project**
> Built with Flask · SQLite · Bootstrap · Chart.js · fpdf2 · openpyxl

---

## 📌 What This Project Does

This platform simulates a real-world **dark web threat intelligence system** used by cybersecurity teams to:

| Feature | Description |
|---|---|
| 🔍 **Dark Web Scanning** | Crawls simulated leak sources (paste sites, forums, archives) |
| 🤖 **AI Risk Scoring** | Weighted Severity Index (WSI) scores threats 0–100 |
| 🚨 **Threat Detection** | 13-pattern regex engine detects emails, passwords, Aadhaar, PAN, bank data |
| 📊 **Live Dashboard** | Real-time stats, severity charts, risk meter |
| 📄 **Report Export** | PDF reports (fpdf2) + Excel workbooks (openpyxl) |
| 📧 **Email Alerts** | SMTP-based threat notifications with file attachments |
| ⚡ **Incident Response** | Step-by-step response guides per leak type |
| ⚖️ **Legal Complaint** | CERT-In / cybercrime.gov.in templates + FIR guide |
| ⚙️ **Settings Panel** | Admin credentials, SMTP config, scan sensitivity |

---

## 🗂️ Project Structure

```
CyberThreatPlatform/
│
├── app.py                      ← Main Flask application (routes, auth, API)
├── requirements.txt            ← Python dependencies
├── seed_data.py                ← One-time demo data seeder
├── database.db                 ← Auto-created SQLite database
│
├── modules/
│   ├── tor_crawler.py          ← Dark web data collection (academic simulation)
│   ├── threat_detector.py      ← AI threat detection + WSI risk scoring
│   ├── report_generator.py     ← PDF + Excel report generation
│   ├── email_sender.py         ← SMTP email with attachments
│   ├── legal_support.py        ← Legal templates + evidence checklist
│   └── export_module.py        ← Unified export interface
│
├── templates/
│   ├── base.html               ← Sidebar layout + topbar
│   ├── login.html              ← Admin login
│   ├── dashboard.html          ← Main dashboard with charts
│   ├── scan.html               ← Scan console with live terminal
│   ├── report.html             ← Full results table + export
│   ├── respond.html            ← Incident response guides
│   ├── legal.html              ← Legal complaint center
│   └── settings.html           ← System configuration
│
├── static/
│   ├── css/style.css           ← Full dark cyber theme (CSS variables)
│   └── js/main.js              ← Chart.js, scan engine, toast system
│
└── exports/
    ├── pdf/                    ← Generated PDF reports
    └── excel/                  ← Generated Excel reports
```

---

## ⚡ Quick Start (Step by Step)

### Step 1 — Clone / Download the project

```bash
cd Desktop
# If downloaded as zip, extract it
# Then:
cd CyberThreatPlatform
```

### Step 2 — Create a Python virtual environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

> **If pip fails for any package**, install individually:
> ```bash
> pip install flask fpdf2 openpyxl requests beautifulsoup4 pandas selenium
> ```

### Step 4 — Initialize the database and seed demo data

```bash
python app.py        # This auto-creates database.db on first run. Ctrl+C after 2 seconds.
python seed_data.py  # Populates 25 demo scan records so dashboard isn't empty
```

### Step 5 — Run the application

```bash
python app.py
```

You should see:
```
============================================================
  Cyber Threat Intelligence Platform
  Running at: http://127.0.0.1:5000
  Admin Login: admin / admin@123
============================================================
```

### Step 6 — Open in browser

```
http://127.0.0.1:5000
```

Login: **admin** / **admin@123**

---

## 🧪 Using the Platform

### Running a Scan
1. Click **Run Scan** in sidebar
2. Choose scan mode and sensitivity
3. Click **⚡ START SCAN**
4. Watch the live terminal output
5. Results are saved to database automatically

### Exporting Reports
- Click **Export PDF** → downloads `ThreatReport_TIMESTAMP.pdf`
- Click **Export Excel** → downloads `ThreatReport_TIMESTAMP.xlsx`
- Reports go to `exports/pdf/` and `exports/excel/`

### Sending Email Alerts
1. Go to **Settings** → fill SMTP credentials (use Gmail App Password)
2. From Dashboard → **Send Email** → enter recipient email
3. Report is emailed with HTML body

### Filing Legal Complaint
- Go to **Legal Complaint** page
- Copy the pre-filled complaint template
- Check the evidence checklist
- Click links to cybercrime.gov.in and CERT-In portal

---

## 🤖 AI Threat Detection — How It Works

### Pattern Detection Engine
The system scans raw text using 13 regex patterns:

```
Email          → regex: [a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+
Password       → regex: (?:pass(?:word)?|pwd)\s*[:=]\s*\S+
Aadhaar        → regex: \b\d{4}\s?\d{4}\s?\d{4}\b
PAN Card       → regex: \b[A-Z]{5}[0-9]{4}[A-Z]\b
Credit Card    → regex: \b(?:\d[ -]?){13,16}\b
Bank Account   → regex: (?:acct|account)\s*[:=]\s*\d{9,18}
... and 7 more
```

### Weighted Severity Index (WSI) Algorithm

```python
base_score    = Σ(TYPE_WEIGHTS[t])   for each detected type
combo_bonus   = (num_types - 1) × 5  # more data types = higher risk
trust_penalty = (10 - source_trust) × 2  # low trust source = higher risk
final_score   = min(100, base_score + combo_bonus + trust_penalty)
```

### Severity Classification Matrix

| Data Types Found | Severity |
|---|---|
| Password + Bank Account | 🔴 Critical |
| Aadhaar + Credit Card | 🔴 Critical |
| VPN Credentials + Internal IP | 🔴 Critical |
| Aadhaar alone | 🟠 High |
| Bank Account alone | 🟠 High |
| Email + Password | 🟡 Medium |
| Email only | 🟢 Low |

---

## 🗣️ Resume Talking Points

When explaining this project in an interview or viva:

**"What problem does this solve?"**
> Organizations need to monitor dark web sources for leaked credentials and sensitive data. This platform automates that monitoring, scores threats by severity, and guides teams through incident response — reducing the time between breach discovery and containment.

**"What AI/ML techniques did you use?"**
> I implemented a Weighted Severity Index (WSI) — a multi-factor scoring algorithm that weighs detected data types by their real-world risk (Aadhaar = 35, bank = 30, email = 5), adds a combination multiplier when multiple data types appear together, and penalises low-trust sources. The result is a 0–100 calibrated risk score.

**"Why Flask + SQLite?"**
> Flask is lightweight and gives full control over routing and API design — appropriate for a security application where you want minimal attack surface. SQLite is sufficient for a single-node deployment; in production this would migrate to PostgreSQL with encrypted fields.

**"How does the Tor integration work?"**
> The tor_crawler module is configured to route requests through a SOCKS5 proxy on 127.0.0.1:9050 — the standard Tor daemon endpoint. For this academic demo, connections are simulated so no real dark web is accessed. In a real deployment, the system would use stem (Python Tor controller) to build circuits to .onion paste sites.

**"What security best practices did you follow?"**
> Session-based auth with a secret key, no raw SQL string interpolation (parameterised queries throughout), credentials stored in the DB not in code, SMTP uses TLS (STARTTLS on port 587), and sensitive data in the database is truncated to 300 characters — never storing full leaked payloads.

**"What Indian cyber laws does this address?"**
> IT Act 2000 Section 43A (data protection liability), 66C (identity theft), the 2022 CERT-In mandatory 6-hour reporting rule, and the Digital Personal Data Protection Act 2023 — all explained in the Legal Complaint module.

---

## 📦 Technologies & Libraries

| Library | Purpose |
|---|---|
| Flask | Web framework, routing, sessions |
| SQLite3 | Persistent storage (stdlib) |
| fpdf2 | Professional PDF generation |
| openpyxl | Excel workbook creation with styling |
| Chart.js | Browser-side severity + risk charts |
| BeautifulSoup4 | HTML parsing for real crawl scenarios |
| Requests | HTTP client for source fetching |
| Selenium | Browser automation for JavaScript-rendered sources |
| Pandas | Data manipulation and analysis |
| smtplib | SMTP email (stdlib) |

---

## 🔒 Security & Ethics Notice

> **This platform uses 100% synthetic, algorithmically-generated demo data.**
> No real dark web sources are accessed. No real personal data is stored.
> All "leaked" records (emails, Aadhaar numbers, card numbers) are fake, generated
> by random string generators for educational demonstration only.
>
> This project is built for **academic and portfolio purposes** under responsible
> disclosure and ethical research principles.

---

## 📬 Legal Reporting Resources (India)

| Resource | Link |
|---|---|
| Cybercrime Complaint Portal | https://cybercrime.gov.in |
| CERT-In Official | https://www.cert-in.org.in |
| CERT-In Incident Email | incident@cert-in.org.in |
| CERT-In Helpline | 1800-11-4949 |
| Cyber Cell Emergency | 1930 |

---

*Built for cybersecurity portfolio and resume development.*
*Demonstrates: Flask web development · SQLite DB design · AI scoring algorithms · Security UI/UX · PDF/Excel automation · SMTP integration · Indian cyber law compliance*
