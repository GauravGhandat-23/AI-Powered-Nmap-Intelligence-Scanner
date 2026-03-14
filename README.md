# 🛡️ NmapAI Intelligence Scanner

> **AI-Powered Network Security Analysis** — Groq · qwen/qwen3-32b · Streamlit

A production-grade cybersecurity web application that combines real Nmap network scanning with Groq LLM-powered analysis to generate professional, actionable security intelligence reports.

---

## ✨ Key Features

| Feature | Details |
|---|---|
| **6 Scan Modes** | Quick, Full TCP, Service Version, OS Detection, Aggressive, Custom |
| **AI Analysis** | Groq `qwen/qwen3-32b` generates structured security assessments |
| **Risk Scoring** | Numeric 0–100 score + Low/Medium/High/Critical label |
| **Report Export** | JSON, TXT, HTML (PDF optional via weasyprint) |
| **Professional UI** | Dark cyber theme, Space Mono typography, animated metrics |
| **Safe Architecture** | Input validation, no shell injection, disclaimer + consent gate |

---

## 📁 Project Structure

```
nmap_ai_scanner/
│
├── app.py                  # Streamlit main application + full UI
├── scanner.py              # Secure Nmap subprocess execution engine
├── parser.py               # Nmap XML → structured Python dict parser
├── ai_analyzer.py          # Groq API integration + prompt engineering
├── report_generator.py     # JSON / TXT / HTML / PDF report generation
├── utils.py                # Shared helpers: logging, validation, scoring
├── config.py               # Centralised configuration + constants
│
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

## ⚙️ Prerequisites

### 1. Python 3.10+

```bash
python --version
```

### 2. Nmap

| OS | Install Command |
|---|---|
| **Ubuntu / Debian** | `sudo apt install nmap` |
| **macOS** | `brew install nmap` |
| **Windows** | Download from [nmap.org/download.html](https://nmap.org/download.html) |
| **Fedora / RHEL** | `sudo dnf install nmap` |

> ⚠️ **Note:** OS Detection (`-O`) and some aggressive scans require root/Administrator privileges.
> On Linux/macOS: `sudo streamlit run app.py`
> On Windows: Run terminal as Administrator.

### 3. Groq API Key

Sign up at [console.groq.com](https://console.groq.com) and generate a free API key.

---

## 🚀 Installation & Setup

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/nmap-ai-scanner.git
cd nmap-ai-scanner

# 2. Create and activate a virtual environment
python -m venv venv

# Linux / macOS
source venv/bin/activate

# Windows (Command Prompt)
venv\Scripts\activate.bat

# Windows (PowerShell)
venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env and set GROQ_API_KEY=gsk_your_actual_key_here

# 5. Launch the app
streamlit run app.py
```

The app opens automatically at **http://localhost:8501**

---

## 🖥️ Usage Guide

1. **Enter Target** — IP address, domain name (e.g. `scanme.nmap.org`), or CIDR subnet (max /24)
2. **Select Scan Type** — Choose from the six scan modes in the sidebar
3. **Set Port Range** — Default is `1-1024`; use `1-65535` for full coverage
4. **Confirm Authorisation** — Check the disclaimer checkbox
5. **Launch Scan** — Click the 🚀 button
6. **Review Results** — Explore the tabbed interface: Ports · Charts · Raw Output · AI Analysis
7. **Download Reports** — Export in JSON, TXT, or HTML format

> ⚠️ **Always scan only systems you own or have written permission to test.**

---

## 🔐 Scan Types

| Scan | Nmap Args | Use Case |
|---|---|---|
| Quick Scan | `-T4 -F` | Fast 100-port overview |
| Full TCP | `-T4 -p-` | Complete port inventory |
| Service Version | `-T4 -sV` | Identify service software + versions |
| OS Detection | `-T4 -O` | Fingerprint operating system |
| Aggressive | `-T4 -A` | Version + OS + scripts + traceroute |
| Custom | User-defined | Advanced / specialised scanning |

---

## 🤖 AI Analysis Output Structure

The Groq `qwen/qwen3-32b` model produces a structured report with these sections:

1. **Executive Summary** — High-level risk posture overview
2. **Open Port & Service Analysis** — Security implications per service
3. **Attack Surface Assessment** — Realistic adversarial attack vectors
4. **Misconfiguration Indicators** — Unsafe defaults and deprecated protocols
5. **Risk Score** — Numeric 0–100 + Low/Medium/High/Critical label
6. **Remediation Recommendations** — Prioritised, specific hardening steps
7. **Blue Team / SOC Notes** — Detection rules and log monitoring guidance
8. **Compliance Observations** — PCI-DSS, CIS, NIST CSF, ISO 27001 notes

---

## 📄 Report Formats

| Format | Contents | Use Case |
|---|---|---|
| **JSON** | Full machine-readable data | API integration, further processing |
| **TXT** | Human-readable text report | Quick review, email attachment |
| **HTML** | Styled standalone web report | Client deliverables, archive |
| **PDF** | (Optional — requires weasyprint) | Formal documentation |

Enable PDF: `pip install weasyprint`

---

## 🔒 Security & Ethical Use

- **Input sanitisation** — Blocks shell injection characters (`; | & \` $ () {}``)
- **Subnet restriction** — Prevents scanning ranges larger than /24
- **Consent gate** — User must confirm authorisation before scanning
- **No hardcoded secrets** — All credentials via `.env`
- **Legal disclaimer** — Prominently displayed in the UI

> This tool is intended solely for **authorised security testing and education**.
> Scanning systems without explicit permission is illegal in most jurisdictions.

---

## 📦 Optional Enhancements

```bash
# PDF export
pip install weasyprint

# Enhanced port scanning (Python API — alternative to subprocess)
pip install python-nmap
```

---

## 🔮 Future Enhancements

- [ ] CVE lookup integration (NVD API / CIRCL CVE Search)
- [ ] MITRE ATT&CK TTP mapping per discovered service
- [ ] Shodan enrichment for public IP context
- [ ] Nmap script library browser
- [ ] Historical scan comparison (diff between runs)
- [ ] Multi-target batch scanning with queue
- [ ] Slack/Teams webhook for scan completion alerts
- [ ] Authenticated API mode for CI/CD pipeline integration
- [ ] CVSS score calculator widget
- [ ] Scan schedule / cron job support

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Frontend | Streamlit 1.35+ |
| AI Engine | Groq API — `qwen/qwen3-32b` |
| Scanner | Nmap (subprocess) |
| Language | Python 3.10+ |
| Reporting | Native Python (JSON/TXT/HTML) |
| Styling | Custom CSS (Space Mono + DM Sans) |

---

## 📜 Licence

MIT Licence — see `LICENSE` for details.

---

*Built as a final-year cybersecurity portfolio project demonstrating AI-augmented offensive security tooling.*
