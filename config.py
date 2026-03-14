"""
config.py — Central configuration for AI-Powered Nmap Intelligence Scanner
Author: NmapAI Project
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ─── Groq API ────────────────────────────────────────────────────────────────
GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL: str   = "qwen/qwen3-32b"
GROQ_MAX_TOKENS: int = 4096
GROQ_TEMPERATURE: float = 0.4

# ─── Scan Defaults ───────────────────────────────────────────────────────────
DEFAULT_TIMEOUT: int  = 300   # seconds
DEFAULT_PORT_RANGE: str = "1-1024"
MAX_SUBNET_MASK: int  = 24    # Minimum /24 to prevent scanning huge ranges

from typing import Dict

# ─── Scan Type Definitions ───────────────────────────────────────────────────
SCAN_TYPES: Dict[str, dict] = {
    "Quick Scan": {
        "args": "-T4 -F",
        "description": "Fast scan of most common 100 ports",
        "icon": "⚡",
    },
    "Full TCP Scan": {
        "args": "-T4 -p-",
        "description": "All 65535 TCP ports — thorough but slow",
        "icon": "🔍",
    },
    "Service Version Detection": {
        "args": "-T4 -sV -p {ports}",
        "description": "Identifies service name and version on open ports",
        "icon": "🔬",
    },
    "OS Detection": {
        "args": "-T4 -O -p {ports}",
        "description": "Attempts to identify the target operating system",
        "icon": "🖥️",
    },
    "Aggressive Scan": {
        "args": "-T4 -A -p {ports}",
        "description": "OS, version, script scanning, and traceroute",
        "icon": "💥",
    },
    "Custom Arguments": {
        "args": "",
        "description": "Specify your own Nmap flags",
        "icon": "⚙️",
    },
}

# ─── Report ───────────────────────────────────────────────────────────────────
REPORT_DIR: str  = "reports"
APP_TITLE: str   = "NmapAI Intelligence Scanner"
APP_VERSION: str = "1.0.0"
APP_TAGLINE: str = "AI-Powered Network Security Analysis"

# ─── Logging ──────────────────────────────────────────────────────────────────
LOG_LEVEL: str  = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE: str   = "nmap_ai.log"

# ─── Risk Score Thresholds ───────────────────────────────────────────────────
RISK_THRESHOLDS = {
    "Critical": (75, 100),
    "High":     (50, 74),
    "Medium":   (25, 49),
    "Low":      (0, 24),
}

RISK_COLORS = {
    "Critical": "#FF2D55",
    "High":     "#FF9F0A",
    "Medium":   "#FFD60A",
    "Low":      "#30D158",
}

# ─── Well-known Dangerous Services ───────────────────────────────────────────
HIGH_RISK_SERVICES = {
    "telnet", "ftp", "rsh", "rlogin", "rexec",
    "tftp", "finger", "snmp", "netbios-ssn", "ms-wbt-server",
}

MEDIUM_RISK_SERVICES = {
    "http", "smtp", "pop3", "imap", "vnc",
    "mysql", "postgresql", "mssql", "oracle", "redis",
    "mongodb", "elasticsearch", "memcache",
}