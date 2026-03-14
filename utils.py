"""
utils.py — Shared utility helpers for NmapAI Intelligence Scanner
"""

import re
import socket
import ipaddress
import logging
import os
from datetime import datetime
from config import LOG_LEVEL, LOG_FILE, RISK_THRESHOLDS, RISK_COLORS


# ─── Logging Setup ────────────────────────────────────────────────────────────
def setup_logger(name: str = "nmap_ai") -> logging.Logger:
    """Configure and return a named logger with file + stream handlers."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # Already configured

    logger.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))

    fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Stream handler
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    # File handler
    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger


logger = setup_logger()


# ─── Input Validation ─────────────────────────────────────────────────────────
def validate_target(target: str) -> tuple[bool, str]:
    """
    Validate that the target is a legitimate IP, domain, or CIDR subnet.
    Returns (is_valid, error_message).
    """
    target = target.strip()

    if not target:
        return False, "Target cannot be empty."

    # Block obviously malicious shell characters
    forbidden = set(";|&`$(){}\\<>")
    if any(c in target for c in forbidden):
        return False, f"Target contains forbidden characters: {forbidden & set(target)}"

    # CIDR notation
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.prefixlen < 24:
            return False, (
                f"Subnet /{net.prefixlen} is too broad. "
                "Use /24 or smaller to prevent unintended mass scanning."
            )
        return True, ""
    except ValueError:
        pass

    # Plain IP
    try:
        ipaddress.ip_address(target)
        return True, ""
    except ValueError:
        pass

    # Hostname / domain — must be valid DNS label pattern
    domain_re = re.compile(
        r"^(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}$"
    )
    if domain_re.match(target):
        return True, ""

    # Single-label hostname (e.g. "localhost")
    if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?$", target):
        return True, ""

    return False, f"'{target}' is not a valid IP address, hostname, or CIDR range."


def validate_port_range(port_range: str) -> tuple[bool, str]:
    """Validate a port range string like '1-1024' or '80,443,8080'."""
    port_range = port_range.strip()
    if not port_range:
        return False, "Port range cannot be empty."

    # Allow comma-separated ports and dash ranges
    if not re.match(r"^[\d,\-\s]+$", port_range):
        return False, "Port range must only contain digits, commas, and hyphens."

    # Check individual port numbers
    parts = re.split(r"[,\s]+", port_range)
    for part in parts:
        if "-" in part:
            bounds = part.split("-")
            if len(bounds) != 2:
                return False, f"Invalid range segment: '{part}'"
            try:
                lo, hi = int(bounds[0]), int(bounds[1])
                if not (1 <= lo <= 65535 and 1 <= hi <= 65535 and lo <= hi):
                    return False, f"Port range {lo}-{hi} is out of bounds (1-65535)."
            except ValueError:
                return False, f"Non-numeric values in range: '{part}'"
        else:
            try:
                p = int(part)
                if not 1 <= p <= 65535:
                    return False, f"Port {p} is out of bounds (1-65535)."
            except ValueError:
                return False, f"Invalid port value: '{part}'"

    return True, ""


# ─── Risk Scoring ─────────────────────────────────────────────────────────────
def get_risk_label(score: int) -> str:
    """Map a numeric risk score (0-100) to a label."""
    for label, (lo, hi) in RISK_THRESHOLDS.items():
        if lo <= score <= hi:
            return label
    return "Unknown"


def get_risk_color(label: str) -> str:
    """Return hex color for a risk label."""
    return RISK_COLORS.get(label, "#8E8E93")


def extract_risk_score(ai_text: str) -> int:
    """
    Parse the numeric risk score from the LLM's response.
    Looks for patterns like 'Risk Score: 72' or 'score of 72/100'.
    """
    patterns = [
        r"risk\s+score[:\s]+(\d{1,3})",
        r"score\s+of\s+(\d{1,3})\s*/\s*100",
        r"score[:\s]+(\d{1,3})\s*/\s*100",
        r"overall\s+risk[:\s]+(\d{1,3})",
        r"\b(\d{1,3})\s*/\s*100\b",
    ]
    for pat in patterns:
        m = re.search(pat, ai_text, re.IGNORECASE)
        if m:
            val = int(m.group(1))
            if 0 <= val <= 100:
                return val
    return 0


# ─── Formatting Helpers ───────────────────────────────────────────────────────
def now_str(fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    return datetime.now().strftime(fmt)


def now_filename(prefix: str = "scan") -> str:
    """Return a safe filename with timestamp."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{ts}"


def safe_mkdir(path: str) -> None:
    """Create directory if it doesn't exist."""
    os.makedirs(path, exist_ok=True)


def truncate(text: str, max_chars: int = 120) -> str:
    """Truncate a string for display purposes."""
    return text if len(text) <= max_chars else text[: max_chars - 3] + "..."
