"""
ai_analyzer.py — Groq LLM analysis engine for NmapAI Intelligence Scanner

Sends structured Nmap results to Groq (qwen/qwen3-32b) and returns a
professional, structured cybersecurity assessment.
"""

import json
from typing import Optional
from groq import Groq, APIConnectionError, RateLimitError, APIStatusError
from config import GROQ_API_KEY, GROQ_MODEL, GROQ_MAX_TOKENS, GROQ_TEMPERATURE
from nmap_parser import flatten_open_ports
from utils import setup_logger, extract_risk_score, get_risk_label

logger = setup_logger("ai_analyzer")


# ─── Exceptions ───────────────────────────────────────────────────────────────
class AnalysisError(RuntimeError):
    """Raised when the AI analysis pipeline fails."""


# ─── Prompt Engineering ───────────────────────────────────────────────────────
SYSTEM_PROMPT = """\
You are NmapAI — a senior cybersecurity analyst and ethical hacker with 15+ years
of experience in network penetration testing, threat modelling, and security
architecture. You analyse Nmap scan results and produce professional, technically
precise, and actionable intelligence reports.

Your analysis style mirrors an elite red-team / SOC hybrid: you think like an
attacker but communicate like a CISO. Reports are concise, structured, and
directly useful to both technical engineers and executive stakeholders.

NEVER produce generic boilerplate. Every insight must be grounded in the actual
data supplied. If a service is present, reason about it specifically.

Always respond in this exact structured format:

---
## 🛡️ EXECUTIVE SUMMARY
[2-4 sentences — high-level risk posture for the target]

## 🔌 OPEN PORT & SERVICE ANALYSIS
[For each open port, one paragraph covering: what the service is, why it matters
from a security standpoint, observed version risk (if version data is present)]

## 🎯 ATTACK SURFACE ASSESSMENT
[Enumerate the realistic attack vectors an adversary could exploit given the
discovered services. Be specific: e.g., "FTP on port 21 supports anonymous login
attempts and plaintext credential interception via MITM."]

## ⚠️ MISCONFIGURATION INDICATORS
[List any configuration red flags, unsafe defaults, or deprecated protocols
visible in the scan data — or note "None detected" if clean.]

## 📊 RISK SCORE
Risk Score: [NUMBER]/100
Risk Level: [Low | Medium | High | Critical]
Justification: [1-2 sentences explaining the score]

## 🔧 REMEDIATION RECOMMENDATIONS
[Numbered, prioritised list of specific hardening actions. Include port/service
references and concrete steps, not vague advice.]

## 🔵 BLUE TEAM / SOC NOTES
[Detection opportunities, log sources to monitor, alerting rules, and defensive
countermeasures relevant to what was observed.]

## 📋 COMPLIANCE & BEST PRACTICE OBSERVATIONS
[Relevant compliance notes — PCI-DSS, CIS benchmarks, NIST CSF, ISO 27001 —
where applicable to the observed services.]
---
"""


def _build_user_prompt(parsed: dict, scan_meta: dict) -> str:
    """Construct the user message with structured scan data."""

    target     = scan_meta.get("target", "Unknown")
    scan_type  = scan_meta.get("scan_type", "Unknown")
    duration   = scan_meta.get("duration_seconds", "?")
    timestamp  = scan_meta.get("timestamp", "?")
    nmap_ver   = scan_meta.get("nmap_version", "?")

    flat_ports = flatten_open_ports(parsed)
    host_count = parsed.get("host_count", 0)
    open_total = parsed.get("open_port_count", 0)
    stats      = parsed.get("stats", {})

    # Build a concise but complete port table for the LLM
    port_table_lines = ["| Host | Port | Protocol | Service | Product | Version | CPE |",
                        "|------|------|----------|---------|---------|---------|-----|"]
    for row in flat_ports[:60]:   # Cap at 60 rows to respect token budget
        port_table_lines.append(
            f"| {row['host']} | {row['port']} | {row['protocol']} "
            f"| {row['service']} | {row['product']} | {row['version']} "
            f"| {row['cpe']} |"
        )
    port_table = "\n".join(port_table_lines) if flat_ports else "No open ports detected."

    # OS detection summary
    os_lines = []
    for host in parsed.get("hosts", []):
        if host["os"]["detected"]:
            os_lines.append(
                f"  - {host['ip']}: {host['os']['best_match']} "
                f"(accuracy: {host['os']['best_accuracy']}%)"
            )
    os_section = "\n".join(os_lines) if os_lines else "  OS detection not available."

    # Script output (abbreviated)
    script_lines = []
    for host in parsed.get("hosts", []):
        for port in host.get("open_ports", []):
            for sc in port.get("scripts", [])[:3]:
                script_lines.append(
                    f"  [{host['ip']}:{port['port']}] {sc['id']}: "
                    f"{sc['output'][:150]}"
                )
    script_section = "\n".join(script_lines[:10]) if script_lines else "  No script results."

    prompt = f"""
SCAN METADATA
=============
Target:         {target}
Scan Type:      {scan_type}
Timestamp:      {timestamp}
Duration:       {duration}s
Nmap Version:   {nmap_ver}
Hosts Scanned:  {stats.get('hosts_total', '?')}
Hosts Up:       {stats.get('hosts_up', host_count)}
Total Open Ports Discovered: {open_total}

OPEN PORTS TABLE
================
{port_table}

OS DETECTION RESULTS
====================
{os_section}

NSE SCRIPT OUTPUT (sample)
===========================
{script_section}

---
Please produce a full professional security analysis of the above scan data.
Ground every finding in the actual data above — do not invent ports or services.
"""
    return prompt.strip()


# ─── Analyzer Class ───────────────────────────────────────────────────────────
class GroqAnalyzer:
    """
    Orchestrates prompt construction, Groq API calls, and response parsing
    for a single Nmap scan result.
    """

    def __init__(self, api_key: Optional[str] = None) -> None:
        key = api_key or GROQ_API_KEY
        if not key:
            raise AnalysisError(
                "GROQ_API_KEY is not set. "
                "Add it to your .env file or set the environment variable."
            )
        self._client = Groq(api_key=key)

    def analyze(self, parsed: dict, scan_meta: dict) -> dict:
        """
        Run AI analysis on parsed Nmap data.

        Returns:
        {
            "raw_response": str,         # Full LLM markdown response
            "risk_score": int,           # Parsed numeric score 0-100
            "risk_label": str,           # Low / Medium / High / Critical
            "model": str,
            "tokens_used": int,
            "prompt_tokens": int,
            "completion_tokens": int,
        }
        """
        user_msg = _build_user_prompt(parsed, scan_meta)

        logger.info("Sending scan data to Groq (%s)…", GROQ_MODEL)
        logger.debug("Prompt length: %d chars", len(user_msg))

        try:
            response = self._client.chat.completions.create(
                model=GROQ_MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": user_msg},
                ],
                max_tokens=GROQ_MAX_TOKENS,
                temperature=GROQ_TEMPERATURE,
                stream=False,
            )
        except APIConnectionError as exc:
            raise AnalysisError(f"Cannot reach Groq API: {exc}") from exc
        except RateLimitError as exc:
            raise AnalysisError(
                "Groq rate limit exceeded. Wait a moment and try again."
            ) from exc
        except APIStatusError as exc:
            raise AnalysisError(
                f"Groq API error {exc.status_code}: {exc.message}"
            ) from exc
        except Exception as exc:
            logger.exception("Unexpected Groq error: %s", exc)
            raise AnalysisError(f"AI analysis failed: {exc}") from exc

        raw = response.choices[0].message.content or ""
        usage = response.usage

        score = extract_risk_score(raw)
        label = get_risk_label(score)

        logger.info(
            "AI analysis complete. Risk score: %d (%s). Tokens used: %d",
            score, label, usage.total_tokens if usage else 0,
        )

        return {
            "raw_response":       raw,
            "risk_score":         score,
            "risk_label":         label,
            "model":              GROQ_MODEL,
            "tokens_used":        usage.total_tokens if usage else 0,
            "prompt_tokens":      usage.prompt_tokens if usage else 0,
            "completion_tokens":  usage.completion_tokens if usage else 0,
        }