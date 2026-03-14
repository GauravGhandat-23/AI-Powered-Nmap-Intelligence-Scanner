"""
report_generator.py — Multi-format report export engine for NmapAI

Supports: JSON, TXT, HTML
Optional: PDF (via weasyprint if installed)
"""

import json
import os
from typing import Union
from datetime import datetime
from config import APP_TITLE, APP_VERSION, REPORT_DIR
from utils import setup_logger, safe_mkdir, now_filename, get_risk_color

logger = setup_logger("report_gen")

# Optional PDF support
try:
    from weasyprint import HTML as WeasyprintHTML
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    logger.info("weasyprint not installed — PDF export disabled.")


# ─── Data Assembly ────────────────────────────────────────────────────────────
def assemble_report_data(
    scan_meta: dict,
    raw_xml: str,
    parsed: dict,
    ai_result: dict,
) -> dict:
    """Bundle all scan artefacts into a single serialisable report dict."""
    return {
        "report_meta": {
            "generator":   APP_TITLE,
            "version":     APP_VERSION,
            "generated_at": datetime.now().isoformat(),
        },
        "scan_meta":   scan_meta,
        "raw_xml":     raw_xml,
        "parsed_data": parsed,
        "ai_analysis": ai_result,
    }


# ─── JSON ─────────────────────────────────────────────────────────────────────
def generate_json_report(report_data: dict) -> str:
    """Return a pretty-printed JSON string of the full report."""
    return json.dumps(report_data, indent=2, default=str)


# ─── TXT ──────────────────────────────────────────────────────────────────────
def generate_txt_report(report_data: dict) -> str:
    """Return a human-readable plain-text report string."""
    meta  = report_data.get("scan_meta", {})
    ai    = report_data.get("ai_analysis", {})
    pdata = report_data.get("parsed_data", {})

    divider = "=" * 70
    thin    = "-" * 70

    lines = [
        divider,
        f"  {APP_TITLE} — Security Scan Report  (v{APP_VERSION})",
        divider,
        "",
        f"  Target      : {meta.get('target', 'N/A')}",
        f"  Scan Type   : {meta.get('scan_type', 'N/A')}",
        f"  Timestamp   : {meta.get('timestamp', 'N/A')}",
        f"  Duration    : {meta.get('duration_seconds', '?')}s",
        f"  Nmap Version: {meta.get('nmap_version', 'N/A')}",
        f"  Command     : {meta.get('command', 'N/A')}",
        "",
        thin,
        "  SCAN SUMMARY",
        thin,
        f"  Hosts Found : {pdata.get('host_count', 0)}",
        f"  Open Ports  : {pdata.get('open_port_count', 0)}",
        f"  Summary     : {pdata.get('summary', 'N/A')}",
        "",
    ]

    # Per-host detail
    for host in pdata.get("hosts", []):
        lines += [
            thin,
            f"  HOST: {host.get('ip', '?')}  [{host.get('status', '?').upper()}]",
            thin,
        ]
        if host.get("os", {}).get("detected"):
            lines.append(f"  OS : {host['os']['best_match']} ({host['os']['best_accuracy']}%)")

        for port in host.get("open_ports", []):
            svc = port.get("service", {})
            svc_str = (
                f"{svc.get('name','?')} {svc.get('product','')} {svc.get('version','')}".strip()
            )
            lines.append(
                f"  {port['port']}/{port['protocol']}  OPEN  {svc_str}"
            )
        lines.append("")

    # AI Analysis
    lines += [
        divider,
        "  AI-POWERED SECURITY ANALYSIS",
        divider,
        "",
        f"  Risk Score : {ai.get('risk_score', 'N/A')}/100",
        f"  Risk Level : {ai.get('risk_label', 'N/A')}",
        f"  Model      : {ai.get('model', 'N/A')}",
        f"  Tokens Used: {ai.get('tokens_used', 'N/A')}",
        "",
        ai.get("raw_response", "No AI analysis available."),
        "",
        divider,
        "  END OF REPORT",
        divider,
    ]

    return "\n".join(lines)


# ─── HTML ─────────────────────────────────────────────────────────────────────
def generate_html_report(report_data: dict) -> str:
    """Return a self-contained, styled HTML report string."""
    meta  = report_data.get("scan_meta", {})
    ai    = report_data.get("ai_analysis", {})
    pdata = report_data.get("parsed_data", {})

    risk_score = ai.get("risk_score", 0)
    risk_label = ai.get("risk_label", "Unknown")
    risk_color = get_risk_color(risk_label)

    # Convert AI markdown to basic HTML paragraphs
    ai_html = _md_to_basic_html(ai.get("raw_response", ""))

    # Port rows
    port_rows = ""
    for host in pdata.get("hosts", []):
        for port in host.get("open_ports", []):
            svc = port.get("service", {})
            svc_name = svc.get("name", "—")
            product  = f"{svc.get('product','')} {svc.get('version','')}".strip() or "—"
            port_rows += (
                f"<tr>"
                f"<td>{host.get('ip','?')}</td>"
                f"<td>{port['port']}</td>"
                f"<td>{port['protocol'].upper()}</td>"
                f"<td>{svc_name}</td>"
                f"<td>{product}</td>"
                f"</tr>"
            )

    hosts_up = pdata.get("stats", {}).get("hosts_up", pdata.get("host_count", 0))
    total_open = pdata.get("open_port_count", 0)
    generated_at = report_data.get("report_meta", {}).get("generated_at", "")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>{APP_TITLE} — Scan Report</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --muted: #8b949e; --accent: #58a6ff;
    --risk-color: {risk_color};
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif;
         font-size: 14px; line-height: 1.6; padding: 2rem; }}
  .header {{ border-bottom: 2px solid var(--accent); padding-bottom: 1rem; margin-bottom: 2rem; }}
  .header h1 {{ font-size: 1.8rem; color: var(--accent); }}
  .header p {{ color: var(--muted); font-size: .85rem; margin-top: .3rem; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 1rem; margin: 1.5rem 0; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; }}
  .card .label {{ color: var(--muted); font-size: .75rem; text-transform: uppercase; letter-spacing: .05em; }}
  .card .value {{ font-size: 1.4rem; font-weight: 700; margin-top: .25rem; }}
  .risk-badge {{ display: inline-block; background: var(--risk-color); color: #000;
                  padding: .3rem .9rem; border-radius: 20px; font-weight: 700;
                  font-size: .9rem; letter-spacing: .03em; }}
  section {{ margin: 2rem 0; }}
  section h2 {{ font-size: 1.1rem; color: var(--accent); border-left: 3px solid var(--accent);
                padding-left: .75rem; margin-bottom: 1rem; }}
  table {{ width: 100%; border-collapse: collapse; background: var(--surface);
           border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
  th {{ background: #1c2128; color: var(--muted); text-transform: uppercase;
        font-size: .75rem; padding: .6rem 1rem; text-align: left; }}
  td {{ padding: .55rem 1rem; border-bottom: 1px solid var(--border); }}
  tr:last-child td {{ border-bottom: none; }}
  .ai-block {{ background: var(--surface); border: 1px solid var(--border);
               border-radius: 8px; padding: 1.5rem; white-space: pre-wrap;
               font-family: 'Courier New', monospace; font-size: .82rem;
               color: var(--text); line-height: 1.8; }}
  .footer {{ margin-top: 3rem; border-top: 1px solid var(--border); padding-top: 1rem;
             color: var(--muted); font-size: .78rem; text-align: center; }}
  h2 span {{ font-size: 1rem; }}
</style>
</head>
<body>

<div class="header">
  <h1>🛡️ {APP_TITLE}</h1>
  <p>Professional Network Security Scan Report &nbsp;|&nbsp; Generated: {generated_at}</p>
</div>

<div class="grid">
  <div class="card">
    <div class="label">Target</div>
    <div class="value" style="font-size:1rem;">{meta.get('target','N/A')}</div>
  </div>
  <div class="card">
    <div class="label">Scan Type</div>
    <div class="value" style="font-size:1rem;">{meta.get('scan_type','N/A')}</div>
  </div>
  <div class="card">
    <div class="label">Hosts Up</div>
    <div class="value">{hosts_up}</div>
  </div>
  <div class="card">
    <div class="label">Open Ports</div>
    <div class="value">{total_open}</div>
  </div>
  <div class="card">
    <div class="label">Risk Score</div>
    <div class="value" style="color:{risk_color};">{risk_score}/100</div>
  </div>
  <div class="card">
    <div class="label">Risk Level</div>
    <div class="value"><span class="risk-badge">{risk_label}</span></div>
  </div>
</div>

<section>
  <h2><span>🔌</span> Discovered Open Ports</h2>
  <table>
    <thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>Service</th><th>Product / Version</th></tr></thead>
    <tbody>{port_rows or '<tr><td colspan="5" style="text-align:center;color:var(--muted)">No open ports detected</td></tr>'}</tbody>
  </table>
</section>

<section>
  <h2><span>🤖</span> AI Security Analysis</h2>
  <div class="ai-block">{ai_html}</div>
</section>

<div class="footer">
  {APP_TITLE} v{APP_VERSION} &nbsp;|&nbsp; For authorised use only &nbsp;|&nbsp;
  Model: {ai.get('model','N/A')} &nbsp;|&nbsp; Tokens: {ai.get('tokens_used','N/A')}
</div>
</body>
</html>"""

    return html


# ─── PDF (optional) ───────────────────────────────────────────────────────────
def generate_pdf_report(html_content: str) -> bytes:
    """Convert an HTML report string to PDF bytes using weasyprint."""
    if not PDF_AVAILABLE:
        raise ImportError(
            "weasyprint is not installed. "
            "Install it with: pip install weasyprint"
        )
    pdf = WeasyprintHTML(string=html_content).write_pdf()
    return pdf


# ─── File I/O ─────────────────────────────────────────────────────────────────
def save_report(content: Union[str, bytes], filename: str, mode: str = "w") -> str:
    """Save report to the REPORT_DIR. Returns the full file path."""
    safe_mkdir(REPORT_DIR)
    path = os.path.join(REPORT_DIR, filename)
    with open(path, mode, encoding="utf-8" if mode == "w" else None) as fh:
        fh.write(content)
    logger.info("Report saved: %s", path)
    return path


# ─── Markdown → HTML Helper ───────────────────────────────────────────────────
def _md_to_basic_html(text: str) -> str:
    """Very lightweight markdown-to-HTML for the report embed."""
    import re
    # Escape HTML entities
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # Headers
    text = re.sub(r"^## (.+)$", r"<h3 style='color:#58a6ff;margin:1rem 0 .4rem'>\1</h3>", text, flags=re.M)
    text = re.sub(r"^# (.+)$",  r"<h2 style='color:#58a6ff;margin:1.2rem 0 .4rem'>\1</h2>", text, flags=re.M)
    # Bold
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    # Horizontal rule
    text = text.replace("---", "<hr style='border-color:#30363d;margin:.8rem 0'>")
    # Line breaks
    text = text.replace("\n", "<br>\n")
    return text