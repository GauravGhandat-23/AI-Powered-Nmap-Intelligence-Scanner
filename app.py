"""
app.py — Main Streamlit application for AI-Powered Nmap Intelligence Scanner
         Dark cybersecurity theme · Groq AI · Production-grade UI
"""

import streamlit as st
import json
import time
import re
from typing import Optional
from datetime import datetime

# ─── Page Config (must be FIRST Streamlit call) ───────────────────────────────
st.set_page_config(
    page_title="NmapAI Intelligence Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "Get Help": "https://nmap.org/docs.html",
        "Report a bug": None,
        "About": "AI-Powered Nmap Intelligence Scanner — Ethical Hacking Toolkit",
    },
)

from config import SCAN_TYPES, APP_TITLE, APP_VERSION, APP_TAGLINE
from scanner import NmapScanner, is_nmap_installed, get_nmap_version, NmapNotFoundError
from nmap_parser import parse_nmap_xml, flatten_open_ports
from ai_analyzer import GroqAnalyzer, AnalysisError
from report_generator import (
    assemble_report_data,
    generate_json_report,
    generate_txt_report,
    generate_html_report,
    generate_pdf_report,
    PDF_AVAILABLE,
)
from utils import validate_target, validate_port_range, now_filename, get_risk_color

# ─── Global CSS ───────────────────────────────────────────────────────────────
CUSTOM_CSS = """
<style>
/* ── Font imports ── */
@import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:ital,wght@0,300;0,400;0,600;1,300&display=swap');

/* ── Root palette ── */
:root {
    --bg-deep:    #070b10;
    --bg-surface: #0d1117;
    --bg-card:    #111820;
    --bg-card2:   #161d26;
    --border:     #1e2d3d;
    --border-glow:#2a4060;
    --accent:     #00d2ff;
    --accent2:    #7b2fff;
    --green:      #00ff88;
    --red:        #ff3a5c;
    --orange:     #ff9f0a;
    --yellow:     #ffd700;
    --text:       #c8d8e8;
    --muted:      #5a7a9a;
    --white:      #eaf4ff;
}

/* ── Global ── */
.stApp { background: var(--bg-deep) !important; font-family: 'DM Sans', sans-serif; }
html, body { background: var(--bg-deep) !important; }

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #070f18 0%, #050d14 100%) !important;
    border-right: 1px solid var(--border) !important;
}
[data-testid="stSidebar"] * { color: var(--text) !important; }

/* ── Hero banner ── */
.hero-banner {
    background: linear-gradient(135deg, #070f18 0%, #0a1628 40%, #0d1f38 100%);
    border: 1px solid var(--border-glow);
    border-radius: 16px;
    padding: 2.2rem 2.5rem;
    margin-bottom: 1.5rem;
    position: relative;
    overflow: hidden;
}
.hero-banner::before {
    content: '';
    position: absolute;
    top: -40%;
    right: -10%;
    width: 500px;
    height: 500px;
    background: radial-gradient(circle, rgba(0,210,255,.06) 0%, transparent 70%);
    pointer-events: none;
}
.hero-title {
    font-family: 'Space Mono', monospace;
    font-size: 2.1rem;
    font-weight: 700;
    background: linear-gradient(90deg, #00d2ff, #7b2fff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 0.3rem;
    line-height: 1.2;
}
.hero-sub {
    color: var(--muted);
    font-size: 0.95rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    font-weight: 300;
}
.hero-badge {
    display: inline-block;
    background: rgba(0,210,255,0.1);
    border: 1px solid rgba(0,210,255,0.3);
    color: var(--accent);
    font-family: 'Space Mono', monospace;
    font-size: 0.68rem;
    padding: 0.2rem 0.7rem;
    border-radius: 20px;
    margin-top: 0.7rem;
}

/* ── Metric cards ── */
.metric-row { display: flex; gap: 1rem; margin: 1rem 0; flex-wrap: wrap; }
.metric-card {
    flex: 1;
    min-width: 130px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.1rem 1.3rem;
    transition: border-color .2s;
}
.metric-card:hover { border-color: var(--border-glow); }
.metric-label {
    color: var(--muted);
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    font-weight: 600;
}
.metric-value {
    font-family: 'Space Mono', monospace;
    font-size: 1.6rem;
    font-weight: 700;
    color: var(--white);
    margin-top: 0.3rem;
    line-height: 1;
}
.metric-value.accent { color: var(--accent); }
.metric-value.green  { color: var(--green); }
.metric-value.red    { color: var(--red); }
.metric-value.orange { color: var(--orange); }

/* ── Risk badge ── */
.risk-badge {
    display: inline-block;
    font-family: 'Space Mono', monospace;
    font-weight: 700;
    font-size: 0.8rem;
    padding: 0.35rem 1rem;
    border-radius: 20px;
    letter-spacing: 0.08em;
}
.risk-Critical { background: rgba(255,45,85,0.2); color: #ff2d55; border: 1px solid #ff2d55; }
.risk-High     { background: rgba(255,159,10,0.2); color: #ff9f0a; border: 1px solid #ff9f0a; }
.risk-Medium   { background: rgba(255,214,10,0.2); color: #ffd60a; border: 1px solid #ffd60a; }
.risk-Low      { background: rgba(48,209,88,0.2);  color: #30d158; border: 1px solid #30d158; }

/* ── Port table ── */
.port-table { width: 100%; border-collapse: collapse; margin-top: 0.8rem; }
.port-table th {
    background: #0d1520;
    color: var(--muted);
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    padding: 0.6rem 1rem;
    text-align: left;
    border-bottom: 1px solid var(--border);
}
.port-table td {
    padding: 0.5rem 1rem;
    border-bottom: 1px solid var(--border);
    font-size: 0.85rem;
    color: var(--text);
}
.port-table tr:hover td { background: rgba(255,255,255,.02); }
.port-open  { color: var(--green); font-weight: 700; font-family: 'Space Mono', monospace; }
.port-num   { color: var(--accent); font-family: 'Space Mono', monospace; }
.svc-name   { color: var(--orange); font-weight: 600; }

/* ── Section header ── */
.section-header {
    font-family: 'Space Mono', monospace;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.15em;
    color: var(--accent);
    border-bottom: 1px solid var(--border);
    padding-bottom: 0.5rem;
    margin: 1.5rem 0 1rem;
}

/* ── AI analysis block ── */
.ai-analysis {
    background: var(--bg-card2);
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent2);
    border-radius: 10px;
    padding: 1.5rem;
    line-height: 1.8;
    color: var(--text);
    font-size: 0.88rem;
}
.ai-analysis h2, .ai-analysis h3 {
    color: var(--accent);
    font-family: 'Space Mono', monospace;
    font-size: 0.9rem;
    margin: 1.2rem 0 0.4rem;
}

/* ── Disclaimer box ── */
.disclaimer {
    background: rgba(255,159,10,0.08);
    border: 1px solid rgba(255,159,10,0.35);
    border-radius: 10px;
    padding: 1rem 1.3rem;
    color: #ffbb44;
    font-size: 0.83rem;
    margin-bottom: 1rem;
}

/* ── Scan status ── */
.scan-status {
    background: rgba(0,210,255,0.06);
    border: 1px solid rgba(0,210,255,0.2);
    border-radius: 8px;
    padding: 0.8rem 1.2rem;
    color: var(--accent);
    font-family: 'Space Mono', monospace;
    font-size: 0.8rem;
}

/* ── Code / raw output ── */
.raw-output {
    background: #060d14;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem;
    font-family: 'Space Mono', monospace;
    font-size: 0.75rem;
    color: #5aff8a;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 500px;
    overflow-y: auto;
}

/* ── Tabs ── */
[data-baseweb="tab-list"] { background: transparent !important; gap: 0.3rem; }
[data-baseweb="tab"] {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
    color: var(--muted) !important;
    font-size: 0.8rem !important;
    padding: 0.5rem 1rem !important;
}
[aria-selected="true"] {
    background: rgba(0,210,255,0.1) !important;
    border-color: var(--accent) !important;
    color: var(--accent) !important;
}

/* ── Buttons ── */
.stButton > button {
    background: linear-gradient(135deg, #005f8a, #003a5c) !important;
    color: var(--accent) !important;
    border: 1px solid var(--accent) !important;
    border-radius: 8px !important;
    font-family: 'Space Mono', monospace !important;
    font-size: 0.8rem !important;
    letter-spacing: 0.06em !important;
    padding: 0.55rem 1.5rem !important;
    transition: all .2s !important;
}
.stButton > button:hover {
    background: linear-gradient(135deg, #0080b8, #004d7a) !important;
    box-shadow: 0 0 15px rgba(0,210,255,.3) !important;
}

/* ── Inputs ── */
[data-testid="stTextInput"] input,
[data-testid="stSelectbox"] > div > div {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
    color: var(--white) !important;
}
</style>
"""

st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ─── Session State Init ───────────────────────────────────────────────────────
def _init_state():
    defaults = {
        "scan_result":  None,
        "parsed_data":  None,
        "ai_result":    None,
        "scan_meta":    None,
        "raw_xml":      None,
        "consent_given": False,
        "scan_running":  False,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

_init_state()


# ─── Hero Banner ──────────────────────────────────────────────────────────────
def render_hero():
    st.markdown(f"""
    <div class="hero-banner">
        <div class="hero-title">🛡️ {APP_TITLE}</div>
        <div class="hero-sub">{APP_TAGLINE}</div>
        <span class="hero-badge">v{APP_VERSION} &nbsp;·&nbsp; Groq AI · qwen/qwen3-32b &nbsp;·&nbsp; Ethical Use Only</span>
    </div>
    """, unsafe_allow_html=True)


# ─── Sidebar ──────────────────────────────────────────────────────────────────
def render_sidebar() -> dict:
    with st.sidebar:
        st.markdown("### 🎛️ Scan Configuration")
        st.markdown("---")

        # Nmap status
        nmap_ok = is_nmap_installed()
        if nmap_ok:
            nmap_ver = get_nmap_version()
            st.markdown(f"✅ **Nmap detected**")
            st.caption(nmap_ver)
        else:
            st.error("❌ Nmap not found in PATH")
            st.caption("Install Nmap: https://nmap.org/download.html")

        st.markdown("---")
        st.markdown("**📡 Target**")
        target = st.text_input(
            "IP / Domain / CIDR",
            placeholder="192.168.1.1  |  scanme.nmap.org  |  10.0.0.0/24",
            label_visibility="collapsed",
        )

        st.markdown("**🔍 Scan Type**")
        scan_type = st.selectbox(
            "Scan Type",
            options=list(SCAN_TYPES.keys()),
            label_visibility="collapsed",
        )
        st.caption(f"{SCAN_TYPES[scan_type]['icon']}  {SCAN_TYPES[scan_type]['description']}")

        custom_args = ""
        if scan_type == "Custom Arguments":
            custom_args = st.text_input(
                "Custom Nmap Args",
                placeholder="-sU -T4 -p 53,161,123",
                help="Enter raw Nmap flags. The target is appended automatically.",
            )

        st.markdown("**🔢 Port Range**")
        port_range = st.text_input(
            "Ports",
            value="1-1024",
            placeholder="1-65535  |  80,443,8080",
            label_visibility="collapsed",
            disabled=(scan_type == "Custom Arguments"),
        )

        st.markdown("**⏱️ Timeout (seconds)**")
        timeout = st.slider("Timeout", 30, 600, 300, step=30, label_visibility="collapsed")

        st.markdown("---")
        st.markdown("**🤖 AI Analysis**")
        run_ai = st.toggle("Enable AI Analysis", value=True)

        st.markdown("---")
        st.markdown("**⚠️ Disclaimer**")
        st.markdown("""
        <div class="disclaimer">
        This tool is for <strong>authorised security testing only</strong>.
        Scanning systems without permission is illegal.
        The authors accept no liability for misuse.
        </div>
        """, unsafe_allow_html=True)

        consent = st.checkbox(
            "I have authorisation to scan the target",
            value=st.session_state.consent_given,
        )
        st.session_state.consent_given = consent

        st.markdown("---")

        launch = st.button("🚀 LAUNCH SCAN", use_container_width=True, type="primary")

    return {
        "target":       target.strip(),
        "scan_type":    scan_type,
        "port_range":   port_range.strip(),
        "custom_args":  custom_args.strip(),
        "timeout":      timeout,
        "run_ai":       run_ai,
        "launch":       launch,
    }


# ─── Metric Card Row ──────────────────────────────────────────────────────────
def render_metrics(parsed: dict, ai_result: Optional[dict], duration: float):
    hosts_up   = parsed.get("stats", {}).get("hosts_up", parsed.get("host_count", 0))
    open_count = parsed.get("open_port_count", 0)
    risk_score = ai_result["risk_score"] if ai_result else "—"
    risk_label = ai_result["risk_label"] if ai_result else "—"
    risk_color = get_risk_color(risk_label) if ai_result else "#8E8E93"

    score_class = f"risk-{risk_label}" if ai_result else ""

    st.markdown(f"""
    <div class="metric-row">
      <div class="metric-card">
        <div class="metric-label">Target</div>
        <div class="metric-value accent" style="font-size:1.1rem">
          {parsed.get('hosts', [{}])[0].get('ip', st.session_state.scan_meta.get('target','?')) if parsed.get('hosts') else st.session_state.scan_meta.get('target','?')}
        </div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Hosts Up</div>
        <div class="metric-value green">{hosts_up}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Open Ports</div>
        <div class="metric-value orange">{open_count}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Scan Duration</div>
        <div class="metric-value">{duration}s</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Risk Score</div>
        <div class="metric-value" style="color:{risk_color}">{risk_score}{'/100' if ai_result else ''}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Risk Level</div>
        <div class="metric-value">
          <span class="risk-badge {score_class}">{risk_label}</span>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)


# ─── Port Table ───────────────────────────────────────────────────────────────
def render_port_table(parsed: dict):
    flat = flatten_open_ports(parsed)
    if not flat:
        st.info("No open ports detected.")
        return

    rows_html = ""
    for row in flat:
        svc_display = row["service"] or "unknown"
        prod_display = f"{row['product']} {row['version']}".strip() or "—"
        rows_html += f"""
        <tr>
          <td>{row['host']}</td>
          <td class="port-num">{row['port']}</td>
          <td style="color:#8b949e">{row['protocol'].upper()}</td>
          <td class="port-open">OPEN</td>
          <td class="svc-name">{svc_display}</td>
          <td style="color:#a8b8c8">{prod_display}</td>
          <td style="color:#5a7a9a;font-size:.75rem">{row['cpe'] or '—'}</td>
        </tr>"""

    st.markdown(f"""
    <table class="port-table">
      <thead>
        <tr>
          <th>Host</th><th>Port</th><th>Protocol</th><th>State</th>
          <th>Service</th><th>Product / Version</th><th>CPE</th>
        </tr>
      </thead>
      <tbody>{rows_html}</tbody>
    </table>
    """, unsafe_allow_html=True)


# ─── Charts ───────────────────────────────────────────────────────────────────
def render_charts(parsed: dict):
    import pandas as pd

    flat = flatten_open_ports(parsed)
    if not flat:
        return

    col1, col2 = st.columns(2)

    with col1:
        services = [r["service"] or "unknown" for r in flat]
        svc_counts = {}
        for s in services:
            svc_counts[s] = svc_counts.get(s, 0) + 1

        df_svc = pd.DataFrame(
            sorted(svc_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            columns=["Service", "Count"]
        )
        st.markdown('<p class="section-header">Service Distribution</p>', unsafe_allow_html=True)
        st.bar_chart(df_svc.set_index("Service"), height=260, use_container_width=True)

    with col2:
        ports_nums = sorted([r["port"] for r in flat])
        # Port range buckets
        buckets = {"1-1023": 0, "1024-8080": 0, "8081-49151": 0, "49152+": 0}
        for p in ports_nums:
            if p <= 1023:        buckets["1-1023"] += 1
            elif p <= 8080:      buckets["1024-8080"] += 1
            elif p <= 49151:     buckets["8081-49151"] += 1
            else:                buckets["49152+"] += 1

        df_bucket = pd.DataFrame(
            [(k, v) for k, v in buckets.items() if v > 0],
            columns=["Range", "Ports"]
        )
        st.markdown('<p class="section-header">Port Range Breakdown</p>', unsafe_allow_html=True)
        st.bar_chart(df_bucket.set_index("Range"), height=260, use_container_width=True)


# ─── AI Analysis Renderer ─────────────────────────────────────────────────────
def render_ai_analysis(ai_result: dict):
    raw = ai_result.get("raw_response", "No analysis available.")

    # Section map for individual expanders
    sections = {
        "EXECUTIVE SUMMARY":               "📊",
        "OPEN PORT & SERVICE ANALYSIS":    "🔌",
        "ATTACK SURFACE ASSESSMENT":       "🎯",
        "MISCONFIGURATION INDICATORS":     "⚠️",
        "RISK SCORE":                      "📈",
        "REMEDIATION RECOMMENDATIONS":     "🔧",
        "BLUE TEAM / SOC NOTES":           "🔵",
        "COMPLIANCE & BEST PRACTICE":      "📋",
    }

    # Full text display
    st.markdown(f"""
    <div class="ai-analysis">
    {_render_md_to_html_inline(raw)}
    </div>
    """, unsafe_allow_html=True)

    # Token info
    st.caption(
        f"🤖 Model: `{ai_result.get('model','?')}` | "
        f"Tokens: {ai_result.get('tokens_used','?')} total "
        f"({ai_result.get('prompt_tokens','?')} prompt + "
        f"{ai_result.get('completion_tokens','?')} completion)"
    )


def _render_md_to_html_inline(text: str) -> str:
    """Lightweight Markdown → HTML for inline rendering inside st.markdown."""
    import html as htmlmod
    safe = htmlmod.escape(text)
    # ## headers
    safe = re.sub(r"^## (.+)$",
                  r"<h3 style='color:#00d2ff;font-family:Space Mono,monospace;"
                  r"font-size:.9rem;margin:1.2rem 0 .4rem;'>\1</h3>",
                  safe, flags=re.M)
    # **bold**
    safe = re.sub(r"\*\*(.+?)\*\*", r"<strong style='color:#eaf4ff'>\1</strong>", safe)
    # horizontal rule
    safe = safe.replace("---", "<hr style='border:none;border-top:1px solid #1e2d3d;margin:.8rem 0'>")
    # newlines
    safe = safe.replace("\n", "<br>\n")
    return safe


# ─── Download Report Builder ──────────────────────────────────────────────────
def render_download_tab(scan_meta, raw_xml, parsed, ai_result):
    report_data = assemble_report_data(scan_meta, raw_xml, parsed, ai_result)

    st.markdown("### 📥 Export Scan Report")
    st.markdown("Download your scan results in multiple formats for documentation and archiving.")

    col1, col2, col3 = st.columns(3)

    with col1:
        json_str = generate_json_report(report_data)
        st.download_button(
            label="⬇️  JSON Report",
            data=json_str,
            file_name=f"{now_filename('nmap_report')}.json",
            mime="application/json",
            use_container_width=True,
        )
        st.caption("Machine-readable structured data")

    with col2:
        txt_str = generate_txt_report(report_data)
        st.download_button(
            label="⬇️  TXT Report",
            data=txt_str,
            file_name=f"{now_filename('nmap_report')}.txt",
            mime="text/plain",
            use_container_width=True,
        )
        st.caption("Human-readable plain text")

    with col3:
        html_str = generate_html_report(report_data)
        st.download_button(
            label="⬇️  HTML Report",
            data=html_str,
            file_name=f"{now_filename('nmap_report')}.html",
            mime="text/html",
            use_container_width=True,
        )
        st.caption("Styled standalone web report")

    if PDF_AVAILABLE:
        st.markdown("---")
        try:
            html_str_pdf = generate_html_report(report_data)
            pdf_bytes    = generate_pdf_report(html_str_pdf)
            st.download_button(
                label="⬇️  PDF Report (Experimental)",
                data=pdf_bytes,
                file_name=f"{now_filename('nmap_report')}.pdf",
                mime="application/pdf",
                use_container_width=False,
            )
        except Exception as exc:
            st.warning(f"PDF generation failed: {exc}")
    else:
        st.info("💡 Install `weasyprint` to enable PDF export: `pip install weasyprint`")


# ─── Results Tabs ─────────────────────────────────────────────────────────────
def render_results():
    parsed   = st.session_state.parsed_data
    ai_res   = st.session_state.ai_result
    scan_meta = st.session_state.scan_meta
    raw_xml  = st.session_state.raw_xml

    if not parsed:
        return

    render_metrics(parsed, ai_res, scan_meta.get("duration_seconds", "?"))

    tab_labels = [
        "🔌 Open Ports",
        "📊 Charts",
        "📝 Raw Output",
        "🧠 AI Analysis",
        "📥 Download",
    ]
    tabs = st.tabs(tab_labels)

    # ── Tab 0 · Open Ports ────────────────────────────────────────────────────
    with tabs[0]:
        st.markdown('<p class="section-header">Discovered Open Ports</p>', unsafe_allow_html=True)
        render_port_table(parsed)

        # Per-host OS info
        for host in parsed.get("hosts", []):
            if host.get("os", {}).get("detected"):
                with st.expander(f"🖥️  OS Detection — {host['ip']}"):
                    os_d = host["os"]
                    st.markdown(f"**Best Match:** {os_d['best_match']} ({os_d['best_accuracy']}% accuracy)")
                    if len(os_d["matches"]) > 1:
                        for m in os_d["matches"][1:4]:
                            st.caption(f"  Alt: {m['name']} — {m['accuracy']}%")

        # Host scripts
        for host in parsed.get("hosts", []):
            for port in host.get("open_ports", []):
                if port.get("scripts"):
                    with st.expander(f"📜 NSE Scripts — {host['ip']}:{port['port']}"):
                        for sc in port["scripts"]:
                            st.code(f"[{sc['id']}]\n{sc['output']}", language="text")

    # ── Tab 1 · Charts ────────────────────────────────────────────────────────
    with tabs[1]:
        render_charts(parsed)

    # ── Tab 2 · Raw Output ────────────────────────────────────────────────────
    with tabs[2]:
        st.markdown('<p class="section-header">Raw Nmap XML Output</p>', unsafe_allow_html=True)
        cmd_display = scan_meta.get("command", "")
        st.code(cmd_display, language="bash")

        if raw_xml:
            xml_display = raw_xml[:8000]
            st.markdown(f'<div class="raw-output">{xml_display}</div>', unsafe_allow_html=True)
            if len(raw_xml) > 8000:
                st.caption(f"Output truncated at 8000 chars. Full data available in report download.")

        if scan_meta.get("stderr"):
            with st.expander("⚠️  Nmap stderr / warnings"):
                st.code(scan_meta["stderr"], language="text")

    # ── Tab 3 · AI Analysis ───────────────────────────────────────────────────
    with tabs[3]:
        if ai_res:
            st.markdown('<p class="section-header">AI-Powered Security Analysis</p>', unsafe_allow_html=True)
            render_ai_analysis(ai_res)
        else:
            st.info("AI analysis was disabled or not yet run. Enable it in the sidebar and re-scan.")

    # ── Tab 4 · Download ──────────────────────────────────────────────────────
    with tabs[4]:
        render_download_tab(scan_meta, raw_xml, parsed, ai_res or {})


# ─── Scan Orchestrator ────────────────────────────────────────────────────────
def run_scan(cfg: dict):
    """Full scan pipeline: validate → scan → parse → AI → store in session."""

    # ── Pre-flight checks ──────────────────────────────────────────────────────
    if not cfg["target"]:
        st.error("Please enter a target IP, domain, or CIDR range.")
        return

    if not st.session_state.consent_given:
        st.warning("⚠️  You must confirm authorisation before scanning.")
        return

    ok, err = validate_target(cfg["target"])
    if not ok:
        st.error(f"Invalid target: {err}")
        return

    if cfg["scan_type"] != "Custom Arguments":
        ok2, err2 = validate_port_range(cfg["port_range"])
        if not ok2:
            st.error(f"Invalid port range: {err2}")
            return

    # ── Scan execution ─────────────────────────────────────────────────────────
    progress_bar = st.progress(0, text="Initialising scan…")
    status_box   = st.empty()

    try:
        status_box.markdown('<div class="scan-status">🔍 Running Nmap scan…</div>', unsafe_allow_html=True)
        progress_bar.progress(10, text="Launching Nmap…")

        scanner = NmapScanner(
            target=cfg["target"],
            scan_type=cfg["scan_type"],
            port_range=cfg["port_range"],
            custom_args=cfg["custom_args"],
            timeout=cfg["timeout"],
        )
        result = scanner.run()
        progress_bar.progress(45, text="Scan complete — parsing results…")

        # ── Parse ───────────────────────────────────────────────────────────────
        status_box.markdown('<div class="scan-status">📊 Parsing Nmap XML output…</div>', unsafe_allow_html=True)
        parsed = parse_nmap_xml(result["xml_output"])
        progress_bar.progress(65, text="Parsed successfully…")

        # ── AI Analysis ─────────────────────────────────────────────────────────
        ai_result = None
        if cfg["run_ai"]:
            status_box.markdown(
                '<div class="scan-status">🤖 Sending data to Groq AI (qwen/qwen3-32b)…</div>',
                unsafe_allow_html=True,
            )
            progress_bar.progress(70, text="AI analysis in progress…")
            try:
                analyzer  = GroqAnalyzer()
                ai_result = analyzer.analyze(parsed, result)
                progress_bar.progress(95, text="AI analysis complete…")
            except AnalysisError as ai_err:
                st.warning(f"⚠️ AI analysis failed: {ai_err}")

        # ── Store in session ────────────────────────────────────────────────────
        st.session_state.scan_result = result
        st.session_state.parsed_data = parsed
        st.session_state.ai_result   = ai_result
        st.session_state.scan_meta   = result
        st.session_state.raw_xml     = result["xml_output"]

        progress_bar.progress(100, text="✅ Scan pipeline complete!")
        time.sleep(0.4)
        progress_bar.empty()
        status_box.success(
            f"✅ Scan completed in {result['duration_seconds']}s — "
            f"{parsed['open_port_count']} open port(s) found on {parsed['host_count']} host(s)."
        )

    except NmapNotFoundError as e:
        progress_bar.empty()
        status_box.empty()
        st.error(f"🔴 Nmap not found: {e}")

    except PermissionError as e:
        progress_bar.empty()
        status_box.empty()
        st.error(f"🔴 Permission denied: {e}")

    except Exception as e:
        progress_bar.empty()
        status_box.empty()
        st.error(f"🔴 Scan failed: {e}")
        with st.expander("Error details"):
            import traceback
            st.code(traceback.format_exc(), language="text")


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    render_hero()

    cfg = render_sidebar()

    if cfg["launch"] and not st.session_state.scan_running:
        st.session_state.scan_running = True
        run_scan(cfg)
        st.session_state.scan_running = False

    if st.session_state.parsed_data:
        render_results()
    else:
        # Welcome screen
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown("""
            <div style='background:#111820;border:1px solid #1e2d3d;border-radius:12px;padding:1.5rem'>
                <div style='color:#00d2ff;font-size:1.8rem;margin-bottom:.5rem'>⚡</div>
                <div style='color:#eaf4ff;font-weight:600;margin-bottom:.4rem'>Multiple Scan Modes</div>
                <div style='color:#5a7a9a;font-size:.83rem'>Quick, Full TCP, Service Version, OS Detection, Aggressive, and Custom.</div>
            </div>
            """, unsafe_allow_html=True)
        with col2:
            st.markdown("""
            <div style='background:#111820;border:1px solid #1e2d3d;border-radius:12px;padding:1.5rem'>
                <div style='color:#7b2fff;font-size:1.8rem;margin-bottom:.5rem'>🤖</div>
                <div style='color:#eaf4ff;font-weight:600;margin-bottom:.4rem'>Groq AI Analysis</div>
                <div style='color:#5a7a9a;font-size:.83rem'>qwen/qwen3-32b generates professional risk assessments, CVE hints, and hardening guides.</div>
            </div>
            """, unsafe_allow_html=True)
        with col3:
            st.markdown("""
            <div style='background:#111820;border:1px solid #1e2d3d;border-radius:12px;padding:1.5rem'>
                <div style='color:#ff9f0a;font-size:1.8rem;margin-bottom:.5rem'>📄</div>
                <div style='color:#eaf4ff;font-weight:600;margin-bottom:.4rem'>Export Reports</div>
                <div style='color:#5a7a9a;font-size:.83rem'>Download full scan reports as JSON, TXT, HTML (or PDF with weasyprint).</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("""
        <div style='text-align:center;color:#1e2d3d;font-family:Space Mono,monospace;font-size:.75rem;
                    letter-spacing:.15em;margin-top:2rem'>
            CONFIGURE TARGET IN SIDEBAR → CONFIRM AUTHORISATION → LAUNCH SCAN
        </div>
        """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()