"""
parser.py — Nmap XML output parser for NmapAI Intelligence Scanner

Transforms raw Nmap XML (piped from -oX -) into clean, structured Python
dicts that feed the AI analysis pipeline and the Streamlit display layer.
"""

import xml.etree.ElementTree as ET
from typing import Optional, List
from utils import setup_logger

logger = setup_logger("parser")


class NmapParseError(ValueError):
    """Raised when XML cannot be parsed or is missing expected structure."""


# ─── Top-Level Parser ─────────────────────────────────────────────────────────
def parse_nmap_xml(xml_string: str) -> dict:
    """
    Parse the raw XML string produced by `nmap -oX -`.

    Returns a structured dict:
    {
        "scan_info": {...},
        "hosts": [ {...}, ... ],
        "stats": {...},
        "summary": "...",
        "open_port_count": int,
        "host_count": int,
    }
    """
    if not xml_string or not xml_string.strip():
        raise NmapParseError("Nmap produced no XML output. The scan may have failed.")

    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError as exc:
        logger.error("XML parse error: %s", exc)
        raise NmapParseError(f"Could not parse Nmap XML: {exc}") from exc

    scan_info   = _parse_scan_info(root)
    hosts       = [_parse_host(h) for h in root.findall("host")]
    run_stats   = _parse_runstats(root)
    open_ports  = sum(h["open_port_count"] for h in hosts)
    summary_txt = _build_summary(hosts, run_stats)

    result = {
        "scan_info":      scan_info,
        "hosts":          hosts,
        "stats":          run_stats,
        "summary":        summary_txt,
        "open_port_count": open_ports,
        "host_count":     len(hosts),
    }

    logger.info(
        "Parsed %d host(s), %d open port(s) total.",
        len(hosts), open_ports,
    )
    return result


# ─── Scan Meta ────────────────────────────────────────────────────────────────
def _parse_scan_info(root: ET.Element) -> dict:
    si = root.find("scaninfo")
    return {
        "scanner":       root.get("scanner", "nmap"),
        "args":          root.get("args", ""),
        "version":       root.get("version", ""),
        "start_time":    root.get("startstr", ""),
        "scan_type":     si.get("type", "") if si is not None else "",
        "protocol":      si.get("protocol", "") if si is not None else "",
        "num_services":  si.get("numservices", "") if si is not None else "",
        "services_range": si.get("services", "") if si is not None else "",
    }


# ─── Per-Host Parsing ─────────────────────────────────────────────────────────
def _parse_host(host_el: ET.Element) -> dict:
    """Parse a single <host> XML element into a structured dict."""

    # Status
    status_el = host_el.find("status")
    status     = status_el.get("state", "unknown") if status_el is not None else "unknown"
    reason     = status_el.get("reason", "") if status_el is not None else ""

    # Addresses
    addresses = []
    for addr_el in host_el.findall("address"):
        addresses.append({
            "addr":     addr_el.get("addr", ""),
            "addrtype": addr_el.get("addrtype", ""),
            "vendor":   addr_el.get("vendor", ""),
        })
    ip   = next((a["addr"] for a in addresses if a["addrtype"] == "ipv4"), "")
    mac  = next((a["addr"] for a in addresses if a["addrtype"] == "mac"), "")
    vendor = next((a["vendor"] for a in addresses if a["addrtype"] == "mac"), "")

    # Hostnames
    hostnames = []
    hn_el = host_el.find("hostnames")
    if hn_el is not None:
        for hn in hn_el.findall("hostname"):
            hostnames.append({
                "name": hn.get("name", ""),
                "type": hn.get("type", ""),
            })

    # OS Detection
    os_info = _parse_os(host_el)

    # Ports
    ports = _parse_ports(host_el)
    open_ports   = [p for p in ports if p["state"] == "open"]
    filtered_ports = [p for p in ports if p["state"] == "filtered"]

    # Host scripts
    host_scripts = _parse_scripts(host_el.find("hostscript"))

    # Timing
    times_el = host_el.find("times")
    timing = {}
    if times_el is not None:
        timing = {
            "rtt_ms":    _ms(times_el.get("srtt")),
            "rttvar_ms": _ms(times_el.get("rttvar")),
        }

    return {
        "ip":              ip,
        "mac":             mac,
        "vendor":          vendor,
        "hostnames":       hostnames,
        "status":          status,
        "status_reason":   reason,
        "addresses":       addresses,
        "os":              os_info,
        "ports":           ports,
        "open_ports":      open_ports,
        "filtered_ports":  filtered_ports,
        "open_port_count": len(open_ports),
        "host_scripts":    host_scripts,
        "timing":          timing,
    }


# ─── OS Parsing ───────────────────────────────────────────────────────────────
def _parse_os(host_el: ET.Element) -> dict:
    os_el = host_el.find("os")
    if os_el is None:
        return {"detected": False, "matches": [], "fingerprint": ""}

    matches = []
    for m in os_el.findall("osmatch"):
        classes = []
        for c in m.findall("osclass"):
            classes.append({
                "type":     c.get("type", ""),
                "vendor":   c.get("vendor", ""),
                "osfamily": c.get("osfamily", ""),
                "osgen":    c.get("osgen", ""),
                "accuracy": c.get("accuracy", ""),
            })
        matches.append({
            "name":     m.get("name", ""),
            "accuracy": m.get("accuracy", ""),
            "classes":  classes,
        })

    fp_el = os_el.find("osfingerprint")
    fp    = fp_el.get("fingerprint", "") if fp_el is not None else ""

    return {
        "detected": bool(matches),
        "matches":  matches,
        "best_match": matches[0]["name"] if matches else "Unknown",
        "best_accuracy": matches[0]["accuracy"] if matches else "0",
        "fingerprint": fp[:200] if fp else "",
    }


# ─── Port / Service Parsing ───────────────────────────────────────────────────
def _parse_ports(host_el: ET.Element) -> List[dict]:
    ports_el = host_el.find("ports")
    if ports_el is None:
        return []

    result = []
    for port_el in ports_el.findall("port"):
        portid   = int(port_el.get("portid", "0"))
        protocol = port_el.get("protocol", "tcp")

        state_el = port_el.find("state")
        state    = state_el.get("state", "unknown")   if state_el  is not None else "unknown"
        reason   = state_el.get("reason", "")         if state_el  is not None else ""

        svc_el = port_el.find("service")
        service = {}
        if svc_el is not None:
            service = {
                "name":       svc_el.get("name", ""),
                "product":    svc_el.get("product", ""),
                "version":    svc_el.get("version", ""),
                "extrainfo":  svc_el.get("extrainfo", ""),
                "ostype":     svc_el.get("ostype", ""),
                "method":     svc_el.get("method", ""),
                "conf":       svc_el.get("conf", ""),
                "cpe":        [c.text or "" for c in svc_el.findall("cpe")],
            }

        scripts = _parse_scripts(port_el)

        result.append({
            "port":     portid,
            "protocol": protocol,
            "state":    state,
            "reason":   reason,
            "service":  service,
            "scripts":  scripts,
        })

    return result


def _parse_scripts(parent_el: Optional[ET.Element]) -> List[dict]:
    """Parse NSE script output blocks attached to a port or host element."""
    if parent_el is None:
        return []
    scripts = []
    for sc in parent_el.findall("script"):
        scripts.append({
            "id":     sc.get("id", ""),
            "output": sc.get("output", "")[:500],
        })
    return scripts


# ─── Run Stats ────────────────────────────────────────────────────────────────
def _parse_runstats(root: ET.Element) -> dict:
    rs = root.find("runstats")
    if rs is None:
        return {}
    finished = rs.find("finished")
    hosts_el = rs.find("hosts")
    return {
        "end_time":    finished.get("timestr", "") if finished is not None else "",
        "elapsed_sec": finished.get("elapsed", "") if finished is not None else "",
        "summary":     finished.get("summary", "") if finished is not None else "",
        "exit_status": finished.get("exit", "") if finished is not None else "",
        "hosts_up":    int(hosts_el.get("up", "0")) if hosts_el is not None else 0,
        "hosts_down":  int(hosts_el.get("down", "0")) if hosts_el is not None else 0,
        "hosts_total": int(hosts_el.get("total", "0")) if hosts_el is not None else 0,
    }


# ─── Human-Readable Summary ───────────────────────────────────────────────────
def _build_summary(hosts: List[dict], stats: dict) -> str:
    if not hosts:
        return "No hosts found in the scan output."
    lines = []
    for h in hosts:
        display = h["ip"] or (h["hostnames"][0]["name"] if h["hostnames"] else "Unknown")
        lines.append(
            f"Host {display} is {h['status'].upper()} — "
            f"{h['open_port_count']} open port(s) detected."
        )
    if stats.get("elapsed_sec"):
        lines.append(f"Scan completed in {stats['elapsed_sec']} seconds.")
    return " | ".join(lines)


# ─── Helper ───────────────────────────────────────────────────────────────────
def _ms(raw: Optional[str]) -> float:
    """Convert Nmap microsecond string to milliseconds."""
    if not raw:
        return 0.0
    try:
        return round(int(raw) / 1000, 2)
    except ValueError:
        return 0.0


# ─── Flat Port Table (for display / AI) ──────────────────────────────────────
def flatten_open_ports(parsed: dict) -> List[dict]:
    """
    Returns a flat list of all open ports across all hosts — useful for
    feeding a concise table to the AI analysis prompt.
    """
    rows = []
    for host in parsed.get("hosts", []):
        for port in host.get("open_ports", []):
            svc = port.get("service", {})
            rows.append({
                "host":     host["ip"] or host["hostnames"][0]["name"] if host["hostnames"] else "?",
                "port":     port["port"],
                "protocol": port["protocol"],
                "service":  svc.get("name", "unknown"),
                "product":  svc.get("product", ""),
                "version":  svc.get("version", ""),
                "cpe":      ", ".join(svc.get("cpe", [])),
            })
    return rows