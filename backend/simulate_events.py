#!/usr/bin/env python3
"""
Volcano AI Firewall — Event Simulator
======================================
Generates realistic firewall events by pushing data through the backend API.
This populates every section of the dashboard: alerts, packet metrics,
firewall rules, port/IP history, TCP sessions, search/file-share logs, etc.

Usage:
    1. Start the backend first:    python app.py
    2. In another terminal:        python simulate_events.py

Options:
    --base-url   Backend URL (default: http://127.0.0.1:8000)
    --rounds     Number of simulation rounds (default: 0 = infinite)
    --interval   Seconds between rounds (default: 2.0)
    --burst      Enable burst mode — floods events rapidly for stress testing
"""

from __future__ import annotations

import argparse
import json
import os
import random
import string
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_BASE_URL = "http://127.0.0.1:8000"
DEFAULT_INTERVAL = 2.0

# ─── Realistic Simulation Data ──────────────────────────────────────

ATTACKER_IPS = [
    "10.10.10.25", "172.16.24.8", "192.168.1.105", "10.0.0.99",
    "203.0.113.42", "198.51.100.7", "10.20.30.40", "172.16.0.88",
    "192.168.100.55", "10.10.10.10",
]

INTERNAL_IPS = [
    "192.168.1.1", "192.168.1.10", "192.168.1.50", "10.0.0.1",
    "10.0.0.5", "172.16.0.1",
]

COMMON_PORTS = [22, 53, 80, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443, 9200]
SCAN_PORTS = list(range(20, 1025))
EPHEMERAL_PORTS = list(range(49152, 65535))

PROTOCOLS = ["TCP", "UDP"]

PHISHING_URLS = [
    "http://secure-paypa1.com/login",
    "https://amaz0n-verify.net/account",
    "http://g00gle-docs.tk/share/doc123",
    "https://micr0soft-reset.xyz/password",
    "http://bank0famerica.pw/signin",
    "https://apple-id-verify.info/manage",
    "http://netfl1x-billing.com/update",
    "https://dhl-tracking.buzz/package",
]

SAFE_URLS = [
    "https://google.com",
    "https://github.com",
    "https://stackoverflow.com",
    "https://docs.python.org",
    "https://wikipedia.org",
    "https://microsoft.com",
]

SEARCH_QUERIES = [
    "python fastapi tutorial", "how to configure firewall rules",
    "scapy packet capture windows", "machine learning anomaly detection",
    "network security best practices", "docker container networking",
    "react state management", "ssl certificate setup",
    "port scanning nmap", "ransomware prevention guide",
]

FILE_NAMES = [
    "quarterly_report.xlsx", "client_database.csv", "backup_2024.tar.gz",
    "source_code.zip", "invoice_final.pdf", "credentials.txt",
    "meeting_notes.docx", "server_logs.txt", "employee_data.xlsx",
    "financial_projections.pptx",
]

USERNAMES = ["admin", "john.doe", "analyst_1", "soc_team", "guest_user", "dev_ops", "network_admin"]

RULE_TEMPLATES = [
    {"name": "Block SSH Brute Force",    "action": "deny",   "dst_port": 22,   "protocol": "TCP",  "priority": 1,  "description": "Prevent SSH brute force attacks"},
    {"name": "Block Telnet Access",      "action": "deny",   "dst_port": 23,   "protocol": "TCP",  "priority": 1,  "description": "Block insecure Telnet connections"},
    {"name": "Allow HTTPS Traffic",      "action": "allow",  "dst_port": 443,  "protocol": "TCP",  "priority": 10, "description": "Permit standard HTTPS traffic"},
    {"name": "Allow DNS Queries",        "action": "allow",  "dst_port": 53,   "protocol": "UDP",  "priority": 10, "description": "Allow outbound DNS resolution"},
    {"name": "Block SMB External",       "action": "deny",   "dst_port": 445,  "protocol": "TCP",  "priority": 5,  "description": "Block external SMB file sharing"},
    {"name": "Block RDP from WAN",       "action": "deny",   "dst_port": 3389, "protocol": "TCP",  "priority": 5,  "description": "Prevent RDP access from external IPs"},
    {"name": "Allow HTTP Traffic",       "action": "allow",  "dst_port": 80,   "protocol": "TCP",  "priority": 10, "description": "Permit standard HTTP traffic"},
    {"name": "Block MySQL External",     "action": "deny",   "dst_port": 3306, "protocol": "TCP",  "priority": 5,  "description": "Block external MySQL connections"},
]


# ─── Helpers ────────────────────────────────────────────────────────

# Fix Windows console encoding
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


class Colors:
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    END    = "\033[0m"


def cprint(color: str, symbol: str, msg: str) -> None:
    try:
        print(f"{color}{symbol}{Colors.END} {msg}")
    except UnicodeEncodeError:
        print(f"{color}*{Colors.END} {msg}")


def post_json(url: str, data: Dict[str, Any], timeout: int = 10) -> Optional[Dict]:
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}


def get_json(url: str, timeout: int = 10) -> Optional[Dict]:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def post_query(url: str, timeout: int = 10) -> Optional[Dict]:
    req = urllib.request.Request(url, data=b"", headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}


# ─── Simulators ─────────────────────────────────────────────────────

def simulate_firewall_rules(base_url: str) -> None:
    """Create a set of realistic firewall rules."""
    cprint(Colors.CYAN, "🛡️", "Creating firewall rules...")
    for template in RULE_TEMPLATES:
        body = {
            "name": template["name"],
            "action": template["action"],
            "src_ip": random.choice(ATTACKER_IPS) if template["action"] == "deny" else None,
            "dst_port": template["dst_port"],
            "protocol": template["protocol"],
            "priority": template["priority"],
            "description": template["description"],
        }
        result = post_json(f"{base_url}/api/rules", body)
        if result and "error" not in result:
            cprint(Colors.GREEN, "  ✓", f"Rule: {template['name']} ({template['action']})")
        else:
            cprint(Colors.DIM, "  ·", f"Rule: {template['name']} (may already exist)")


def simulate_search_history(base_url: str, count: int = 5) -> None:
    """Post realistic web search history entries."""
    for _ in range(count):
        query = random.choice(SEARCH_QUERIES)
        url = random.choice(SAFE_URLS + PHISHING_URLS[:2])
        who = random.choice(USERNAMES)
        post_json(f"{base_url}/api/history/searches", {"who": who, "query": query, "url": url})
    cprint(Colors.GREEN, "🔍", f"Posted {count} search history entries")


def simulate_file_shares(base_url: str, count: int = 3) -> None:
    """Post file sharing activity."""
    for _ in range(count):
        filename = random.choice(FILE_NAMES)
        dest_ip = random.choice(INTERNAL_IPS + ATTACKER_IPS[:2])
        who = random.choice(USERNAMES)
        post_json(f"{base_url}/api/history/file-shares", {
            "who": who, "filename": filename, "dest_ip": dest_ip,
        })
    cprint(Colors.GREEN, "📁", f"Posted {count} file share events")


def simulate_port_activity(base_url: str, count: int = 12, burst: bool = False) -> None:
    """Post realistic port usage, scanning, and current connection samples."""
    protocol_choices = ["TCP", "UDP"]
    direction_choices = ["inbound", "outbound"]
    used_ports: List[int] = []

    for _ in range(count):
        # Mix common service ports with ephemeral ports to look like real traffic.
        if burst and random.random() < 0.5:
            port = random.choice(SCAN_PORTS)
        else:
            port = random.choice(COMMON_PORTS + random.sample(EPHEMERAL_PORTS, k=3))

        src_ip = random.choice(ATTACKER_IPS + INTERNAL_IPS)
        dst_ip = random.choice(INTERNAL_IPS + ATTACKER_IPS[:3])
        protocol = random.choice(protocol_choices)
        direction = random.choice(direction_choices)

        result = post_json(
            f"{base_url}/api/history/ports",
            {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "port": port,
                "protocol": protocol,
                "direction": direction,
                "who": random.choice(USERNAMES),
            },
        )
        if result and "error" not in result:
            used_ports.append(port)

    if used_ports:
        sample = ", ".join(str(port) for port in used_ports[:8])
        cprint(Colors.GREEN, "🔌", f"Posted {len(used_ports)} random port activity events ({sample}{'...' if len(used_ports) > 8 else ''})")
    else:
        cprint(Colors.YELLOW, "🔌", "Port activity posting skipped")


def simulate_phishing_checks(base_url: str, count: int = 2) -> None:
    """Run URL phishing analysis on random URLs."""
    urls = random.sample(PHISHING_URLS + SAFE_URLS, min(count, len(PHISHING_URLS + SAFE_URLS)))
    for url in urls:
        result = post_json(f"{base_url}/api/check-url", {"url": url})
        if result and "classification" in result:
            cls = result["classification"]
            score = result.get("final_risk_score", 0)
            color = Colors.RED if cls == "Phishing" else Colors.GREEN
            cprint(color, "🔗", f"URL: {url[:50]}  →  {cls} (risk={score:.4f})")
        else:
            cprint(Colors.YELLOW, "🔗", f"URL: {url[:50]}  →  check sent")


def simulate_copilot_queries(base_url: str) -> None:
    """Send a security query to the AI copilot."""
    queries = [
        "What are the current active threats?",
        "Show me high-risk devices",
        "Are there any port scan alerts?",
        "What is the current threat level?",
        "How many firewall rules are active?",
    ]
    query = random.choice(queries)
    result = post_query(f"{base_url}/api/copilot/ask?query={urllib.request.quote(query)}")
    if result and "answer" in result:
        answer_preview = result["answer"][:80]
        cprint(Colors.BLUE, "🤖", f"Copilot: \"{query}\" → {answer_preview}...")
    else:
        cprint(Colors.YELLOW, "🤖", f"Copilot query sent: \"{query}\"")


def simulate_traditional_traffic(base_url: str) -> None:
    """Post aggregate traffic metrics to feed the Traditional Traffic View.

    Sends a small payload with packet velocity and protocol breakdown so the
    frontend can render charts without raw packet capture.
    """
    proto_counts = {
        "TCP": random.randint(50, 400),
        "UDP": random.randint(5, 80),
        "ICMP": random.randint(0, 8),
    }
    pv = float(round(random.uniform(10.0, 450.0), 2))
    payload = {"protocol_breakdown": proto_counts, "packet_velocity": pv, "file_change_rate": round(random.uniform(0.0, 5.0), 2)}
    result = post_json(f"{base_url}/api/traffic", payload)
    if result and "error" not in result:
        cprint(Colors.CYAN, "📈", f"Posted traffic snapshot (pps={pv}, proto=T:{proto_counts['TCP']},U:{proto_counts['UDP']})")
    else:
        cprint(Colors.YELLOW, "📈", "Traffic snapshot sent")


def simulate_tcp_sessions(base_url: str, count: int = 6) -> None:
    """Simulate active TCP sessions and post them to the sessions endpoint.

    This populates the Active TCP Sessions view and `current_connections`.
    """
    sessions = []
    for _ in range(count):
        src = random.choice(INTERNAL_IPS + ATTACKER_IPS)
        dst = random.choice(INTERNAL_IPS + ATTACKER_IPS)
        port = random.choice(COMMON_PORTS + [random.randint(1024, 65535)])
        proto = "TCP"
        direction = "outbound" if src in INTERNAL_IPS else "inbound"
        last_seen = datetime.now().isoformat()
        sessions.append({"src": src, "dst": dst, "port": port, "protocol": proto, "direction": direction, "last_seen": last_seen})

    payload = {"sessions": sessions}
    result = post_json(f"{base_url}/api/current/sessions", payload)
    if result and "error" not in result:
        cprint(Colors.GREEN, "🔁", f"Posted {len(sessions)} TCP session samples")
    else:
        cprint(Colors.YELLOW, "🔁", "TCP session samples sent")


def simulate_sandbox_activity(watch_dir: str, count: int = 8) -> None:
    """Create and modify files in the sandbox directory to trigger ransomware detection."""
    sandbox = Path(watch_dir)
    sandbox.mkdir(parents=True, exist_ok=True)

    extensions = [".docx", ".xlsx", ".pdf", ".txt", ".csv", ".encrypted", ".locked"]
    for i in range(count):
        ext = random.choice(extensions)
        name = "".join(random.choices(string.ascii_lowercase, k=6)) + ext
        filepath = sandbox / name
        try:
            filepath.write_text(f"Simulated content at {datetime.now().isoformat()}\n" * random.randint(1, 20))
        except Exception:
            pass
        time.sleep(0.05)

    # Modify some existing files rapidly (triggers ransomware detector)
    existing = [p for p in sandbox.glob("*") if p.name != ".gitkeep"]
    # Bounded simulation: clean up older files to prevent disk bloat
    if len(existing) > 25:
        for old_f in sorted(existing, key=lambda p: p.stat().st_mtime)[:len(existing) - 15]:
            try:
                old_f.unlink(missing_ok=True)
            except Exception:
                pass
        existing = [p for p in sandbox.glob("*") if p.name != ".gitkeep"]

    for f in random.sample(existing, min(5, len(existing))):
        try:
            with open(f, "a") as fh:
                fh.write(f"\nModified at {datetime.now().isoformat()}")
        except Exception:
            pass
        time.sleep(0.02)

    cprint(Colors.GREEN, "📂", f"Created/modified {count + min(5, len(existing))} sandbox files (ransomware trigger)")


def simulate_incident_report(base_url: str) -> None:
    """Generate an incident report."""
    types = ["malware", "phishing", "ddos", "intrusion", "ransomware", "port_scan"]
    severities = ["critical", "high", "medium"]
    body = {
        "incident_type": random.choice(types),
        "severity": random.choice(severities),
        "days": random.randint(1, 7),
    }
    result = post_json(f"{base_url}/api/reports/incident", body)
    if result and "error" not in result:
        cprint(Colors.GREEN, "📄", f"Incident report generated: {body['incident_type']} ({body['severity']})")
    else:
        cprint(Colors.YELLOW, "📄", f"Report request sent: {body['incident_type']}")


def simulate_autonomous_block(base_url: str) -> None:
    """Trigger an autonomous IP block."""
    ip = random.choice(ATTACKER_IPS)
    duration = random.choice([300, 600, 1800, 3600])
    result = post_query(f"{base_url}/api/autonomous/block-ip?ip={ip}&duration={duration}")
    if result and "error" not in result:
        cprint(Colors.RED, "⛔", f"Autonomous block: {ip} for {duration}s")
    else:
        cprint(Colors.YELLOW, "⛔", f"Block request sent: {ip}")


def simulate_brute_force(base_url: str) -> None:
    """Simulate a targeted brute-force password spraying attack on an auth port."""
    attacker = random.choice(ATTACKER_IPS)
    target = random.choice(INTERNAL_IPS)
    port = random.choice([22, 3389, 445])
    service = {22: "SSH", 3389: "RDP", 445: "SMB"}[port]
    cprint(Colors.RED, "💥", f"Simulating {service} Brute-Force from {attacker} to {target}:{port} (6 attempts)...")
    for _ in range(6):
        payload = {
            "src_ip": attacker,
            "dst_ip": target,
            "port": port,
            "protocol": "TCP",
            "direction": "inbound",
            "who": f"attacker_{attacker.split('.')[-1]}",
        }
        post_json(f"{base_url}/api/history/ports", payload)
        time.sleep(0.05)


def simulate_dns_tunneling(base_url: str) -> None:
    """Simulate high-entropy, long subdomain DNS Tunneling data exfiltration."""
    attacker = random.choice(INTERNAL_IPS)
    payload_slug = "".join(random.choices("abcdef0123456789", k=52))
    tunnel_domain = f"{payload_slug}.c2-exfil-node.net"
    cprint(Colors.RED, "📡", f"Simulating DNS Tunneling query: {tunnel_domain[:45]}... from {attacker}")
    post_json(f"{base_url}/api/history/searches", {
        "who": attacker,
        "query": f"DNS: {tunnel_domain}",
        "url": f"http://{tunnel_domain}",
        "meta": {"type": "DNS Query", "src": attacker},
    })


def simulate_dga_domains(base_url: str) -> None:
    """Simulate algorithmically generated domain (DGA) queries."""
    attacker = random.choice(INTERNAL_IPS)
    dga_base = "".join(random.choices("bcdfghjklmnpqrstvwxyz0123456789", k=16))
    dga_domain = f"{dga_base}.xyz"
    cprint(Colors.YELLOW, "🎲", f"Simulating DGA domain lookup: {dga_domain} from {attacker}")
    post_json(f"{base_url}/api/history/searches", {
        "who": attacker,
        "query": f"DNS: {dga_domain}",
        "url": f"http://{dga_domain}",
        "meta": {"type": "DNS Query", "src": attacker},
    })


def simulate_threat_feed_hits(base_url: str) -> None:
    """Simulate incoming traffic from known malicious IoC IPs from threat feeds."""
    known_bad_ip = random.choice(["185.220.101.5", "103.145.13.44", "194.26.29.114", "45.154.255.88"])
    target = random.choice(INTERNAL_IPS)
    cprint(Colors.RED, "⚠️", f"Simulating known Threat Feed IoC match from {known_bad_ip} to {target}:443")
    post_json(f"{base_url}/api/history/ports", {
        "src_ip": known_bad_ip,
        "dst_ip": target,
        "port": 443,
        "protocol": "TCP",
        "direction": "inbound",
        "who": "feodo_c2_bot",
    })


def print_dashboard_snapshot(base_url: str) -> None:
    """Fetch and display a quick snapshot of the system state."""
    metrics = get_json(f"{base_url}/api/metrics")
    alerts = get_json(f"{base_url}/api/alerts")
    threat = get_json(f"{base_url}/api/threat-summary")
    health = get_json(f"{base_url}/api/health")
    rules = get_json(f"{base_url}/api/rules")

    print()
    print(f"{Colors.CYAN}{Colors.BOLD}──── System Snapshot ────{Colors.END}")

    if metrics:
        pv = metrics.get("current_packet_velocity", 0)
        fcr = metrics.get("file_change_rate", 0)
        pm = "Active" if metrics.get("port_monitoring_active") else "Idle"
        proto = metrics.get("protocol_breakdown", {})
        proto_str = " | ".join(f"{k}: {v}" for k, v in proto.items()) if proto else "—"
        print(f"  Packet Velocity:  {Colors.BOLD}{pv}{Colors.END} pps")
        print(f"  Port Monitoring:  {pm}")
        print(f"  File Change Rate: {fcr} events/5s")
        print(f"  Protocols:        {proto_str}")

    if alerts:
        count = alerts.get("count", 0)
        print(f"  Active Alerts:    {Colors.BOLD}{count}{Colors.END}")

    if threat:
        level = threat.get("threat_level", "Low")
        score = threat.get("risk_score", 0)
        conf = threat.get("confidence", 0)
        color = Colors.RED if level in ("Critical", "High") else Colors.YELLOW if level in ("Medium", "Elevated") else Colors.GREEN
        print(f"  Threat Level:     {color}{Colors.BOLD}{level}{Colors.END} (score={score:.4f}, conf={conf:.2f})")

    if health:
        status = health.get("status", "unknown")
        rule_count = health.get("rules", 0)
        print(f"  Health:           {status} ({rule_count} rules)")

    if rules:
        print(f"  Firewall Rules:   {len(rules)} configured")

    print(f"{Colors.CYAN}{'─' * 32}{Colors.END}")
    print()


# ─── Main Loop ──────────────────────────────────────────────────────

def run_simulation_round(base_url: str, round_num: int, burst: bool = False) -> None:
    """Execute one round of simulated events."""
    now = datetime.now().strftime("%H:%M:%S")
    print(f"\n{Colors.BOLD}{Colors.CYAN}═══ Round {round_num} │ {now} ═══{Colors.END}\n")

    sandbox_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sandbox")

    # Every round: searches, file shares, sandbox activity
    simulate_search_history(base_url, count=random.randint(3, 8))
    simulate_file_shares(base_url, count=random.randint(2, 5))
    simulate_port_activity(base_url, count=random.randint(10, 20) if burst else random.randint(5, 12), burst=burst)
    simulate_sandbox_activity(sandbox_dir, count=random.randint(5, 15) if burst else random.randint(3, 8))

    # Post aggregate traffic metrics and active TCP sessions for the Traditional Traffic View
    try:
        simulate_traditional_traffic(base_url)
    except Exception:
        pass
    try:
        simulate_tcp_sessions(base_url, count=random.randint(3, 8))
    except Exception:
        pass

    # Most rounds: phishing checks
    if random.random() < 0.7:
        simulate_phishing_checks(base_url, count=random.randint(1, 3))

    # Phase 2 Attack Simulations (Brute force, DNS threats, Threat feed IoCs)
    if random.random() < 0.35:
        simulate_brute_force(base_url)
    if random.random() < 0.30:
        simulate_dns_tunneling(base_url)
    if random.random() < 0.25:
        simulate_dga_domains(base_url)
    if random.random() < 0.25:
        simulate_threat_feed_hits(base_url)

    # Sometimes: copilot queries
    if random.random() < 0.4:
        simulate_copilot_queries(base_url)

    # Occasionally: incident reports
    if random.random() < 0.25:
        simulate_incident_report(base_url)

    # Rarely: autonomous block
    if random.random() < 0.15:
        simulate_autonomous_block(base_url)

    # Show snapshot every round
    print_dashboard_snapshot(base_url)


def run_scenario_once(base_url: str, scenario: str) -> None:
    """Execute a specific targeted scenario once."""
    sandbox_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sandbox")
    cprint(Colors.CYAN, "🎯", f"Executing targeted scenario: {scenario.upper()}")
    if scenario == "brute-force":
        simulate_brute_force(base_url)
    elif scenario == "dns-tunneling":
        simulate_dns_tunneling(base_url)
    elif scenario == "dga":
        simulate_dga_domains(base_url)
    elif scenario == "threat-feed":
        simulate_threat_feed_hits(base_url)
    elif scenario == "ransomware":
        simulate_sandbox_activity(sandbox_dir, count=15)
    elif scenario == "phishing":
        simulate_phishing_checks(base_url, count=4)
    else:
        # Run all
        simulate_brute_force(base_url)
        simulate_dns_tunneling(base_url)
        simulate_dga_domains(base_url)
        simulate_threat_feed_hits(base_url)
        simulate_sandbox_activity(sandbox_dir, count=10)
    print_dashboard_snapshot(base_url)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Volcano AI Firewall — Event Simulator. Generates realistic events to test every dashboard feature.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python simulate_events.py                      # Run infinite simulation
  python simulate_events.py --scenario brute-force # Run specific attack scenario
  python simulate_events.py --scenario dns-tunneling
  python simulate_events.py --rounds 5           # Run 5 rounds then stop
  python simulate_events.py --burst --interval 1 # Rapid stress test
  python simulate_events.py --setup-only         # Create rules & exit
        """,
    )
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Backend URL (default: http://127.0.0.1:8000)")
    parser.add_argument("--rounds", type=int, default=0, help="Number of simulation rounds (0=infinite)")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL, help="Seconds between rounds (default: 2.0)")
    parser.add_argument("--burst", action="store_true", help="Burst mode — more events per round")
    parser.add_argument("--setup-only", action="store_true", help="Only create firewall rules, then exit")
    parser.add_argument(
        "--scenario",
        choices=["all", "brute-force", "dns-tunneling", "dga", "threat-feed", "ransomware", "phishing"],
        default=None,
        help="Run a specific targeted detection scenario",
    )
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")

    print(f"""
{Colors.BOLD}{Colors.CYAN}==================================================
     Volcano AI Firewall Event Simulator
=================================================={Colors.END}
""")

    # Check backend connectivity
    cprint(Colors.BLUE, "🔌", f"Connecting to {base_url}...")
    health = get_json(f"{base_url}/api/health")
    if not health:
        cprint(Colors.RED, "✗", f"Cannot connect to backend at {base_url}")
        cprint(Colors.YELLOW, "ℹ", "Start the backend first:  python app.py")
        return 1
    cprint(Colors.GREEN, "✓", f"Backend online: {health.get('status', 'unknown')}")

    # Phase 1: Setup firewall rules (first run only)
    print()
    simulate_firewall_rules(base_url)

    if args.setup_only:
        print()
        print_dashboard_snapshot(base_url)
        cprint(Colors.GREEN, "✓", "Setup complete. Firewall rules created.")
        return 0

    if args.scenario:
        print()
        run_scenario_once(base_url, args.scenario)
        return 0

    # Phase 2: Continuous simulation
    print()
    cprint(Colors.BLUE, "▶", f"Starting simulation (interval={args.interval}s, burst={'ON' if args.burst else 'OFF'})...")
    cprint(Colors.DIM, " ", "Press Ctrl+C to stop\n")

    round_num = 0
    try:
        while True:
            round_num += 1
            run_simulation_round(base_url, round_num, burst=args.burst)

            if args.rounds > 0 and round_num >= args.rounds:
                cprint(Colors.GREEN, "✓", f"Completed {args.rounds} rounds.")
                break

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Simulation stopped after {round_num} rounds.{Colors.END}")
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
