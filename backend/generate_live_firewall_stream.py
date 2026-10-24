from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from itertools import cycle
from typing import Any, Dict, Iterable, List


DEFAULT_BASE_URL = "http://127.0.0.1:8000"
DEFAULT_INTERVAL = 2.0
DEFAULT_LIMIT = 10


DEMO_ALERT_BLUEPRINTS = [
    {
        "source": "network",
        "severity": "high",
        "category": "Port Scan",
        "message": "Synthetic port-scan pattern detected across sequential ports.",
        "meta": {"protocol": "TCP", "unique_ports": [22, 80, 443, 445, 3389], "source_ip": "10.10.10.25"},
    },
    {
        "source": "network",
        "severity": "critical",
        "category": "DDoS Attack",
        "message": "Synthetic burst traffic crossed the packet-per-second threshold.",
        "meta": {"protocol": "UDP", "packets_per_second": 146, "source_ip": "172.16.24.8"},
    },
    {
        "source": "filesystem",
        "severity": "critical",
        "category": "Ransomware Alert",
        "message": "Synthetic high-frequency file modifications detected in sandbox.",
        "meta": {"event_type": "modified", "path": "sandbox\\client\\invoice.docx", "rate_5s": 19},
    },
    {
        "source": "system",
        "severity": "warning",
        "category": "Packet Sniffer Disabled",
        "message": "Synthetic fallback event while waiting for live packet capture.",
        "meta": {"protocol": "OTHER"},
    },
]


def fetch_json(url: str) -> Dict[str, Any]:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        payload = response.read().decode("utf-8")
    return json.loads(payload)


def clear_screen() -> None:
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


def clamp_text(value: Any, max_length: int = 120) -> str:
    text = "—" if value is None else str(value)
    return text if len(text) <= max_length else text[: max_length - 1] + "…"


def format_alert_ports(meta: Dict[str, Any]) -> str:
    if not meta:
        return "—"

    if isinstance(meta.get("unique_ports"), list) and meta["unique_ports"]:
        return ", ".join(str(port) for port in meta["unique_ports"][:6])

    port_samples = meta.get("port_samples")
    if isinstance(port_samples, list) and port_samples:
        samples = []
        for item in port_samples[:6]:
            if isinstance(item, dict) and item.get("port") is not None:
                protocol = item.get("protocol", meta.get("protocol", "UNKNOWN"))
                samples.append(f"{item['port']}/{protocol}")
        if samples:
            return ", ".join(samples)

    destination_port = meta.get("destination_port")
    if destination_port is not None:
        protocol = meta.get("protocol", "UNKNOWN")
        return f"{destination_port}/{protocol}"

    return "—"


def format_alert_protocol(meta: Dict[str, Any]) -> str:
    if not meta:
        return "—"
    return str(meta.get("protocol", "—"))


def render_key_value(label: str, value: Any, width: int = 18) -> str:
    return f"{label:<{width}} {clamp_text(value)}"


def render_alert_row(alert: Dict[str, Any]) -> str:
    meta = alert.get("meta") if isinstance(alert.get("meta"), dict) else {}
    timestamp = clamp_text(alert.get("timestamp", ""), 19)
    source = clamp_text(alert.get("source", ""), 12)
    port_info = clamp_text(format_alert_ports(meta), 28)
    protocol = clamp_text(format_alert_protocol(meta), 10)
    category = clamp_text(alert.get("category", ""), 18)
    severity = clamp_text(alert.get("severity", ""), 9)
    message = clamp_text(alert.get("message", ""), 80)
    return f"{timestamp:<20} {source:<10} {port_info:<28} {protocol:<10} {category:<18} {severity:<10} {message}"


def sorted_count_items(items: Dict[str, Any], reverse: bool = True) -> List[tuple[str, Any]]:
    return sorted(items.items(), key=lambda pair: pair[1], reverse=reverse)


def render_protocol_distribution(protocol_distribution: Dict[str, Any]) -> str:
    if not protocol_distribution:
        return "No protocol activity yet."
    return " | ".join(f"{protocol}: {count}" for protocol, count in sorted_count_items(protocol_distribution))


def format_top_port(top_ports: List[Dict[str, Any]]) -> str:
    if not top_ports:
        return "No port data"
    item = top_ports[0]
    port = item.get("port", "—")
    protocol = item.get("protocol", "UNKNOWN")
    count = item.get("count", 0)
    return f"{port}/{protocol} ({count} hits)"


def render_top_ports(top_ports: Iterable[Dict[str, Any]]) -> List[str]:
    lines: List[str] = []
    for index, item in enumerate(top_ports, start=1):
        port = item.get("port", "—")
        protocol = item.get("protocol", "UNKNOWN")
        count = item.get("count", 0)
        lines.append(f"{index:>2}. {port}/{protocol:<5}  hits={count}")
    return lines or ["No port activity yet."]


def render_top_sources(top_sources: Iterable[Dict[str, Any]]) -> List[str]:
    lines: List[str] = []
    for index, item in enumerate(top_sources, start=1):
        source_ip = item.get("source_ip", "—")
        direction = item.get("direction", "unknown")
        last_protocol = item.get("last_protocol", "UNKNOWN")
        count = item.get("count", 0)
        lines.append(f"{index:>2}. {source_ip:<15} {direction:<9} last={last_protocol:<5} hits={count}")
    return lines or ["No source activity yet."]


def render_section_title(title: str) -> None:
    print(f"\n{title}")
    print("-" * len(title))


def render_dashboard(payloads: Dict[str, Dict[str, Any]], limit: int) -> None:
    alerts = payloads.get("alerts", {}).get("alerts", [])
    metrics = payloads.get("metrics", {})
    threat = payloads.get("threat-summary", {})
    firewall = payloads.get("firewall-insights", {})

    if not alerts:
        alerts = build_demo_alert_stream(metrics, threat, firewall, limit)

    clear_screen()
    print("Volcano Live Firewall Stream")
    print(f"Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    print(render_key_value("Packet Velocity:", f"{metrics.get('current_packet_velocity', 0)} pps"))
    print(render_key_value("Port Monitoring:", "Active" if metrics.get("port_monitoring_active") else "Idle"))
    print(render_key_value("File Change Rate:", f"{metrics.get('file_change_rate', 0)} events / 5s"))
    print(render_key_value("Threat Level:", threat.get("threat_level", "Low")))
    print(render_key_value("Threat Score:", threat.get("risk_score", 0)))
    print(render_key_value("Confidence:", threat.get("confidence", 0)))
    print(render_key_value("Top Port:", format_top_port(firewall.get("top_ports", []))))

    render_section_title("Host-Level Threat Synthesis")
    print(render_key_value("Recommended:", threat.get("recommended_action", "—")))
    top_signals = threat.get("top_signals", [])
    if isinstance(top_signals, list) and top_signals:
        print("Signals: " + " | ".join(clamp_text(signal, 50) for signal in top_signals))
    else:
        print("Signals: None")
    protocol_distribution = firewall.get("protocol_distribution", {}) if isinstance(firewall.get("protocol_distribution"), dict) else {}
    print("Protocol mix: " + render_protocol_distribution(protocol_distribution))

    render_section_title("Firewall Insights")
    print("Top ports:")
    for line in render_top_ports(firewall.get("top_ports", [])[:limit]):
        print("  " + line)
    print("Top source IPs:")
    for line in render_top_sources(firewall.get("top_sources", [])[:limit]):
        print("  " + line)

    render_section_title("Live Event Stream")
    print(f"{'Time':<20} {'Source':<10} {'Port(s)':<28} {'Protocol':<10} {'Category':<18} {'Severity':<10} Message")
    print("-" * 120)
    for alert in alerts[-limit:]:
        print(render_alert_row(alert))


def build_demo_payloads(limit: int) -> Dict[str, Dict[str, Any]]:
    metrics = {
        "current_packet_velocity": 128,
        "port_monitoring_active": True,
        "file_change_rate": 3.8,
        "watch_directory": "sandbox",
        "protocol_breakdown": {"TCP": 88, "UDP": 40},
    }
    threat = {
        "risk_score": 0.86,
        "threat_level": "Critical",
        "recommended_action": "Isolate the host and inspect active compromise indicators immediately.",
        "confidence": 0.91,
        "top_signals": ["Traffic burst anomaly detected", "Port scan pattern detected"],
        "category_breakdown": {"Port Scan": 2, "DDoS Attack": 1},
        "severity_breakdown": {"critical": 2, "high": 1},
    }
    firewall = {
        "top_ports": [
            {"port": 443, "protocol": "TCP", "count": 42},
            {"port": 22, "protocol": "TCP", "count": 24},
            {"port": 53, "protocol": "UDP", "count": 18},
        ],
        "protocol_distribution": {"TCP": 88, "UDP": 40},
        "top_sources": [
            {"source_ip": "10.10.10.25", "direction": "inbound", "count": 24, "last_protocol": "TCP"},
            {"source_ip": "172.16.24.8", "direction": "inbound", "count": 18, "last_protocol": "UDP"},
        ],
        "recent_scan_alerts": [],
        "alert_count": limit,
    }

    payloads = {"alerts": {}, "metrics": metrics, "threat-summary": threat, "firewall-insights": firewall}
    payloads["alerts"]["alerts"] = build_demo_alert_stream(metrics, threat, firewall, limit)
    return payloads


def build_demo_alert_stream(
    metrics: Dict[str, Any],
    threat: Dict[str, Any],
    firewall: Dict[str, Any],
    limit: int,
) -> List[Dict[str, Any]]:
    now = datetime.now()
    threat_level = str(threat.get("threat_level", "Low"))
    threat_signals = threat.get("top_signals", []) if isinstance(threat.get("top_signals"), list) else []
    top_ports = firewall.get("top_ports", []) if isinstance(firewall.get("top_ports"), list) else []
    top_sources = firewall.get("top_sources", []) if isinstance(firewall.get("top_sources"), list) else []
    protocol_distribution = firewall.get("protocol_distribution", {}) if isinstance(firewall.get("protocol_distribution"), dict) else {}

    severity_map = {
        "Critical": "critical",
        "High": "high",
        "Elevated": "medium",
        "Low": "low",
    }

    generated: List[Dict[str, Any]] = []
    blueprint_cycle = cycle(DEMO_ALERT_BLUEPRINTS)

    for index in range(limit):
        blueprint = next(blueprint_cycle)
        template_meta = dict(blueprint.get("meta", {}))

        if top_ports:
            top_port = top_ports[index % len(top_ports)]
            template_meta.setdefault("unique_ports", [top_port.get("port", 0)])
            template_meta["protocol"] = top_port.get("protocol", template_meta.get("protocol", "UNKNOWN"))
            template_meta["destination_port"] = top_port.get("port", template_meta.get("destination_port"))

        if top_sources:
            top_source = top_sources[index % len(top_sources)]
            template_meta["source_ip"] = top_source.get("source_ip", template_meta.get("source_ip", "0.0.0.0"))
            template_meta.setdefault("direction", top_source.get("direction", "inbound"))

        if protocol_distribution:
            protocol_name = next(iter(protocol_distribution.keys()))
            template_meta.setdefault("protocol", protocol_name)

        generated.append(
            {
                "id": index + 1,
                "timestamp": (now.replace(microsecond=0)).isoformat(),
                "source": blueprint["source"],
                "severity": severity_map.get(threat_level, blueprint["severity"]),
                "category": blueprint["category"],
                "message": (
                    f"{blueprint['message']} Threat level {threat_level}. "
                    f"Signals: {', '.join(threat_signals[:2]) if threat_signals else 'none'}."
                ),
                "meta": template_meta,
            }
        )

    return generated


def load_payloads(base_url: str) -> Dict[str, Dict[str, Any]]:
    endpoints = {
        "alerts": f"{base_url}/api/alerts",
        "metrics": f"{base_url}/api/metrics",
        "threat-summary": f"{base_url}/api/threat-summary",
        "firewall-insights": f"{base_url}/api/firewall-insights",
    }
    payloads: Dict[str, Dict[str, Any]] = {}
    for key, url in endpoints.items():
        payloads[key] = fetch_json(url)
    return payloads


def main() -> int:
    parser = argparse.ArgumentParser(description="Render Volcano live event stream and host-level threat synthesis.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Backend base URL, e.g. http://127.0.0.1:8000")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL, help="Refresh interval in seconds.")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="How many alerts and insight rows to show.")
    parser.add_argument("--demo", action="store_true", help="Always render synthetic live events instead of backend alerts.")
    args = parser.parse_args()

    if args.interval < 0.5:
        print("Interval must be at least 0.5 seconds.", file=sys.stderr)
        return 2

    print(f"Connecting to {args.base_url} ...")
    time.sleep(0.2)

    try:
        while True:
            try:
                payloads = load_payloads(args.base_url.rstrip("/"))
                if args.demo or not payloads.get("alerts", {}).get("alerts"):
                    demo_payloads = build_demo_payloads(args.limit)
                    if args.demo:
                        payloads = demo_payloads
                    else:
                        payloads = {
                            "alerts": {"alerts": demo_payloads["alerts"]["alerts"]},
                            "metrics": payloads.get("metrics", demo_payloads["metrics"]),
                            "threat-summary": payloads.get("threat-summary", demo_payloads["threat-summary"]),
                            "firewall-insights": payloads.get("firewall-insights", demo_payloads["firewall-insights"]),
                        }
                render_dashboard(payloads, args.limit)
            except urllib.error.URLError as exc:
                payloads = build_demo_payloads(args.limit)
                render_dashboard(payloads, args.limit)
                print()
                print(f"Backend unavailable at {args.base_url}: {exc}")
                print("Showing synthetic demo stream. Start the backend with: python app.py")
            except json.JSONDecodeError as exc:
                payloads = build_demo_payloads(args.limit)
                render_dashboard(payloads, args.limit)
                print()
                print(f"Backend returned invalid JSON: {exc}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())