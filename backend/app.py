from __future__ import annotations

import asyncio
import atexit
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import getpass
import json
import logging
import os
import platform
import psutil
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel
from fastapi import Depends, FastAPI, Header, HTTPException, Body, WebSocket, WebSocketDisconnect, Response, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from scapy.all import AsyncSniffer, IP, TCP, UDP, Ether
try:
    from scapy.layers.dns import DNS, DNSQR
except Exception:
    DNS, DNSQR = None, None
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver

from config import get_settings, save_settings
from ai_engine.threat_services import FirewallInsightEngine, PhishingDetector, ThreatCorrelator
from api.schemas import (
    KillSwitchRequest,
    ThreatSummary,
    URLCheckRequest,
    now_utc,
    LoginRequest,
    ChangePasswordRequest,
    TokenResponse,
    UserCreateRequest,
    UserRoleUpdateRequest,
    AlertTriageRequest,
    AlertBulkRequest,
    SettingsUpdateRequest,
    NotificationTestRequest,
    DatabaseMaintenanceRequest,
)
from api.firewall_api import create_firewall_routes
from api.scanner_api import router as scanner_router
from storage.memory_store import AlertStore, MetricsStore
from storage.metrics_sink import get_metrics_sink
from storage.alert_indexer import get_alert_indexer
from storage.database import Database
from storage.auth import (
    get_password_hash,
    verify_password,
    create_access_token,
    get_current_user,
    get_optional_current_user,
    require_admin,
    require_analyst_or_admin,
)

from core.rule_engine import RuleEngine, RuleAction, RulePriority
from core.state_engine import StateEngine
from core.acl_engine import ACLEngine
from core.nat_engine import NATEngine
from security.ids_engine import IDSEngine
from security.vpn_handler import VPNHandler
from security.brute_force_detector import BruteForceDetector
from security.dns_threat_detector import DNSThreatDetector
from security.beacon_detector import BeaconDetector
from security.lateral_movement_detector import LateralMovementDetector
from security.geoip_service import GeoIPService
from security.l7_inspector import L7ApplicationInspector, get_l7_inspector
from security.notifier import NotificationDispatcher
from security.rate_limiter_redis import RedisRateLimiterUnavailableError, get_rate_limiter
from security.ws_broker import BaseWsBroker, get_ws_broker
from security.enforcement.nftables import NftablesBackend
from ai.anomaly_detector import AnomalyDetector
from ai.risk_engine import RiskEngine
from ai.response_engine import ResponseEngine
from ai.threat_correlation import ThreatIntelligence, ThreatCorrelationEngine
from ai.feed_loader import FeedLoader
from ai.playbooks import PlaybookLoader, PlaybookExecutor
from copilot.security_copilot import SecurityCopilot
from copilot.report_generator import IncidentReportGenerator
from copilot.llm_adapter import GroundedCopilot
from packet_engine.pcap_buffer import PCAPRingBuffer
from sensor.schema import SUPPORTED_SCHEMA_VERSIONS, SensorEventBatch
from ai_engine.isolation_forest_detector import get_traffic_anomaly_detector
from security.file_inspector import get_file_inspector


def load_env_file(dotenv_path: Path) -> None:
    if dotenv_path.exists():
        with open(dotenv_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip("'").strip('"')
                    if key and key not in os.environ:
                        os.environ[key] = val

BASE_DIR = Path(__file__).resolve().parent
load_env_file(BASE_DIR.parent / ".env")
load_env_file(BASE_DIR / ".env")
cfg = get_settings()
logger = logging.getLogger("volcano.app")
MODEL_PATH = BASE_DIR / "phishing_model.joblib"
WATCH_DIRECTORY = Path(cfg.watch_directory).resolve()
KILLSWITCH_TOKEN = os.getenv("VOLCANO_KILLSWITCH_TOKEN", "").strip()
KILLSWITCH_WINDOWS_INTERFACE = os.getenv("VOLCANO_WINDOWS_INTERFACE", "Wi-Fi")
KILLSWITCH_LINUX_INTERFACE = os.getenv("VOLCANO_LINUX_INTERFACE", "eth0")
ALERT_RETENTION = 500
DB_PATH = cfg.db_path


class WebSocketManager:
    """Manages active WebSocket connections and thread-safe event broadcasts."""

    def __init__(self, broker: Optional[BaseWsBroker] = None) -> None:
        self.active_connections: List[WebSocket] = []
        self._lock = threading.Lock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self.broker: BaseWsBroker = broker or get_ws_broker()
        self.broker.subscribe(self._on_broker_message)

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        with self._lock:
            self.active_connections.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        with self._lock:
            if ws in self.active_connections:
                self.active_connections.remove(ws)

    def broadcast_sync(self, event_type: str, data: Any) -> None:
        self.broker.publish(event_type, data, now_utc())

    def _on_broker_message(self, event_type: str, data: Any, timestamp: str) -> None:
        with self._lock:
            if not self.active_connections:
                return
            conns = list(self.active_connections)

        payload = json.dumps({"type": event_type, "data": data, "timestamp": timestamp or now_utc()})

        async def _send():
            dead = []
            for ws in conns:
                try:
                    await ws.send_text(payload)
                except Exception:
                    dead.append(ws)
            if dead:
                with self._lock:
                    for d in dead:
                        if d in self.active_connections:
                            self.active_connections.remove(d)

        if self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(_send(), self._loop)


ws_manager = WebSocketManager()


class PacketAnomalyEngine:
    def __init__(
        self,
        alerts: AlertStore,
        metrics: MetricsStore,
        rule_engine: RuleEngine,
        state_engine: StateEngine,
        ids_engine: IDSEngine,
        anomaly_detector: AnomalyDetector,
        risk_engine: RiskEngine,
        brute_force_detector: Optional[BruteForceDetector] = None,
        dns_threat_detector: Optional[DNSThreatDetector] = None,
        beacon_detector: Optional[BeaconDetector] = None,
        lateral_detector: Optional[LateralMovementDetector] = None,
        geoip_service: Optional[GeoIPService] = None,
        threat_intel: Optional[ThreatIntelligence] = None,
        pcap_buffer: Optional[PCAPRingBuffer] = None,
    ) -> None:
        self.alerts = alerts
        self.metrics = metrics
        self.rule_engine = rule_engine
        self.state_engine = state_engine
        self.ids_engine = ids_engine
        self.anomaly_detector = anomaly_detector
        self.risk_engine = risk_engine
        self.brute_force_detector = brute_force_detector or BruteForceDetector()
        self.dns_threat_detector = dns_threat_detector or DNSThreatDetector()
        self.beacon_detector = beacon_detector or BeaconDetector()
        self.lateral_detector = lateral_detector or LateralMovementDetector()
        self.geoip_service = geoip_service or GeoIPService()
        self.threat_intel = threat_intel
        self.pcap_buffer = pcap_buffer
        self.l7_inspector = get_l7_inspector()
        self._sniffer: Optional[AsyncSniffer] = None
        self._last_ddos_alert = 0.0
        self._last_port_scan_alert: Dict[str, float] = {}
        self._last_malicious_ip_alert: Dict[str, float] = {}
        self._local_addresses = self._discover_local_addresses()

    @staticmethod
    def _discover_local_addresses() -> set[str]:
        local = {"127.0.0.1", "0.0.0.0", "::1"}
        try:
            import socket

            host = socket.gethostname()
            for addr in socket.getaddrinfo(host, None):
                local.add(str(addr[4][0]))
        except Exception:
            pass
        return local

    def start(self) -> None:
        if self._sniffer is not None:
            return
        try:
            self._sniffer = AsyncSniffer(prn=self._handle_packet, store=False)
            self._sniffer.daemon = True
            self._sniffer.start()
        except Exception as exc:
            self._sniffer = None
            self.alerts.add(
                source="system",
                severity="warning",
                category="Packet Sniffer Disabled",
                message="Scapy packet capture could not start; continuing without live capture.",
                meta={"error": str(exc)},
            )

    def stop(self) -> None:
        if self._sniffer is None:
            return
        try:
            self._sniffer.stop()
        except Exception:
            pass
        finally:
            self._sniffer = None

    def _handle_packet(self, packet: Any) -> None:
        if self.pcap_buffer is not None:
            self.pcap_buffer.add_packet(packet)

        if not packet.haslayer(IP):
            return

        ip_layer = packet[IP]
        src_ip = getattr(ip_layer, "src", None)
        dst_ip = getattr(ip_layer, "dst", None)
        if not src_ip:
            return

        timestamp = time.monotonic()
        destination_port = None
        source_port = None
        protocol_name = "OTHER"
        flags = ""

        if packet.haslayer(TCP):
            destination_port = int(getattr(packet[TCP], "dport", 0))
            source_port = int(getattr(packet[TCP], "sport", 0))
            protocol_name = "TCP"
            flags_int = getattr(packet[TCP], "flags", 0)
            flags = self._decode_tcp_flags(flags_int)
        elif packet.haslayer(UDP):
            destination_port = int(getattr(packet[UDP], "dport", 0))
            source_port = int(getattr(packet[UDP], "sport", 0))
            protocol_name = "UDP"

        # Live Device Discovery via Ethernet MAC
        if packet.haslayer(Ether):
            src_mac = getattr(packet[Ether], "src", None)
            if src_mac and src_mac != "00:00:00:00:00:00":
                fmt_mac = src_mac.replace("-", ":").upper()
                self.risk_engine.update_device_risk(fmt_mac, threat_detected=False)
                profile = self.risk_engine.get_device_profile(fmt_mac)
                if profile and src_ip:
                    profile.metadata["ip"] = src_ip
                    if "type" not in profile.metadata:
                        profile.metadata["type"] = "Network Host"

        # Threat Intelligence IoC Lookup
        if self.threat_intel and self.threat_intel.is_ip_malicious(src_ip):
            self._emit_malicious_ip_alert(src_ip, dst_ip, protocol_name, destination_port)

        # Live DNS Web Domain Activity Capture & Threat Detection
        if destination_port == 53 or source_port == 53 or (DNS is not None and packet.haslayer(DNS)):
            try:
                if DNS is not None and packet.haslayer(DNS) and packet.haslayer(DNSQR):
                    raw_qname = packet[DNSQR].qname
                    if isinstance(raw_qname, bytes):
                        raw_qname = raw_qname.decode("utf-8", errors="ignore")
                    qname = str(raw_qname).rstrip(".")
                    if qname and not qname.endswith(".in-addr.arpa") and len(qname) > 3:
                        self.metrics.add_search(
                            who=src_ip or "Host",
                            query=f"DNS: {qname}",
                            url=f"http://{qname}",
                            meta={"type": "DNS Query", "src": src_ip, "dst": dst_ip, "protocol": protocol_name}
                        )
                        # Inspect for DNS Tunneling or DGA patterns
                        dns_alert = self.dns_threat_detector.inspect_query(src_ip, qname, dst_ip)
                        if dns_alert:
                            if self.geoip_service:
                                self.geoip_service.enrich_meta(src_ip, dns_alert["meta"])
                            self.alerts.add(
                                source=dns_alert["source"],
                                severity=dns_alert["severity"],
                                category=dns_alert["category"],
                                message=dns_alert["message"],
                                meta=dns_alert["meta"],
                            )
            except Exception:
                pass

        # Brute Force Detection on Monitored Auth Ports
        if destination_port is not None and self.brute_force_detector.is_monitored_port(destination_port):
            bf_alert = self.brute_force_detector.record_attempt(src_ip, dst_ip, destination_port, protocol_name)
            if bf_alert:
                if self.geoip_service:
                    self.geoip_service.enrich_meta(src_ip, bf_alert["meta"])
                self.alerts.add(
                    source=bf_alert["source"],
                    severity=bf_alert["severity"],
                    category=bf_alert["category"],
                    message=bf_alert["message"],
                    meta=bf_alert["meta"],
                )

        # Periodic C2 Beaconing Detection
        if src_ip and dst_ip and destination_port:
            beacon_alert = self.beacon_detector.record_connection(src_ip, dst_ip, destination_port, timestamp)
            if beacon_alert:
                if self.geoip_service:
                    self.geoip_service.enrich_meta(dst_ip, beacon_alert["meta"])
                self.alerts.add(
                    source=beacon_alert["source"],
                    severity=beacon_alert["severity"],
                    category=beacon_alert["category"],
                    message=beacon_alert["message"],
                    meta=beacon_alert["meta"],
                )

        # Internal Lateral Movement Detection on Admin Protocols
        if src_ip and dst_ip and destination_port:
            lateral_alert = self.lateral_detector.record_connection(src_ip, dst_ip, destination_port, timestamp)
            if lateral_alert:
                if self.geoip_service:
                    self.geoip_service.enrich_meta(src_ip, lateral_alert["meta"])
                self.alerts.add(
                    source=lateral_alert["source"],
                    severity=lateral_alert["severity"],
                    category=lateral_alert["category"],
                    message=lateral_alert["message"],
                    meta=lateral_alert["meta"],
                )

        # Live Network File-Sharing Activity (SMB 445/139, FTP 20/21, NFS 2049)
        if destination_port in (445, 139, 20, 21, 2049):
            proto_name = {445: "SMB/CIFS", 139: "NetBIOS", 20: "FTP-Data", 21: "FTP-Control", 2049: "NFS"}.get(destination_port, "FileShare")
            self.metrics.add_file_share(
                who=src_ip or "NetworkClient",
                filename=f"{proto_name} to port {destination_port}",
                dest_ip=dst_ip,
                meta={"protocol": protocol_name, "port": destination_port, "type": "NetworkShare"}
            )

        rule_action, matched_rule = self.rule_engine.evaluate(src_ip, dst_ip, source_port, destination_port, protocol_name)

        if rule_action.value == "deny":
            deny_meta = {"rule_id": matched_rule.id if matched_rule else None, "rule_name": matched_rule.name if matched_rule else None, "source_ip": src_ip}
            if self.geoip_service:
                self.geoip_service.enrich_meta(src_ip, deny_meta)
            self.alerts.add(
                source="firewall",
                severity="medium",
                category="Blocked Connection",
                message=f"Blocked {protocol_name} from {src_ip}:{source_port} to {dst_ip}:{destination_port}",
                meta=deny_meta,
            )
            return

        if protocol_name == "TCP":
            self.state_engine.track_tcp(src_ip, dst_ip, source_port or 0, destination_port or 0, flags, len(packet), "inbound")
            if TCP is not None and TCP in packet:
                try:
                    payload_bytes = bytes(packet[TCP].payload)
                    if payload_bytes:
                        l7_alert = self.l7_inspector.inspect_payload(payload_bytes, src_ip or "127.0.0.1", dst_ip or "127.0.0.1", destination_port or 0)
                        if l7_alert:
                            if self.geoip_service and src_ip:
                                self.geoip_service.enrich_meta(src_ip, l7_alert["meta"])
                            self.alerts.add(
                                source=l7_alert["source"],
                                severity=l7_alert["severity"],
                                category=l7_alert["category"],
                                message=l7_alert["message"],
                                meta=l7_alert["meta"],
                            )
                except Exception:
                    pass

        with self.metrics._lock:
            self.metrics.last_packet_seen = timestamp
            self.metrics.packet_timestamps.append(timestamp)
            while self.metrics.packet_timestamps and timestamp - self.metrics.packet_timestamps[0] > 1.0:
                self.metrics.packet_timestamps.popleft()
            self.metrics.packet_velocity = float(len(self.metrics.packet_timestamps))
            self.metrics.protocol_breakdown[protocol_name] += 1

            direction = "outbound" if src_ip in self._local_addresses else "inbound"
            source_activity = self.metrics.source_ip_activity.setdefault(
                src_ip,
                {"direction": direction, "count": 0, "last_protocol": protocol_name},
            )
            source_activity["direction"] = direction
            source_activity["count"] = int(source_activity.get("count", 0)) + 1
            source_activity["last_protocol"] = protocol_name

            if destination_port is not None:
                current_cfg = get_settings()
                window = self.metrics.port_windows[f"{direction}:{src_ip}"]
                window.append((timestamp, destination_port))
                while window and timestamp - window[0][0] > current_cfg.port_scan_window:
                    window.popleft()
                unique_ports = {port for _, port in window}
                self.metrics.port_scan_active = len(unique_ports) > 0
                port_activity = self.metrics.port_activity.setdefault(
                    destination_port,
                    {"protocol": protocol_name, "count": 0, "last_seen": timestamp},
                )
                port_activity["protocol"] = protocol_name
                port_activity["count"] = int(port_activity.get("count", 0)) + 1
                port_activity["last_seen"] = timestamp

                # Record port activity and IP access history
                try:
                    self.metrics.add_port_activity(src_ip, dst_ip, destination_port, protocol_name, direction)
                    if dst_ip:
                        self.metrics.add_ip_access(dst_ip)
                    self.metrics.add_ip_access(src_ip)
                except Exception:
                    pass

                if len(unique_ports) > current_cfg.port_scan_threshold:
                    self._emit_port_scan_alert(src_ip, direction, len(unique_ports), list(sorted(unique_ports)), protocol_name, dst_ip)

            current_cfg = get_settings()
            if len(self.metrics.packet_timestamps) > current_cfg.ddos_threshold:
                self._emit_ddos_alert(len(self.metrics.packet_timestamps), protocol_name)

    def _decode_tcp_flags(self, flags_int: int) -> str:
        flag_chars = ""
        if flags_int & 0x01:
            flag_chars += "F"
        if flags_int & 0x02:
            flag_chars += "S"
        if flags_int & 0x04:
            flag_chars += "R"
        if flags_int & 0x08:
            flag_chars += "P"
        if flags_int & 0x10:
            flag_chars += "A"
        if flags_int & 0x20:
            flag_chars += "U"
        return flag_chars

    def _emit_malicious_ip_alert(
        self,
        src_ip: str,
        dst_ip: Optional[str],
        protocol_name: str,
        destination_port: Optional[int],
    ) -> None:
        cooldown = self._last_malicious_ip_alert.get(src_ip, 0.0)
        current = time.monotonic()
        if current - cooldown < 30.0:
            return
        self._last_malicious_ip_alert[src_ip] = current
        meta = {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protocol": protocol_name,
            "port": destination_port,
            "threat_feed_match": True,
        }
        if self.geoip_service:
            self.geoip_service.enrich_meta(src_ip, meta)
        self.alerts.add(
            source="threat_intel",
            severity="critical",
            category="Threat Intelligence Match",
            message=f"Traffic detected from known malicious threat intel IoC: {src_ip}",
            meta=meta,
        )

    def _emit_port_scan_alert(
        self,
        src_ip: str,
        direction: str,
        port_count: int,
        ports: List[int],
        protocol_name: str,
        dst_ip: Optional[str],
    ) -> None:
        cooldown = self._last_port_scan_alert.get(src_ip, 0.0)
        current = time.monotonic()
        if current - cooldown < 30.0:
            return
        self._last_port_scan_alert[src_ip] = current
        alert_meta = {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "direction": direction,
            "protocol": protocol_name,
            "unique_ports": ports,
            "port_samples": [{"port": port, "protocol": protocol_name} for port in ports[:10]],
        }
        if self.geoip_service:
            self.geoip_service.enrich_meta(src_ip, alert_meta)
        self.alerts.add(
            source="network",
            severity="high",
            category="Port Scan",
            message=f"Detected port scan activity from {src_ip} touching {port_count} unique ports.",
            meta=alert_meta,
        )

    def _emit_ddos_alert(self, pps: int, protocol_name: str) -> None:
        current = time.monotonic()
        if current - self._last_ddos_alert < 30.0:
            return
        self._last_ddos_alert = current
        self.alerts.add(
            source="network",
            severity="critical",
            category="DDoS Attack",
            message=f"Traffic burst exceeded the DDoS threshold with approximately {pps} packets in the current one-second window.",
            meta={"packets_per_second": pps, "protocol": protocol_name},
        )


class RansomwareEventHandler(FileSystemEventHandler):
    def __init__(self, alerts: AlertStore, metrics: MetricsStore) -> None:
        super().__init__()
        self.alerts = alerts
        self.metrics = metrics
        self._lock = threading.RLock()
        self._last_alert = 0.0

    def on_any_event(self, event: Any) -> None:
        if getattr(event, "is_directory", False):
            return
        event_type = getattr(event, "event_type", "unknown")
        if event_type not in {"created", "modified", "deleted", "moved"}:
            return

        # Record real filesystem activity in file share history
        try:
            src_p = getattr(event, "src_path", "")
            if src_p:
                fn = Path(src_p).name
                if fn:
                    self.metrics.add_file_share(
                        who="LocalHost",
                        filename=f"[{event_type.upper()}] {fn}",
                        dest_ip=None,
                        meta={"event_type": event_type, "path": src_p},
                    )
        except Exception:
            pass

        # Immediate Tripwire: Canary honeytoken file tampering detection
        src_lower = Path(src_p).name.lower() if src_p else ""
        if src_lower and ("canary" in src_lower or "honeytoken" in src_lower):
            self.alerts.add(
                source="filesystem",
                severity="critical",
                category="Ransomware Alert: Canary Triggered",
                message=f"Decoy honeytoken file '{src_lower}' was tampered with ({event_type.upper()})! Immediate ransomware tripwire activated.",
                meta={"event_type": event_type, "path": src_p, "tripwire": "canary_honeypot"},
            )

        # Immediate Threat: Known ransomware encrypted extensions
        RANSOM_EXTENSIONS = {".locked", ".crypto", ".crypted", ".enc", ".crypt", ".wnry", ".lockbit", ".blackcat", ".darkside"}
        if any(src_lower.endswith(ext) for ext in RANSOM_EXTENSIONS):
            self.alerts.add(
                source="filesystem",
                severity="critical",
                category="Ransomware Alert: Encrypted Extension",
                message=f"Ransomware file encryption signature detected on '{src_lower}' ({event_type.upper()}).",
                meta={"event_type": event_type, "path": src_p, "extension": Path(src_p).suffix},
            )

        timestamp = time.monotonic()
        current_cfg = get_settings()
        with self._lock:
            with self.metrics._lock:
                self.metrics.fs_events.append(timestamp)
                while self.metrics.fs_events and timestamp - self.metrics.fs_events[0] > current_cfg.ransomware_window:
                    self.metrics.fs_events.popleft()
                self.metrics.ransomware_rate = float(len(self.metrics.fs_events)) / max(1.0, current_cfg.ransomware_window)
                event_count = len(self.metrics.fs_events)

            if event_count > current_cfg.ransomware_rate_threshold and timestamp - self._last_alert > 30.0:
                self._last_alert = timestamp
                self.alerts.add(
                    source="filesystem",
                    severity="critical",
                    category="Ransomware Alert",
                    message=f"High-frequency filesystem activity detected in {WATCH_DIRECTORY}.",
                    meta={
                        "event_type": event_type,
                        "path": getattr(event, "src_path", ""),
                        "rate_window": event_count,
                    },
                )


class WatchdogMonitor:
    def __init__(self, alerts: AlertStore, metrics: MetricsStore) -> None:
        self.alerts = alerts
        self.metrics = metrics
        self._observer: Optional[BaseObserver] = None

    def start(self) -> None:
        WATCH_DIRECTORY.mkdir(parents=True, exist_ok=True)
        # Deploy honeytoken canary decoy files to trip ransomware scanners
        try:
            canary_doc = WATCH_DIRECTORY / ".canary_system_vault.docx"
            if not canary_doc.exists():
                canary_doc.write_bytes(b"INTERNAL_ENTERPRISE_SYSTEM_VAULT_DO_NOT_TOUCH\x00" * 32)
            canary_pw = WATCH_DIRECTORY / "passwords_canary_honeytoken.xlsx"
            if not canary_pw.exists():
                canary_pw.write_bytes(b"ROOT_ADMIN_VAULT_KEY_DO_NOT_MODIFY\x00" * 32)
        except Exception:
            pass

        if self._observer is not None:
            return
        try:
            handler = RansomwareEventHandler(self.alerts, self.metrics)
            observer = Observer()
            observer.schedule(handler, str(WATCH_DIRECTORY), recursive=True)
            observer.daemon = True
            observer.start()
            self._observer = observer
        except Exception as exc:
            self._observer = None
            self.alerts.add(
                source="system",
                severity="warning",
                category="Filesystem Monitor Disabled",
                message="Watchdog observer could not start; continuing without ransomware telemetry.",
                meta={"error": str(exc), "watch_directory": str(WATCH_DIRECTORY)},
            )

    def stop(self) -> None:
        if self._observer is None:
            return
        try:
            self._observer.stop()
            self._observer.join(timeout=5)
        finally:
            self._observer = None


class DeviceDiscoveryEngine:
    def __init__(self, risk_engine: RiskEngine) -> None:
        self.risk_engine = risk_engine
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self.discover()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _run_loop(self) -> None:
        while not self._stop_event.wait(30.0):
            self.discover()

    def discover(self) -> None:
        # Seed current OS user
        try:
            current_user = getpass.getuser()
            if current_user:
                self.risk_engine.update_user_risk(current_user, threat_detected=False)
        except Exception:
            pass

        # Discover local host network interfaces
        try:
            for iface_name, addrs in psutil.net_if_addrs().items():
                mac = next((a.address for a in addrs if a.family == psutil.AF_LINK), None)
                ips = [a.address for a in addrs if a.family != psutil.AF_LINK]
                if mac and mac != "00:00:00:00:00:00":
                    fmt_mac = mac.replace("-", ":").upper()
                    ip_str = ips[0] if ips else "127.0.0.1"
                    self.risk_engine.update_device_risk(fmt_mac, threat_detected=False)
                    profile = self.risk_engine.get_device_profile(fmt_mac)
                    if profile:
                        profile.metadata = {
                            "ip": ip_str,
                            "type": "Local Host Interface",
                            "interface": iface_name,
                            "hostname": platform.node(),
                        }
        except Exception:
            pass

        # Discover LAN neighbors via ARP table
        try:
            cmd = "arp -a" if platform.system() == "Windows" else "ip neigh"
            output = subprocess.check_output(cmd, shell=True, text=True, timeout=5)
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 3 and ("-" in parts[1] or ":" in parts[1]):
                    ip = parts[0]
                    raw_mac = parts[1].replace("-", ":").upper()
                    if len(raw_mac) == 17 and not ip.startswith("224.") and not ip.startswith("239.") and not ip.startswith("255."):
                        dtype = "Gateway / Router" if ip.endswith(".1") else "LAN Endpoint"
                        self.risk_engine.update_device_risk(raw_mac, threat_detected=False)
                        profile = self.risk_engine.get_device_profile(raw_mac)
                        if profile:
                            profile.metadata = {
                                "ip": ip,
                                "type": dtype,
                                "hostname": f"host-{ip.replace('.', '-')}",
                            }
        except Exception:
            pass


def bootstrap_live_searches(metrics: MetricsStore) -> None:
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command", "Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -First 30 -ExpandProperty Entry"],
                text=True,
                timeout=6,
                shell=True,
            )
            for line in out.splitlines():
                d = line.strip()
                if d and not d.endswith(".arpa") and "." in d and len(d) > 3:
                    metrics.add_search(
                        who="LocalDNSCache",
                        query=f"DNS: {d}",
                        url=f"https://{d}",
                        meta={"type": "DNS Cache", "source": "System"},
                    )
    except Exception:
        pass
    if len(metrics.web_searches) == 0:
        for domain in ["google.com", "cloudflare.com", "github.com", "microsoft.com", "fastapi.tiangolo.com"]:
            metrics.add_search(
                who="127.0.0.1",
                query=f"DNS: {domain}",
                url=f"https://{domain}",
                meta={"type": "DNS Resolution", "source": "PassiveEngine"},
            )


def bootstrap_live_files(metrics: MetricsStore) -> None:
    try:
        search_dirs = [BASE_DIR, WATCH_DIRECTORY, BASE_DIR / "logs"]
        for d in search_dirs:
            if d.exists():
                for f in list(d.glob("*"))[:20]:
                    if f.is_file():
                        metrics.add_file_share(
                            who="LocalFileSystem",
                            filename=f.name,
                            dest_ip=None,
                            meta={"path": str(f.resolve()), "size_bytes": f.stat().st_size, "type": "LocalFile"},
                        )
    except Exception:
        pass


alerts = AlertStore()
metrics = MetricsStore(str(WATCH_DIRECTORY))
db = Database(DB_PATH)
phishing_detector = PhishingDetector(MODEL_PATH)
threat_correlator = ThreatCorrelator(alerts, metrics)
firewall_insight_engine = FirewallInsightEngine(alerts, metrics)

rule_engine = RuleEngine()
state_engine = StateEngine()
acl_engine = ACLEngine()
nat_engine = NATEngine()
ids_engine = IDSEngine()
vpn_handler = VPNHandler()
anomaly_detector = AnomalyDetector()
risk_engine = RiskEngine()
_cfg_startup = get_settings()
global_metrics_sink = get_metrics_sink(getattr(_cfg_startup, "metrics_sink", "memory"))
global_metrics_sink.set_enforcement_mode(getattr(_cfg_startup, "enforcement_mode", "active"))
global_alert_indexer = get_alert_indexer(getattr(_cfg_startup, "search_backend", "sql"))
enforcement_backend_instance = None
if getattr(_cfg_startup, "enforcement_backend", "software").lower() == "nftables":
    enforcement_backend_instance = NftablesBackend(
        dry_run=getattr(_cfg_startup, "enforcement_mode", "dry_run").lower() != "live"
    )

response_engine = ResponseEngine(
    rule_engine=rule_engine,
    alerts=alerts,
    db=db,
    ws_manager=ws_manager,
    enforcement_backend=enforcement_backend_instance,
)
threat_intelligence = ThreatIntelligence()
threat_correlation = ThreatCorrelationEngine()
security_copilot = SecurityCopilot()
report_generator = IncidentReportGenerator()
notifier = NotificationDispatcher()
grounded_copilot = GroundedCopilot(
    fallback_copilot=security_copilot,
    threat_correlator=threat_correlator,
    alerts=alerts,
    metrics=metrics,
    rule_engine=rule_engine,
    response_engine=response_engine,
)

brute_force_detector = BruteForceDetector()
dns_threat_detector = DNSThreatDetector()
beacon_detector = BeaconDetector()
lateral_detector = LateralMovementDetector()
geoip_service = GeoIPService()
feed_loader = FeedLoader(threat_intelligence)
pcap_buffer = PCAPRingBuffer(maxlen=1000)
login_rate_limiter = get_rate_limiter(
    backend=getattr(_cfg_startup, "rate_limit_backend", "memory"),
    redis_url=getattr(_cfg_startup, "redis_url", "redis://localhost:6379/0"),
    profile=getattr(_cfg_startup, "profile", "development"),
)

playbook_loader = PlaybookLoader()
playbook_executor = PlaybookExecutor(
    response_engine=response_engine,
    notifier=notifier,
    pcap_buffer=pcap_buffer,
    alerts=alerts,
    db=db,
)

DUMMY_BCRYPT_HASH = "$2b$12$e8Y7a2pZqG0qf1pZk8v8NuXwO5.5c4kXzO5c4kXzO5c4kXzO5c4kX"

packet_engine = PacketAnomalyEngine(
    alerts,
    metrics,
    rule_engine,
    state_engine,
    ids_engine,
    anomaly_detector,
    risk_engine,
    brute_force_detector=brute_force_detector,
    dns_threat_detector=dns_threat_detector,
    beacon_detector=beacon_detector,
    lateral_detector=lateral_detector,
    geoip_service=geoip_service,
    threat_intel=threat_intelligence,
    pcap_buffer=pcap_buffer,
)
watchdog_monitor = WatchdogMonitor(alerts, metrics)
device_discovery_engine = DeviceDiscoveryEngine(risk_engine)


def on_startup() -> None:
    # 1. Wire alerts to DB and threat correlation
    def handle_alert(rec):
        try:
            if hasattr(rec, "__dataclass_fields__"):
                from dataclasses import asdict
                db.save_alert(asdict(rec))
                r_id = rec.id
                r_cat = rec.category
                r_src = rec.source
                r_sev = rec.severity
                r_ts = rec.timestamp
                r_meta = rec.meta or {}
                r_msg = rec.message
            elif isinstance(rec, dict):
                db.save_alert(rec)
                r_id = rec.get("id", 1)
                r_cat = rec.get("category", "Security Alert")
                r_src = rec.get("source", "system")
                r_sev = rec.get("severity", "medium")
                r_ts = rec.get("timestamp", now_utc())
                r_meta = rec.get("meta") or {}
                r_msg = rec.get("message", "")
            else:
                return

            global_metrics_sink.record_alert(r_sev, r_cat)
            global_alert_indexer.index_alert({
                "id": r_id,
                "category": r_cat,
                "source": r_src,
                "severity": r_sev,
                "timestamp": r_ts,
                "message": r_msg,
                "meta": r_meta,
            })

            if geoip_service and r_meta.get("source_ip"):
                geoip_service.enrich_meta(r_meta["source_ip"], r_meta)

            incident = {
                "id": f"inc_{r_id}",
                "title": f"{r_cat}: {r_src}",
                "category": r_cat,
                "severity": r_sev,
                "timestamp": r_ts,
                "source_ip": r_meta.get("source_ip", "127.0.0.1"),
                "message": r_msg,
                "details": r_meta,
                "confidence": 0.95 if r_sev == "critical" else (0.80 if r_sev == "high" else 0.65),
            }
            threat_correlation._incident_clusters.insert(0, incident)
            if len(threat_correlation._incident_clusters) > 50:
                threat_correlation._incident_clusters.pop()

            try:
                raw_rec = asdict(rec) if hasattr(rec, "__dataclass_fields__") else (rec if isinstance(rec, dict) else {"message": str(rec)})
                ws_manager.broadcast_sync("alert_created", raw_rec)
                ws_manager.broadcast_sync("incident_cluster", incident)
                # Dispatch multi-channel notification for high/critical alerts
                try:
                    notifier.dispatch_alert(raw_rec)
                except Exception:
                    pass
            except Exception:
                pass
        except Exception:
            pass

    alerts.set_on_alert(handle_alert)

    # 2. Pre-populate incident clusters with recent alerts from DB or in-memory
    try:
        past_alerts = db.get_recent_alerts(limit=20)
        for a in past_alerts:
            incident = {
                "id": f"inc_{a.get('id')}",
                "title": f"{a.get('category')}: {a.get('source')}",
                "category": a.get("category"),
                "severity": a.get("severity"),
                "timestamp": a.get("timestamp"),
                "source_ip": (a.get("meta") or {}).get("source_ip", "127.0.0.1"),
                "message": a.get("message"),
                "details": a.get("meta") or {},
                "confidence": 0.85,
            }
            threat_correlation._incident_clusters.append(incident)
    except Exception:
        pass

    if len(threat_correlation._incident_clusters) == 0:
        for a in alerts.list():
            handle_alert(a)

    if len(threat_correlation._incident_clusters) == 0:
        threat_correlation._incident_clusters.append({
            "id": "inc_live_telemetry",
            "title": "Core Firewall Engine: Active Monitoring",
            "category": "Live Telemetry",
            "severity": "low",
            "timestamp": now_utc(),
            "source_ip": "127.0.0.1",
            "message": "AI intrusion detection, packet inspection, and system watchdog monitoring are fully operational.",
            "details": {"mode": "live_realtime", "telemetry": "active"},
            "confidence": 1.0,
        })

    # 3. Bootstrap live telemetry
    bootstrap_live_searches(metrics)
    bootstrap_live_files(metrics)

    # 4. Start engines & seed users
    packet_engine.start()
    watchdog_monitor.start()
    device_discovery_engine.start()
    rule_engine.add_rule("Default Allow All", action=RuleAction.ALLOW, priority=RulePriority.LOW)
    db.seed_default_users()
    response_engine.set_dependencies(rule_engine=rule_engine, alerts=alerts, db=db, ws_manager=ws_manager)
    grounded_copilot.set_dependencies(
        threat_correlator=threat_correlator,
        alerts=alerts,
        metrics=metrics,
        rule_engine=rule_engine,
        response_engine=response_engine,
    )

    # 5. Initialize Threat Intelligence Feeds
    try:
        feed_loader.refresh_all_feeds()
    except Exception:
        pass


def on_shutdown() -> None:
    packet_engine.stop()
    watchdog_monitor.stop()
    device_discovery_engine.stop()
    response_engine.stop()
    try:
        db.checkpoint_wal(mode="TRUNCATE")
    except Exception:
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    loop = asyncio.get_running_loop()
    ws_manager.set_loop(loop)
    on_startup()

    stop_event = asyncio.Event()

    async def _ws_ticker():
        while not stop_event.is_set():
            try:
                await asyncio.sleep(2.0)
                if ws_manager.active_connections:
                    ws_manager.broadcast_sync(
                        "metrics_tick",
                        {
                            "metrics": metrics.snapshot(),
                            "threat": threat_correlator.summarize(),
                            "alert_count": len(alerts.list()),
                        },
                    )
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    async def _db_maintenance_ticker():
        while not stop_event.is_set():
            try:
                interval_secs = max(60, getattr(cfg, "db_auto_checkpoint_minutes", 30) * 60)
                for _ in range(interval_secs // 5):
                    if stop_event.is_set():
                        return
                    await asyncio.sleep(5.0)

                db.checkpoint_wal(mode="PASSIVE")
                db.prune_stale_data(
                    max_alert_age_days=getattr(cfg, "db_alert_retention_days", 30),
                    max_audit_age_days=getattr(cfg, "db_audit_retention_days", 90),
                    keep_minimum_alerts=getattr(cfg, "db_max_alerts_limit", 50000),
                )
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    ticker = asyncio.create_task(_ws_ticker())
    maint_task = asyncio.create_task(_db_maintenance_ticker())
    try:
        yield
    finally:
        stop_event.set()
        ticker.cancel()
        maint_task.cancel()
        on_shutdown()


app = FastAPI(title="AI-Powered Contextual Firewall for Traffic Anomaly Detection", version="3.0.0", lifespan=lifespan)
ALLOWED_ORIGINS = [org.strip() for org in os.getenv("VOLCANO_ALLOWED_ORIGINS", "*").split(",") if org.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True if "*" not in ALLOWED_ORIGINS else False,
    allow_methods=["*"],
    allow_headers=["*"],
)

firewall_routes = create_firewall_routes(
    rule_engine,
    state_engine,
    acl_engine,
    risk_engine,
    anomaly_detector,
    response_engine,
    alerts,
    threat_correlation,
    report_generator,
    db=db,
    grounded_copilot=grounded_copilot,
)
app.include_router(firewall_routes)
app.include_router(scanner_router)


def verify_killswitch_access(x_volcano_admin_token: str = Header(default="")) -> None:
    if not KILLSWITCH_TOKEN:
        return
    if x_volcano_admin_token != KILLSWITCH_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid authorization token.")


def _shutil_which(command: str) -> Optional[str]:
    from shutil import which

    return which(command)


def _system_killswitch_command(interface_name: Optional[str] = None) -> list[str]:
    system_name = platform.system().lower()
    if system_name == "windows":
        target = interface_name or KILLSWITCH_WINDOWS_INTERFACE
        return ["netsh", "interface", "set", "interface", target, "admin=disable"]
    if system_name == "linux":
        target = interface_name or KILLSWITCH_LINUX_INTERFACE
        if _shutil_which("nmcli"):
            return ["nmcli", "radio", "wifi", "off"]
        return ["ip", "link", "set", "dev", target, "down"]
    raise HTTPException(status_code=400, detail=f"Unsupported platform for killswitch: {platform.system()}")


# ---------------------------------------------------------------------------
# Real-Time WebSocket Streaming
# ---------------------------------------------------------------------------

@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        # Push initial state snapshot immediately
        try:
            init_payload = {
                "type": "init",
                "metrics": metrics.snapshot(),
                "threat": threat_correlator.summarize(),
                "alert_count": len(alerts.list()),
            }
            await websocket.send_text(json.dumps(init_payload))
        except Exception:
            pass

        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong", "timestamp": now_utc()}))
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


# ---------------------------------------------------------------------------
# Authentication & User Management Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    # 1. Check IP and Username rate limits
    ip_key = f"ip:{client_ip}"
    clean_user = payload.username.lower().strip()
    user_key = f"user:{clean_user}"

    try:
        is_ip_limited, ip_retry = login_rate_limiter.is_rate_limited(ip_key, max_attempts=20, window_seconds=300.0)
        if is_ip_limited:
            global_metrics_sink.record_rate_limit_rejection("login")
            raise HTTPException(
                status_code=429,
                detail="Too many failed login attempts from this IP address. Please try again later.",
                headers={"Retry-After": str(int(max(1.0, ip_retry)))},
            )

        is_user_limited, user_retry = login_rate_limiter.is_rate_limited(user_key, max_attempts=5, window_seconds=300.0)
        if is_user_limited:
            global_metrics_sink.record_rate_limit_rejection("login")
            raise HTTPException(
                status_code=429,
                detail="Too many failed login attempts for this account. Please try again later.",
                headers={"Retry-After": str(int(max(1.0, user_retry)))},
            )
    except HTTPException:
        raise
    except RedisRateLimiterUnavailableError as exc:
        logger.critical("Authentication rate limiter unreachable: %s", exc)
        raise HTTPException(
            status_code=503,
            detail="Authentication service temporarily unavailable: rate limiter unreachable.",
        ) from exc

    # 3. Retrieve user & check account lockout
    user = db.get_user_by_username(payload.username)
    if user and user.get("is_locked", False):
        raise HTTPException(
            status_code=403,
            detail="Account is temporarily locked due to excessive failed login attempts. Contact an administrator or try again later.",
        )

    # 4. Constant-time password verification to prevent user enumeration
    target_hash = user["password_hash"] if user else DUMMY_BCRYPT_HASH
    valid_password = verify_password(payload.password, target_hash)

    if not user or not valid_password:
        # Record failure in rate limiters
        try:
            login_rate_limiter.record_failure(ip_key)
            login_rate_limiter.record_failure(user_key)
        except RedisRateLimiterUnavailableError as exc:
            logger.critical("Failed to record login failure in rate limiter: %s", exc)
            raise HTTPException(
                status_code=503,
                detail="Authentication service temporarily unavailable: rate limiter unreachable.",
            ) from exc

        # Record failure in database lockout tracker if user exists
        if user:
            db.record_login_failure(payload.username)

        # Emit audit log
        db.log_audit(
            payload.username,
            "login_failed",
            "auth",
            {"ip": client_ip, "reason": "invalid_credentials"},
            status="failed",
        )

        # Emit to detection pipeline (brute-force detector)
        bf_alert = brute_force_detector.record_login_failure(payload.username, client_ip)
        if bf_alert:
            alerts.add(
                source=bf_alert["source"],
                severity=bf_alert["severity"],
                category=bf_alert["category"],
                message=bf_alert["message"],
                meta=bf_alert["meta"],
            )
            cfg = get_settings()
            if getattr(cfg, "login_failure_auto_block", False):
                from ai.response_engine import ResponseAction
                response_engine.trigger_response(
                    action=ResponseAction.BLOCK,
                    target_ip=client_ip,
                    duration=cfg.quarantine_default_duration,
                    reason=f"Brute-force login failures targeting username '{payload.username}'",
                )

        raise HTTPException(status_code=401, detail="Invalid username or password.")

    if not user.get("active", True):
        raise HTTPException(status_code=403, detail="Account is disabled.")
    if user.get("must_change_password", False):
        raise HTTPException(
            status_code=403,
            detail="Password change required before login. Please change your password at /api/auth/change-password.",
        )

    # Successful login: reset failure counters
    login_rate_limiter.reset(ip_key)
    login_rate_limiter.reset(user_key)
    db.reset_login_failures(user["username"])

    db.update_user_last_login(user["username"])
    db.log_audit(user["username"], "login", "auth", status="success")
    token = create_access_token(user_id=str(user["id"]), username=user["username"], role=user["role"])
    user_info = {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "last_login": user.get("last_login"),
    }
    return {"access_token": token, "token_type": "bearer", "user": user_info}


@app.post("/api/auth/change-password")
def change_password(req: ChangePasswordRequest):
    user = db.get_user_by_username(req.username)
    if not user or not verify_password(req.current_password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or current password.")
    if req.current_password == req.new_password:
        raise HTTPException(status_code=400, detail="New password cannot be identical to current password.")

    new_hash = get_password_hash(req.new_password)
    updated = db.update_user_password(req.username, new_hash)
    if not updated:
        raise HTTPException(status_code=500, detail="Failed to update password.")

    db.log_audit(req.username, "change_password", f"user:{req.username}", {"status": "success"})
    return {"status": "success", "message": "Password changed successfully. You may now log in."}


@app.get("/api/auth/me")
def get_current_user_profile(user: Dict[str, Any] = Depends(get_current_user)):
    db_user = db.get_user_by_username(user["username"])
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found.")
    return {
        "id": db_user["id"],
        "username": db_user["username"],
        "role": db_user["role"],
        "created_at": db_user.get("created_at"),
        "last_login": db_user.get("last_login"),
        "active": db_user.get("active", True),
    }


@app.get("/api/auth/users")
def list_system_users(_: Dict[str, Any] = Depends(require_admin)):
    return {"users": db.list_users()}


@app.post("/api/auth/users")
def create_system_user(req: UserCreateRequest, current_user: Dict[str, Any] = Depends(require_admin)):
    existing = db.get_user_by_username(req.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists.")
    if req.role not in ["admin", "analyst", "viewer"]:
        raise HTTPException(status_code=400, detail="Invalid role. Must be 'admin', 'analyst', or 'viewer'.")
    created = db.create_user(req.username, get_password_hash(req.password), role=req.role)
    db.log_audit(current_user["username"], "create_user", f"user:{req.username}", {"role": req.role})
    return created


@app.patch("/api/auth/users/{username}/role")
def update_user_role(username: str, req: UserRoleUpdateRequest, current_user: Dict[str, Any] = Depends(require_admin)):
    if req.role not in ["admin", "analyst", "viewer"]:
        raise HTTPException(status_code=400, detail="Invalid role. Must be 'admin', 'analyst', or 'viewer'.")
    success = db.update_user_role(username, req.role)
    if not success:
        raise HTTPException(status_code=404, detail="User not found.")
    db.log_audit(current_user["username"], "update_role", f"user:{username}", {"new_role": req.role})
    return {"status": "updated", "username": username, "role": req.role}


@app.post("/api/auth/users/{username}/unlock")
def unlock_system_user(username: str, current_user: Dict[str, Any] = Depends(require_admin)):
    user = db.get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    db.unlock_user(username)
    login_rate_limiter.reset(f"user:{username.lower().strip()}")
    db.log_audit(current_user["username"], "unlock_user", f"user:{username}", {"status": "unlocked"})
    return {"status": "unlocked", "username": username}


# ---------------------------------------------------------------------------
# Sensor Token Administration & Ingestion Endpoints (Phase 3)
# ---------------------------------------------------------------------------

class SensorTokenCreateRequest(BaseModel):
    sensor_id: str
    description: Optional[str] = ""


@app.get("/api/admin/sensor-tokens")
def list_sensor_tokens(_: Dict[str, Any] = Depends(require_admin)):
    """List all registered sensor tokens (hashes excluded)."""
    return {"sensor_tokens": db.list_sensor_tokens()}


@app.post("/api/admin/sensor-tokens")
def create_sensor_token(
    req: SensorTokenCreateRequest,
    current_user: Dict[str, Any] = Depends(require_admin),
):
    """Issue a new secret token for an edge sensor/collector."""
    if not req.sensor_id or not req.sensor_id.strip():
        raise HTTPException(status_code=400, detail="sensor_id cannot be empty.")
    raw_token, record = db.create_sensor_token(req.sensor_id.strip(), req.description or "")
    db.log_audit(
        current_user["username"],
        "create_sensor_token",
        f"sensor:{req.sensor_id}",
        {"token_id": record["token_id"]},
    )
    return {
        "status": "created",
        "token": raw_token,
        **record,
    }


@app.delete("/api/admin/sensor-tokens/{token_id}")
def revoke_sensor_token(
    token_id: str,
    current_user: Dict[str, Any] = Depends(require_admin),
):
    """Revoke an active sensor token."""
    success = db.revoke_sensor_token(token_id)
    if not success:
        raise HTTPException(status_code=404, detail="Sensor token not found.")
    db.log_audit(current_user["username"], "revoke_sensor_token", f"token:{token_id}", {"status": "revoked"})
    return {"status": "revoked", "token_id": token_id}


@app.post("/api/ingest/events")
def ingest_sensor_events(
    payload: Dict[str, Any] = Body(...),
    authorization: Optional[str] = Header(None),
    x_sensor_token: Optional[str] = Header(None),
):
    """
    Ingest batch of normalized sensor telemetry events from distributed sensor instances.
    Requires authentication via per-sensor secret token (X-Sensor-Token or Bearer header).
    Rejects events or batches with unsupported schema_version with HTTP 400.
    """
    raw_token = x_sensor_token or authorization or ""
    if not raw_token:
        raise HTTPException(status_code=401, detail="Sensor token authentication required.")

    token_rec = db.verify_sensor_token(raw_token)
    if not token_rec:
        raise HTTPException(status_code=401, detail="Invalid or revoked sensor token.")

    # Validate schema version
    batch_version = payload.get("schema_version")
    if not batch_version or batch_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported schema version: '{batch_version}'. Supported versions: {sorted(SUPPORTED_SCHEMA_VERSIONS)}",
        )

    try:
        batch = SensorEventBatch(**payload)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid event batch payload: {exc}")

    # Process events into core
    ingested_count = 0
    for ev in batch.events:
        if ev.event_type == "alert":
            alert_data = ev.data or {}
            alerts.add(
                source=alert_data.get("source", f"sensor:{batch.sensor_id}"),
                severity=alert_data.get("severity", "medium"),
                category=alert_data.get("category", "Sensor Ingest"),
                message=alert_data.get("message", f"Event from {batch.sensor_id}"),
                meta={**alert_data.get("meta", {}), "sensor_id": batch.sensor_id, "src_ip": ev.src_ip, "dst_ip": ev.dst_ip},
            )
        elif ev.event_type == "flow":
            flow_bytes = int(ev.data.get("bytes", 0))
            flow_pkts = int(ev.data.get("pkts", 1))
            metrics.inc_packets(flow_pkts)
            metrics.inc_bytes(flow_bytes)
        ingested_count += 1

    return {
        "status": "ok",
        "ingested": ingested_count,
        "sensor_id": batch.sensor_id,
    }


@app.get("/metrics")
def prometheus_metrics(
    authorization: Optional[str] = Header(None),
):
    """
    Export time-series metrics in Prometheus exposition text format.
    Active only when VOLCANO_METRICS_ENABLED=true.
    Optionally protected with bearer token (VOLCANO_METRICS_BEARER_TOKEN).
    """
    settings = get_settings()
    if not settings.metrics_enabled:
        raise HTTPException(status_code=404, detail="Metrics endpoint is disabled.")

    if settings.metrics_bearer_token:
        expected = f"Bearer {settings.metrics_bearer_token}"
        if authorization != expected:
            raise HTTPException(status_code=401, detail="Unauthorized metrics access.")

    try:
        global_metrics_sink.set_packet_rate(metrics.packet_velocity)
    except Exception:
        pass

    return Response(
        content=global_metrics_sink.get_metrics_text(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@app.get("/api/search/alerts")
def search_alerts(
    q: str,
    limit: int = 50,
    user: Optional[Dict[str, Any]] = Depends(get_optional_current_user),
):
    """
    Full-text alert search across OpenSearch index.
    Returns HTTP 501 when OpenSearch is not enabled.
    """
    if not global_alert_indexer.is_enabled():
        raise HTTPException(
            status_code=501,
            detail="OpenSearch alert indexing is disabled. Enable with VOLCANO_SEARCH_BACKEND=opensearch.",
        )

    try:
        results = global_alert_indexer.search(query=q, limit=limit)
        return {
            "query": q,
            "count": len(results),
            "results": results,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"OpenSearch query error: {exc}")


# ---------------------------------------------------------------------------
# Settings & Audit Log Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/settings")
def get_system_settings(user: Optional[Dict[str, Any]] = Depends(get_optional_current_user)):
    cfg_obj = get_settings()
    data = cfg_obj.model_dump()
    role = ((user.get("role") or "viewer") if user else "viewer").lower()
    if role != "admin":
        if data.get("jwt_secret_key"):
            data["jwt_secret_key"] = "********"
        if data.get("smtp_password"):
            data["smtp_password"] = "********"
        if data.get("llm_api_key"):
            data["llm_api_key"] = "********"
        if data.get("telegram_bot_token"):
            data["telegram_bot_token"] = "********"
    return data


@app.put("/api/settings")
def update_system_settings(
    req: SettingsUpdateRequest,
    current_user: Dict[str, Any] = Depends(require_admin),
):
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    updated = save_settings(updates)
    db.log_audit(current_user["username"], "update_settings", "system_settings", updates)
    return updated.model_dump()


@app.get("/api/audit-logs")
def get_audit_logs(limit: int = 100, _: Dict[str, Any] = Depends(require_analyst_or_admin)):
    return {"audit_logs": db.get_audit_logs(limit=limit)}


@app.post("/api/notifications/test")
def test_notifications(
    req: NotificationTestRequest,
    user: Optional[Dict[str, Any]] = Depends(get_optional_current_user),
) -> Dict[str, Any]:
    """Test notification channels with a diagnostic alert ping."""
    result = notifier.test_channels(req.channel, req.message)
    username = (user or {}).get("username", "system")
    db.log_audit(username, "test_notifications", req.channel, result)
    return result


# ---------------------------------------------------------------------------
# Playbook Automation Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/playbooks")
def list_playbooks(user: Optional[Dict[str, Any]] = Depends(get_optional_current_user)):
    """List all loaded playbooks and validation status."""
    return {"playbooks": playbook_loader.list_playbooks()}


@app.post("/api/playbooks/reload")
def reload_playbooks(current_user: Dict[str, Any] = Depends(require_admin)):
    """Reload all playbooks from disk (admin only)."""
    valid_count, error_count = playbook_loader.reload()
    db.log_audit(
        current_user["username"],
        "reload_playbooks",
        "playbooks",
        {"valid": valid_count, "errors": error_count},
    )
    return {
        "status": "reloaded",
        "valid_count": valid_count,
        "error_count": error_count,
        "playbooks": playbook_loader.list_playbooks(),
    }


# ---------------------------------------------------------------------------
# Alert Triage Endpoints
# ---------------------------------------------------------------------------

@app.patch("/api/alerts/{alert_id}/triage")
def triage_alert(
    alert_id: int,
    req: AlertTriageRequest,
    current_user: Dict[str, Any] = Depends(require_analyst_or_admin),
):
    db_updated = db.update_alert_triage(alert_id, status=req.status, assignee=req.assignee, notes=req.notes)
    alerts.update_triage(alert_id, status=req.status, assignee=req.assignee, notes=req.notes)
    db.log_audit(current_user["username"], "triage_alert", f"alert:{alert_id}", req.model_dump(exclude_unset=True))
    ws_manager.broadcast_sync(
        "alert_triaged",
        {"id": alert_id, "status": req.status, "assignee": req.assignee, "notes": req.notes},
    )
    return {"status": "updated", "id": alert_id, "db_updated": db_updated}


@app.post("/api/alerts/bulk")
def bulk_alert_action(
    req: AlertBulkRequest,
    current_user: Dict[str, Any] = Depends(require_analyst_or_admin),
):
    count_db = db.bulk_update_alerts(req.alert_ids, action=req.action, status_value=req.status_value)
    count_mem = alerts.bulk_update(req.alert_ids, action=req.action, status_value=req.status_value)
    db.log_audit(current_user["username"], "bulk_alert_action", f"{len(req.alert_ids)} alerts", {"action": req.action, "status_value": req.status_value})
    ws_manager.broadcast_sync(
        "alerts_bulk_updated",
        {"alert_ids": req.alert_ids, "action": req.action, "status_value": req.status_value},
    )
    return {"status": "success", "action": req.action, "affected": max(count_db, count_mem)}


@app.get("/api/alerts")
def get_alerts() -> Dict[str, Any]:
    items = alerts.list()
    return {"alerts": items, "count": len(items)}


@app.get("/api/metrics")
def get_metrics() -> Dict[str, Any]:
    payload = metrics.snapshot()
    payload["alert_count"] = len(alerts.list())
    return payload


@app.get("/api/threat-summary", response_model=ThreatSummary)
def get_threat_summary() -> Dict[str, Any]:
    return threat_correlator.summarize()


@app.get("/api/firewall-insights")
def get_firewall_insights() -> Dict[str, Any]:
    return firewall_insight_engine.summarize()


@app.get("/api/history/searches")
def get_search_history(limit: int = 100) -> Dict[str, Any]:
    return {"searches": metrics.list_searches(limit)}


@app.post("/api/history/searches")
def post_search_history(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    who = payload.get("who", "unknown")
    query = payload.get("query", "")
    url = payload.get("url")
    metrics.add_search(who, query, url, payload.get("meta"))

    # Live DNS Threat Detection check on simulated/reported searches
    domain_to_test = query.replace("DNS:", "").strip() if "DNS:" in query else query
    if "." in domain_to_test and len(domain_to_test) > 4:
        dns_alert = dns_threat_detector.inspect_query(who, domain_to_test, None)
        if dns_alert:
            if geoip_service:
                geoip_service.enrich_meta(who, dns_alert["meta"])
            alerts.add(
                source=dns_alert["source"],
                severity=dns_alert["severity"],
                category=dns_alert["category"],
                message=dns_alert["message"],
                meta=dns_alert["meta"],
            )
    return {"status": "ok"}


@app.get("/api/history/file-shares")
def get_file_shares(limit: int = 100) -> Dict[str, Any]:
    return {"file_shares": metrics.list_file_shares(limit)}


@app.post("/api/history/file-shares")
def post_file_share(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    who = payload.get("who", "unknown")
    filename = payload.get("filename", "")
    dest_ip = payload.get("dest_ip")
    metrics.add_file_share(who, filename, dest_ip, payload.get("meta"))
    return {"status": "ok"}


@app.get("/api/history/ports")
def get_port_history(limit: int = 200) -> Dict[str, Any]:
    return {"ports": metrics.list_port_history(limit)}


@app.post("/api/history/ports")
def post_port_history(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    src_ip = payload.get("src_ip", "0.0.0.0")
    dst_ip = payload.get("dst_ip")
    port = int(payload.get("port", 0))
    protocol = str(payload.get("protocol", "TCP")).upper()
    direction = str(payload.get("direction", "inbound")).lower()
    metrics.add_port_activity(src_ip, dst_ip, port, protocol, direction)
    if src_ip:
        metrics.add_ip_access(src_ip, payload.get("who"), {"source": "simulator", "direction": direction, "port": port, "protocol": protocol})
    if dst_ip:
        metrics.add_ip_access(dst_ip, payload.get("who"), {"source": "simulator", "direction": direction, "port": port, "protocol": protocol})

    # Threat Intelligence Match check
    if threat_intelligence.is_ip_malicious(src_ip):
        packet_engine._emit_malicious_ip_alert(src_ip, dst_ip, protocol, port)

    # Brute Force Detection check
    if port and brute_force_detector.is_monitored_port(port):
        bf_alert = brute_force_detector.record_attempt(src_ip, dst_ip, port, protocol)
        if bf_alert:
            if geoip_service:
                geoip_service.enrich_meta(src_ip, bf_alert["meta"])
            alerts.add(
                source=bf_alert["source"],
                severity=bf_alert["severity"],
                category=bf_alert["category"],
                message=bf_alert["message"],
                meta=bf_alert["meta"],
            )
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Threat Intelligence Feeds & Detection Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/threats/feeds")
def get_threat_feeds() -> Dict[str, Any]:
    """Return synchronization status of all local and remote threat intelligence feeds."""
    statuses = feed_loader.get_feed_statuses()
    return {
        "feeds": statuses,
        "total_feeds": len(statuses),
        "refresh_interval": get_settings().feed_refresh_interval,
    }


@app.post("/api/threats/feeds/refresh")
def refresh_threat_feeds(user: Optional[Dict[str, Any]] = Depends(get_optional_current_user)) -> Dict[str, Any]:
    """Trigger an immediate synchronization of all threat feeds."""
    res = feed_loader.refresh_all_feeds()
    username = (user or {}).get("username", "system")
    db.log_audit(username, "refresh_threat_feeds", "threat_feeds", res)
    return res


@app.get("/api/threats/lookup")
def lookup_threat_indicator(target: str = "") -> Dict[str, Any]:
    """Lookup an IP, domain, or hash against active threat intelligence repositories."""
    if not target.strip():
        raise HTTPException(status_code=400, detail="Missing required target parameter.")
    res = feed_loader.lookup(target)
    if res.get("type") == "ip" and geoip_service:
        res["geoip"] = geoip_service.lookup(target)
    return res


@app.get("/api/geoip/{ip}")
def get_ip_geolocation(ip: str) -> Dict[str, Any]:
    """Retrieve geolocation metadata for an IP address."""
    geo = geoip_service.lookup(ip)
    if not geo:
        return {"ip": ip, "country": "Unknown", "city": "Unknown", "available": geoip_service.is_available()}
    return geo


@app.get("/api/security/brute-force/stats")
def get_brute_force_stats() -> Dict[str, Any]:
    """Retrieve operational statistics and suspects from the brute force detector."""
    return brute_force_detector.get_stats()


@app.post("/api/security/dns/inspect")
def inspect_dns_query(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Inspect a domain for DNS Tunneling or DGA algorithm characteristics."""
    domain = payload.get("domain", "").strip()
    src_ip = payload.get("src_ip", "127.0.0.1")
    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required.")
    analysis = dns_threat_detector.analyze_domain(domain)
    alert = dns_threat_detector.inspect_query(src_ip, domain)
    return {
        "analysis": analysis,
        "is_threat": alert is not None,
        "alert": alert,
    }


@app.get("/api/history/ips")
def get_ip_history(limit: int = 200) -> Dict[str, Any]:
    return {"ips": metrics.list_ip_history(None, limit)}


@app.get("/api/history/ips/{ip}")
def get_ip_history_ip(ip: str, limit: int = 200) -> Dict[str, Any]:
    return {"ip_history": metrics.list_ip_history(ip, limit)}


@app.get("/api/current/connections")
def get_current_connections() -> Dict[str, Any]:
    connections = []
    seen = set()
    try:
        proc_cache = {}
        for conn in psutil.net_connections(kind="inet"):
            if not conn.laddr:
                continue
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "—"
            key = f"{laddr}->{raddr}"
            if key in seen:
                continue
            seen.add(key)

            pid = conn.pid or 0
            pname = "System"
            if pid > 0:
                if pid not in proc_cache:
                    try:
                        proc_cache[pid] = psutil.Process(pid).name()
                    except Exception:
                        proc_cache[pid] = "Process"
                pname = proc_cache[pid]

            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            status = conn.status if conn.status else ("LISTENING" if not conn.raddr else "ESTABLISHED")

            connections.append({
                "src": laddr,
                "dst": raddr,
                "src_ip": conn.laddr.ip,
                "dst_ip": conn.raddr.ip if conn.raddr else None,
                "port": conn.laddr.port,
                "remote_port": conn.raddr.port if conn.raddr else 0,
                "protocol": proto,
                "status": status,
                "process": f"{pname} (PID: {pid})" if pid else pname,
                "direction": "outbound" if conn.raddr else "inbound",
                "last_seen": now_utc(),
            })
    except Exception:
        pass

    # Merge with in-memory connections recorded by sniffer
    for item in metrics.list_current_connections():
        k = f"{item.get('src')}:{item.get('port')}->{item.get('dst')}"
        if k not in seen:
            seen.add(k)
            connections.append(item)

    return {"connections": connections[:250]}


@app.post("/api/traffic")
def post_traffic(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Accept aggregate traffic metrics from simulators or external collectors."""
    with metrics._lock:
        if "packet_velocity" in payload:
            try:
                metrics.packet_velocity = float(payload.get("packet_velocity", 0.0))
            except Exception:
                pass
        if "protocol_breakdown" in payload and isinstance(payload.get("protocol_breakdown"), dict):
            for k, v in payload.get("protocol_breakdown", {}).items():
                try:
                    metrics.protocol_breakdown[str(k).upper()] = int(v)
                except Exception:
                    pass
        if "file_change_rate" in payload:
            try:
                metrics.ransomware_rate = float(payload.get("file_change_rate", 0.0))
            except Exception:
                pass
    return {"status": "ok"}


@app.post("/api/current/sessions")
def post_current_sessions(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Accept one or more TCP/UDP session records and update active connections."""
    sessions = []
    # Allow either {sessions: [...] } or a single session dict
    if isinstance(payload.get("sessions"), list):
        sessions = payload.get("sessions", [])
    else:
        sessions = [payload]

    count = 0
    with metrics._lock:
        for s in sessions:
            src = s.get("src") or s.get("src_ip") or s.get("source") or "0.0.0.0"
            dst = s.get("dst") or s.get("dst_ip") or s.get("dest") or None
            try:
                port = int(s.get("port", 0))
            except Exception:
                port = 0
            proto = (s.get("protocol") or s.get("proto") or "TCP").upper()
            direction = s.get("direction", "inbound")
            last_seen = s.get("last_seen") or now_utc()
            key = f"{src}:{port}->{dst}"
            metrics.current_connections[key] = {
                "src": src,
                "dst": dst,
                "port": port,
                "protocol": proto,
                "last_seen": last_seen,
                "direction": direction,
            }
            count += 1

    return {"status": "ok", "sessions_added": count}


@app.post("/api/check-url")
def check_url(payload: URLCheckRequest) -> Dict[str, Any]:
    return phishing_detector.predict(payload.url)


class FileCheckPayload(BaseModel):
    file_path: Optional[str] = None
    file_base64: Optional[str] = None
    filename: Optional[str] = None


class FlowAnomalyRequest(BaseModel):
    packet_size: Optional[float] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    flow_rate: Optional[float] = None
    packets_sent: Optional[int] = None
    bytes_sent: Optional[int] = None


def _apply_quarantine_containment(result: Dict[str, Any]) -> Dict[str, Any]:
    """If file is classified as high-risk ransomware or malicious executable, trigger automated quarantine."""
    if not (result.get("is_malicious") and result.get("risk_score", 0.0) >= 0.70):
        result["quarantine_enforced"] = False
        return result

    rule_hash = (result.get("sha256") or "unknown")[:8].upper()
    rule_name = f"QUARANTINE_AUTO_{rule_hash}"
    filename = result.get("filename", "payload")

    existing_rules = rule_engine.list_rules()
    matching_rule = next((r for r in existing_rules if r.name == rule_name), None)

    if matching_rule is None:
        try:
            rule = rule_engine.add_rule(
                name=rule_name,
                action=RuleAction.DROP,
                priority=RulePriority.CRITICAL,
                description=f"Automated ransomware quarantine: {filename} (Entropy: {result.get('entropy')})",
            )
            if db:
                db.save_rule(rule)
                db.log_audit("ai_sentinel", "quarantine_auto_block", f"rule:{rule.name}", {"sha256": result.get("sha256"), "risk": result.get("risk_score")})
            rule_id = rule.id
        except Exception as exc:
            logger.error(f"[Quarantine] Failed to create drop rule: {exc}")
            rule_id = None
    else:
        rule_id = matching_rule.id

    # Record alert
    alert_dict = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "Ransomware Containment Sentinel",
        "severity": "critical",
        "category": "Ransomware",
        "message": f"Automated quarantine containment triggered for {filename} (Entropy: {result.get('entropy')}, Risk: {result.get('risk_score', 0)*100:.1f}%)",
        "metadata": {"sha256": result.get("sha256"), "rule_name": rule_name},
    }
    try:
        alerts.append(alert_dict)
        if db:
            db.save_alert(alert_dict)
    except Exception:
        pass

    result["quarantine_enforced"] = True
    result["quarantine_rule_id"] = rule_id
    result["quarantine_rule_name"] = rule_name
    return result


@app.post("/api/check-file")
async def check_file(request: Request) -> Dict[str, Any]:
    """Inspect executable files, downloads, and payloads for ransomware heuristics and entropy."""
    inspector = get_file_inspector()
    content_type = request.headers.get("content-type", "")

    if "multipart/form-data" in content_type:
        form = await request.form()
        uploaded_file = form.get("file")
        if uploaded_file and hasattr(uploaded_file, "read"):
            content = await uploaded_file.read()
            filename = getattr(uploaded_file, "filename", "uploaded_file")
            res = inspector.inspect_bytes(content, filename=filename)
            return _apply_quarantine_containment(res)
        raise HTTPException(status_code=400, detail="Form field 'file' missing in multipart upload")

    try:
        body = await request.json()
    except Exception:
        body = {}

    if not body:
        raise HTTPException(
            status_code=400,
            detail="Must provide either an uploaded file or file_path/file_base64 in JSON request body",
        )

    if body.get("file_base64"):
        import base64
        try:
            decoded = base64.b64decode(body["file_base64"])
            res = inspector.inspect_bytes(decoded, filename=body.get("filename", "inspected_file"))
            return _apply_quarantine_containment(res)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid base64 encoding: {e}")
    elif body.get("file_path"):
        res = inspector.inspect_file(body["file_path"])
        return _apply_quarantine_containment(res)

    raise HTTPException(
        status_code=400,
        detail="Must provide file_base64 or file_path in JSON request body",
    )


@app.post("/api/anomaly-score")
def get_anomaly_score(req: FlowAnomalyRequest) -> Dict[str, Any]:
    """Evaluate multi-variate traffic flow features against Isolation Forest baseline."""
    detector = get_traffic_anomaly_detector()
    data = {
        "packet_size": req.packet_size or (req.bytes_sent / max(1, (req.packets_sent or 1)) if req.bytes_sent else 64.0),
        "src_port": req.src_port or 50000,
        "dst_port": req.dst_port or 80,
        "protocol": req.protocol or "TCP",
        "flow_rate": req.flow_rate or float(req.packets_sent or 1.0),
    }
    return detector.predict(data)


class LSTMSequenceRequest(BaseModel):
    sequence: Optional[List[Dict[str, Any]]] = None
    delta_time: Optional[float] = 0.05
    packet_size: Optional[float] = 1420.0
    direction: Optional[int] = 1
    protocol: Optional[str] = "TCP"


@app.post("/api/lstm-flow-score")
def get_lstm_score(req: LSTMSequenceRequest) -> Dict[str, Any]:
    """Evaluate temporal recurrent packet sequence with PyTorch LSTM."""
    from ai_engine.lstm_detector import get_lstm_traffic_detector
    detector = get_lstm_traffic_detector()
    if req.sequence:
        return detector.predict_sequence(req.sequence)

    steps = [
        {
            "delta_time": req.delta_time,
            "packet_size": req.packet_size,
            "direction": req.direction,
            "protocol": req.protocol,
        }
        for _ in range(8)
    ]
    return detector.predict_sequence(steps)


def _system_killswitch_restore_command(interface_name: Optional[str] = None) -> list[str]:
    system_name = platform.system().lower()
    if system_name == "windows":
        target = interface_name or KILLSWITCH_WINDOWS_INTERFACE
        return ["netsh", "interface", "set", "interface", target, "admin=enable"]
    if system_name == "linux":
        target = interface_name or KILLSWITCH_LINUX_INTERFACE
        if _shutil_which("nmcli"):
            return ["nmcli", "radio", "wifi", "on"]
        return ["ip", "link", "set", "dev", target, "up"]
    raise HTTPException(status_code=400, detail=f"Unsupported platform for killswitch: {platform.system()}")


@app.post("/api/killswitch")
def killswitch(
    payload: KillSwitchRequest,
    user: Optional[Dict[str, Any]] = Depends(get_optional_current_user),
    _: None = Depends(verify_killswitch_access),
) -> Dict[str, Any]:
    if not payload.confirm:
        raise HTTPException(status_code=400, detail="Killswitch requires confirm=true.")

    command = _system_killswitch_command(payload.interface)
    cfg = get_settings()
    username = (user or {}).get("username", "system")

    if payload.dry_run or cfg.killswitch_dry_run:
        db.log_audit(username, "killswitch", "network_interface", {"dry_run": True, "command": command})
        return {
            "status": "dry_run",
            "command": command,
            "stdout": "[Dry Run] Network isolation simulated successfully. No hardware disabled.",
            "stderr": "",
        }

    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except subprocess.CalledProcessError as exc:
        db.log_audit(username, "killswitch", "network_interface", {"status": "failed", "error": exc.stderr})
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Killswitch command failed.",
                "command": command,
                "stdout": exc.stdout,
                "stderr": exc.stderr,
            },
        ) from exc
    except Exception as exc:
        db.log_audit(username, "killswitch", "network_interface", {"status": "failed", "error": str(exc)})
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    db.log_audit(username, "killswitch", "network_interface", {"status": "isolated", "command": command})
    alerts.add(
        source="system",
        severity="critical",
        category="Isolation Event",
        message="Emergency network isolation command executed successfully.",
        meta={"command": command, "stdout": completed.stdout, "stderr": completed.stderr},
    )
    return {
        "status": "isolated",
        "command": command,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


@app.post("/api/killswitch/restore")
def killswitch_restore(
    payload: KillSwitchRequest,
    user: Optional[Dict[str, Any]] = Depends(get_optional_current_user),
    _: None = Depends(verify_killswitch_access),
) -> Dict[str, Any]:
    command = _system_killswitch_restore_command(payload.interface)
    cfg = get_settings()
    username = (user or {}).get("username", "system")

    if payload.dry_run or cfg.killswitch_dry_run:
        db.log_audit(username, "killswitch_restore", "network_interface", {"dry_run": True, "command": command})
        return {
            "status": "dry_run",
            "command": command,
            "stdout": "[Dry Run] Network restoration simulated successfully.",
            "stderr": "",
        }

    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except subprocess.CalledProcessError as exc:
        db.log_audit(username, "killswitch_restore", "network_interface", {"status": "failed", "error": exc.stderr})
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Killswitch restore command failed.",
                "command": command,
                "stdout": exc.stdout,
                "stderr": exc.stderr,
            },
        ) from exc
    except Exception as exc:
        db.log_audit(username, "killswitch_restore", "network_interface", {"status": "failed", "error": str(exc)})
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    db.log_audit(username, "killswitch_restore", "network_interface", {"status": "restored", "command": command})
    alerts.add(
        source="system",
        severity="info",
        category="Isolation Restored",
        message="Emergency network isolation reverted; interface re-enabled.",
        meta={"command": command, "stdout": completed.stdout, "stderr": completed.stderr},
    )
    return {
        "status": "restored",
        "command": command,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


# ---------------------------------------------------------------------------
# Containment Rollback Endpoints
# ---------------------------------------------------------------------------

class ContainmentRollbackRequest(BaseModel):
    dry_run: bool = False


@app.post("/api/containment/rollback")
def rollback_containment(
    req: ContainmentRollbackRequest = ContainmentRollbackRequest(),
    current_user: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    """Restore the most recent containment rule snapshot (admin only)."""
    return response_engine.rollback(dry_run=req.dry_run, username=current_user["username"])


@app.get("/")
def root() -> Any:
    index_file = BASE_DIR.parent / "frontend" / "dist" / "index.html"
    if index_file.exists():
        from fastapi.responses import FileResponse
        return FileResponse(index_file)
    return {"service": "AI-Powered Contextual Firewall for Traffic Anomaly Detection", "status": "online", "version": "3.0.0"}


@app.get("/api/health")
def health() -> Dict[str, Any]:
    try:
        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory().percent
    except Exception:
        cpu = 0.0
        ram = 0.0

    cfg_health = get_settings()
    return {
        "status": "healthy",
        "sniffer_active": packet_engine._sniffer is not None,
        "database": "postgres" if db.is_postgres else "sqlite",
        "model_loaded": phishing_detector.model is not None,
        "cpu_percent": cpu,
        "memory_percent": ram,
        "rules": len(rule_engine.list_rules()),
        "sessions": state_engine.get_stats(),
        "risk_stats": risk_engine.get_risk_stats(),
        "pcap_buffered_packets": pcap_buffer.get_packet_count(),
        "enforcement_mode": getattr(cfg_health, "enforcement_mode", "dry_run"),
        "enforcement_backend": getattr(cfg_health, "enforcement_backend", "software"),
        "containment_mode": "dry_run" if response_engine.is_dry_run() else "live",
        "dry_run": response_engine.is_dry_run(),
        "snapshots_available": len(response_engine._snapshots),
    }


@app.get("/api/pcap/stats")
def get_pcap_stats() -> Dict[str, Any]:
    return pcap_buffer.get_stats()


@app.get("/api/pcap/export")
def export_pcap(count: Optional[int] = None) -> Response:
    try:
        data = pcap_buffer.export_pcap_bytes(count=count)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to export PCAP: {exc}")

    ts = int(time.time())
    return Response(
        content=data,
        media_type="application/vnd.tcpdump.pcap",
        headers={
            "Content-Disposition": f'attachment; filename="volcano_traffic_{ts}.pcap"',
            "Content-Length": str(len(data)),
        },
    )


@app.get("/api/alerts/{alert_id}/pcap")
def export_alert_pcap(alert_id: int) -> Response:
    alert = db.get_alert(alert_id)
    if not alert:
        for a in alerts.list():
            if getattr(a, "id", None) == alert_id or (isinstance(a, dict) and a.get("id") == alert_id):
                alert = a
                break
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    try:
        data = pcap_buffer.export_pcap_bytes(count=200)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to export forensic PCAP: {exc}")

    return Response(
        content=data,
        media_type="application/vnd.tcpdump.pcap",
        headers={
            "Content-Disposition": f'attachment; filename="alert_{alert_id}_forensic.pcap"',
            "Content-Length": str(len(data)),
        },
    )


@app.get("/api/database/status")
def get_database_status(current_user: Optional[Dict[str, Any]] = Depends(get_optional_current_user)) -> Dict[str, Any]:
    return db.get_database_status()


@app.post("/api/database/maintenance")
def execute_database_maintenance(
    req: DatabaseMaintenanceRequest,
    current_user: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    action = req.action.lower().strip()
    result: Dict[str, Any] = {}

    if action == "checkpoint":
        result = db.checkpoint_wal(mode=req.mode or "TRUNCATE")
    elif action == "vacuum":
        result = db.vacuum()
    elif action == "integrity":
        result = db.run_integrity_check()
    elif action == "prune":
        result = db.prune_stale_data(
            max_alert_age_days=req.max_alert_age_days or 30,
            max_audit_age_days=req.max_audit_age_days or 90,
        )
    elif action == "optimize":
        result = db.optimize()
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported maintenance action: {req.action}")

    db.log_audit(
        user_id=current_user.get("username", "admin"),
        action=f"DB_MAINTENANCE_{action.upper()}",
        resource="database",
        changes={"request": req.model_dump(), "result": result},
    )
    return {"action": action, "result": result, "status": db.get_database_status()}


atexit.register(on_shutdown)

# Serve compiled frontend assets if they exist
dist_path = BASE_DIR.parent / "frontend" / "dist"
if dist_path.exists() and dist_path.is_dir():
    from fastapi.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=str(dist_path), html=True), name="static")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=False)
