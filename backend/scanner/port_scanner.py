"""High-Performance Defensive Port Scanner & Service Discovery Engine.

Provides multi-threaded TCP connect scanning, banner grabbing, and service identification
for defensive vulnerability assessments and firewall configuration auditing.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import socket
import time
from typing import Any, Dict, List, Optional, Set, Tuple


# Top 20 Most Common Network Ports
TOP_20_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080,
]

# Top 100 Common Service Ports
TOP_100_PORTS: List[int] = sorted(list(set(TOP_20_PORTS + [
    20, 69, 88, 119, 123, 137, 138, 161, 162, 179, 389, 465, 500, 514, 515,
    520, 587, 631, 636, 873, 902, 989, 990, 1080, 1194, 1521, 1723, 1812,
    1813, 2049, 2082, 2083, 2086, 2087, 2181, 2222, 3000, 3128, 3306, 4000,
    4200, 4848, 5000, 5001, 5060, 5061, 5173, 5353, 5672, 5900, 5901, 5985,
    5986, 6000, 6379, 6667, 7000, 7001, 8000, 8008, 8081, 8443, 8888, 9000,
    9042, 9090, 9092, 9100, 9200, 9300, 9418, 9999, 10000, 11211, 27017, 27018,
    28017, 50000, 50070,
])))

# Well-known Service Name Mappings
PORT_SERVICES: Dict[int, str] = {
    21: "FTP (File Transfer)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Insecure Remote Shell)",
    25: "SMTP (Mail Transfer)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Web Server)",
    110: "POP3 (Mail Retrieval)",
    111: "RPCBind",
    135: "MSRPC (Microsoft RPC)",
    139: "NetBIOS Session",
    143: "IMAP (Mail Access)",
    443: "HTTPS (Secure Web Server)",
    445: "SMB (Server Message Block)",
    993: "IMAPS (Secure IMAP)",
    995: "POP3S (Secure POP3)",
    1433: "MSSQL (Microsoft SQL Server)",
    1521: "Oracle DB",
    2049: "NFS (Network File System)",
    2181: "ZooKeeper",
    3000: "Node.js / React Dev Server",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop)",
    5000: "Flask / FastAPI Dev Server",
    5173: "Vite Web Console",
    5432: "PostgreSQL Database",
    5900: "VNC Remote Desktop",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    6379: "Redis In-Memory Data Store",
    8000: "HTTP / Volcano Backend Core",
    8080: "HTTP-Proxy / Alternate Web Server",
    8443: "HTTPS-Alt / Tomcat SSL",
    9000: "SonarQube / PHP-FPM",
    9090: "Prometheus Server",
    9200: "Elasticsearch REST API",
    11211: "Memcached Memory Cache",
    27017: "MongoDB Database",
}


class PortScanner:
    """Threadpool-based TCP connect scanner with banner grabbing."""

    def __init__(self, max_threads: int = 40, default_timeout: float = 0.8) -> None:
        self.max_threads = max(1, min(max_threads, 100))
        self.default_timeout = default_timeout

    @staticmethod
    def resolve_target(target: str) -> str:
        """Validates and resolves a target IP or domain name."""
        target = target.strip()
        if not target:
            raise ValueError("Target hostname or IP address cannot be empty.")
        
        # Strip protocol if user passed a URL like http://localhost:8000
        if "://" in target:
            target = target.split("://")[1].split("/")[0].split(":")[0]
        else:
            target = target.split("/")[0].split(":")[0]

        try:
            # Check if it's already a valid IPv4/IPv6
            ipaddress.ip_address(target)
            return target
        except ValueError:
            pass

        # Resolve domain
        try:
            resolved_ip = socket.gethostbyname(target)
            return resolved_ip
        except socket.gaierror as exc:
            raise ValueError(f"Could not resolve host '{target}': {exc}") from exc

    @staticmethod
    def parse_port_range(port_spec: str) -> List[int]:
        """Parses a port specification string (e.g. '80,443,8000-8010') into a sorted port list."""
        ports: Set[int] = set()
        parts = port_spec.replace(" ", "").split(",")
        for part in parts:
            if not part:
                continue
            if "-" in part:
                start_s, end_s = part.split("-", 1)
                start, end = int(start_s), int(end_s)
                if start > end:
                    start, end = end, start
                for p in range(max(1, start), min(65535, end) + 1):
                    ports.add(p)
            else:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)

        if len(ports) > 1000:
            raise ValueError(f"Requested {len(ports)} ports exceeds maximum allowable single scan limit of 1000 ports.")
        return sorted(list(ports))

    def _grab_banner(self, ip: str, port: int, timeout: float) -> str:
        """Attempts to grab an application banner or response from an open port."""
        banner = ""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))

                # For HTTP/HTTPS ports, send a quick HEAD request
                if port in (80, 8080, 8000, 3000, 5000, 5173):
                    req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Volcano-Firewall-Auditor/3.0\r\n\r\n"
                    s.sendall(req.encode("ascii", errors="ignore"))
                elif port == 443 or port == 8443:
                    # Generic TLS banner indicator
                    return "TLS/SSL Encrypted Service"
                elif port == 21:
                    # FTP servers usually send a greeting upon connect
                    pass
                elif port == 22:
                    # SSH servers send SSH-2.0-OpenSSH... immediately
                    pass
                elif port == 23:
                    # Telnet greeting
                    pass
                elif port == 6379:
                    s.sendall(b"PING\r\n")
                elif port == 11211:
                    s.sendall(b"version\r\n")
                else:
                    # Generic probe
                    s.sendall(b"\r\n\r\n")

                s.settimeout(timeout)
                data = s.recv(1024)
                if data:
                    raw_text = data.decode("latin-1", errors="replace").strip()
                    # Clean control chars
                    cleaned = re.sub(r"[\r\n]+", " | ", raw_text)
                    banner = cleaned[:160]
        except Exception:
            pass
        return banner

    def _scan_port(self, ip: str, port: int, timeout: float, grab_banner: bool = True) -> Optional[Dict[str, Any]]:
        """Scans a single TCP port and measures latency."""
        start_time = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((ip, port))
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            if result == 0:
                service = PORT_SERVICES.get(port, "Unknown Service")
                banner = ""
                if grab_banner:
                    banner = self._grab_banner(ip, port, timeout=min(timeout, 1.0))
                return {
                    "port": port,
                    "service": service,
                    "state": "open",
                    "latency_ms": latency_ms,
                    "banner": banner,
                }
            return None
        except Exception:
            return None
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def scan(
        self,
        target: str,
        profile: str = "top20",
        custom_ports: Optional[str] = None,
        timeout: Optional[float] = None,
        grab_banner: bool = True,
    ) -> Dict[str, Any]:
        """Executes a port scan against the target using the specified profile."""
        start_time = time.perf_counter()
        resolved_ip = self.resolve_target(target)
        effective_timeout = timeout or self.default_timeout

        # Determine target port list
        if profile == "top20":
            ports = TOP_20_PORTS
        elif profile == "top100":
            ports = TOP_100_PORTS
        elif profile == "custom":
            if not custom_ports:
                raise ValueError("Custom profile requires 'custom_ports' specification (e.g., '80,443,8000-8080').")
            ports = self.parse_port_range(custom_ports)
        else:
            ports = TOP_20_PORTS

        open_ports: List[Dict[str, Any]] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {
                executor.submit(self._scan_port, resolved_ip, p, effective_timeout, grab_banner): p
                for p in ports
            }
            for future in concurrent.futures.as_completed(future_to_port):
                res = future.result()
                if res:
                    open_ports.append(res)

        # Sort results by port number
        open_ports.sort(key=lambda x: x["port"])
        duration = round(time.perf_counter() - start_time, 2)

        return {
            "target": target,
            "resolved_ip": resolved_ip,
            "profile": profile,
            "ports_scanned_count": len(ports),
            "open_ports_count": len(open_ports),
            "scan_duration_seconds": duration,
            "open_ports": open_ports,
            "timestamp": time.time(),
        }


# Singleton instance
_port_scanner_instance: Optional[PortScanner] = None

def get_port_scanner() -> PortScanner:
    """Returns the singleton PortScanner instance."""
    global _port_scanner_instance
    if _port_scanner_instance is None:
        _port_scanner_instance = PortScanner()
    return _port_scanner_instance
