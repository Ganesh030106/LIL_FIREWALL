"""Layer-7 Deep Packet Inspection & Application-Level Threat Analyzer.

Performs application payload dissection (HTTP, TLS, DNS, SSH) and detects
Layer-7 web application attacks including SQLi, XSS, Path Traversal, and Command Injection.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple


# Regex patterns for Layer 7 web attacks
L7_ATTACK_PATTERNS: List[Tuple[str, str, str, re.Pattern]] = [
    (
        "SQL Injection",
        "high",
        "CWE-89",
        re.compile(
            r"(?:'|\")\s*(?:or|and)\s*[\d'\"]\s*=\s*[\d'\"]|"
            r"union\s+(?:all\s+)?select\b|"
            r"(?:waitfor\s+delay|sleep\s*\(\d+\))|"
            r"information_schema\.(?:tables|columns)|"
            r"(?:drop|truncate)\s+table\b",
            re.IGNORECASE,
        ),
    ),
    (
        "Directory Path Traversal",
        "high",
        "CWE-22",
        re.compile(
            r"(?:\.\./|\.\.\\){2,}|"
            r"(?:/etc/passwd|/etc/shadow|/proc/self/environ)|"
            r"(?:windows[/\\]system32|win\.ini|boot\.ini)",
            re.IGNORECASE,
        ),
    ),
    (
        "Cross-Site Scripting (XSS)",
        "medium",
        "CWE-79",
        re.compile(
            r"<\s*script\b[^>]*>|"
            r"javascript\s*:|"
            r"on(?:error|load|click|mouseover)\s*=\s*[\"'][^\"']+[\"']|"
            r"document\.cookie\b|"
            r"<\s*img\b[^>]*onerror\s*=",
            re.IGNORECASE,
        ),
    ),
    (
        "Remote Command Injection",
        "critical",
        "CWE-78",
        re.compile(
            r";\s*(?:cat|ls|id|whoami|nc|bash|sh|curl|wget)\b|"
            r"\|\s*(?:bash|sh|python|perl)\b|"
            r"powershell(?:\.exe)?\s+(?:-[eE]nc|[^\s]+)|"
            r"(?:cmd\.exe\s+/c|/bin/sh\s+-c)",
            re.IGNORECASE,
        ),
    ),
]


class L7ApplicationInspector:
    """Performs deep inspection of application payloads extracted from network packets."""

    def __init__(self) -> None:
        pass

    def inspect_payload(self, raw_bytes: bytes, src_ip: str, dst_ip: str, dst_port: int) -> Optional[Dict[str, Any]]:
        """Analyzes application layer bytes for protocols and application-level attacks."""
        if not raw_bytes or len(raw_bytes) < 4:
            return None

        # Try decoding as Latin-1 / ASCII text
        try:
            text = raw_bytes[:4096].decode("latin-1", errors="ignore")
        except Exception:
            return None

        # 1. Check for HTTP Request
        http_method_match = re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s+([^\s]+)\s+HTTP/\d\.\d", text, re.IGNORECASE)
        if http_method_match:
            method = http_method_match.group(1).upper()
            uri = http_method_match.group(2)

            # Analyze full request URI and body for attacks, unquoting URL encoding
            import urllib.parse
            unquoted_text = urllib.parse.unquote_plus(text)

            for attack_name, severity, cwe_id, pattern in L7_ATTACK_PATTERNS:
                matched = pattern.search(text) or pattern.search(unquoted_text)
                if matched:
                    matched_snippet = matched.group(0)[:80]
                    return {
                        "source": "l7_inspector",
                        "severity": severity,
                        "category": f"L7 Attack: {attack_name}",
                        "message": f"Detected {attack_name} in HTTP {method} request to {uri[:60]}",
                        "meta": {
                            "protocol": "HTTP",
                            "method": method,
                            "uri": uri[:120],
                            "attack_type": attack_name,
                            "cwe_id": cwe_id,
                            "matched_pattern": matched_snippet,
                            "source_ip": src_ip,
                            "dest_ip": dst_ip,
                            "dest_port": dst_port,
                        },
                    }

        # 2. Check for non-HTTP command injection in generic telnet/raw socket text
        for attack_name, severity, cwe_id, pattern in L7_ATTACK_PATTERNS:
            if attack_name in ("Remote Command Injection", "Directory Path Traversal"):
                matched = pattern.search(text)
                if matched:
                    return {
                        "source": "l7_inspector",
                        "severity": severity,
                        "category": f"L7 Attack: {attack_name}",
                        "message": f"Detected {attack_name} in raw application stream on port {dst_port}",
                        "meta": {
                            "protocol": "Raw/Socket",
                            "attack_type": attack_name,
                            "cwe_id": cwe_id,
                            "matched_pattern": matched.group(0)[:80],
                            "source_ip": src_ip,
                            "dest_ip": dst_ip,
                            "dest_port": dst_port,
                        },
                    }

        return None


# Singleton instance
_l7_inspector_instance: Optional[L7ApplicationInspector] = None

def get_l7_inspector() -> L7ApplicationInspector:
    """Returns the singleton L7ApplicationInspector instance."""
    global _l7_inspector_instance
    if _l7_inspector_instance is None:
        _l7_inspector_instance = L7ApplicationInspector()
    return _l7_inspector_instance
