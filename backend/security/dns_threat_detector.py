"""DNS Threat Detection Module for Volcano AI Firewall.
Analyzes DNS queries to identify:
1. DNS Tunneling (data exfiltration/C2 via high-entropy, long subdomains)
2. DGA Domains (Algorithmically Generated Domains characterized by pseudo-random characters)
3. High query rate spikes from individual hosts
"""

from __future__ import annotations

import math
import re
import threading
import time
from collections import Counter, defaultdict, deque
from typing import Any, Dict, Optional, Tuple

from config import get_settings


VOWELS = set("aeiou")
HEX_BASE64_PATTERN = re.compile(r"^[a-zA-Z0-9+/=_\-]+$")


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy for a given string."""
    if not text:
        return 0.0
    length = len(text)
    freq = Counter(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


class DNSThreatDetector:
    """Detects DNS Tunneling and DGA query patterns in real-time DNS traffic."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # Track query rates per source IP: src_ip -> deque of timestamps
        self._ip_query_windows: Dict[str, deque[float]] = defaultdict(deque)
        # Alert cooldown per (src_ip, domain, threat_type) -> float
        self._alert_cooldowns: Dict[Tuple[str, str, str], float] = {}

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Perform static lexical and entropy analysis on a domain string."""
        clean_domain = domain.lower().rstrip(".")
        parts = clean_domain.split(".")

        # Heuristic extraction of subdomain and base domain
        if len(parts) >= 3:
            subdomain = ".".join(parts[:-2])
            base_name = parts[-2]
            tld = parts[-1]
        elif len(parts) == 2:
            subdomain = ""
            base_name = parts[0]
            tld = parts[1]
        else:
            subdomain = ""
            base_name = clean_domain
            tld = ""

        subdomain_len = len(subdomain)
        subdomain_entropy = calculate_entropy(subdomain)
        base_entropy = calculate_entropy(base_name)

        # Consonant/vowel ratio on base name
        vowel_count = sum(1 for c in base_name if c in VOWELS)
        consonant_count = sum(1 for c in base_name if c.isalpha() and c not in VOWELS)
        digit_count = sum(1 for c in base_name if c.isdigit())
        total_chars = max(1, len(base_name))

        vowel_ratio = vowel_count / total_chars
        consonant_ratio = consonant_count / total_chars
        digit_ratio = digit_count / total_chars

        return {
            "domain": clean_domain,
            "subdomain": subdomain,
            "base_name": base_name,
            "tld": tld,
            "subdomain_length": subdomain_len,
            "subdomain_entropy": subdomain_entropy,
            "base_entropy": base_entropy,
            "vowel_ratio": round(vowel_ratio, 3),
            "consonant_ratio": round(consonant_ratio, 3),
            "digit_ratio": round(digit_ratio, 3),
        }

    def inspect_query(
        self,
        src_ip: str,
        domain: str,
        dst_ip: Optional[str] = None,
        query_type: str = "A",
    ) -> Optional[Dict[str, Any]]:
        """Inspect a DNS query from src_ip. Returns an alert dict if a threat is detected."""
        if not domain or len(domain) < 4:
            return None

        # Ignore local lookup suffixes
        clean_domain = domain.lower().rstrip(".")
        if clean_domain.endswith(".in-addr.arpa") or clean_domain.endswith(".local"):
            return None

        cfg = get_settings()
        metrics = self.analyze_domain(clean_domain)
        now = time.monotonic()

        with self._lock:
            # 1. Update source query rate tracking
            q = self._ip_query_windows[src_ip]
            q.append(now)
            cutoff = now - 1.0  # 1-second rate window
            while q and q[0] < cutoff:
                q.popleft()
            rate_1s = len(q)

            # 2. Check for DNS Tunneling (long encoded payload in subdomain)
            is_tunneling = (
                metrics["subdomain_length"] >= cfg.dns_tunneling_subdomain_length
                and metrics["subdomain_entropy"] >= cfg.dns_tunneling_entropy
            ) or (
                metrics["subdomain_length"] > 60 and metrics["subdomain_entropy"] >= 3.5
            )

            if is_tunneling:
                cooldown_key = (src_ip, metrics["base_name"], "tunneling")
                if now - self._alert_cooldowns.get(cooldown_key, 0.0) >= 30.0:
                    self._alert_cooldowns[cooldown_key] = now
                    return {
                        "source": "network",
                        "severity": "critical",
                        "category": "DNS Threat",
                        "rule_name": "DNS Tunneling Detected",
                        "message": (
                            f"Suspected DNS tunneling payload to domain '{clean_domain}' from {src_ip} "
                            f"(subdomain length={metrics['subdomain_length']}, entropy={metrics['subdomain_entropy']:.2f})."
                        ),
                        "meta": {
                            "source_ip": src_ip,
                            "destination_ip": dst_ip,
                            "threat_type": "DNS_TUNNELING",
                            "domain": clean_domain,
                            "subdomain": metrics["subdomain"],
                            "subdomain_length": metrics["subdomain_length"],
                            "entropy": metrics["subdomain_entropy"],
                            "query_type": query_type,
                        },
                    }

            # 3. Check for DGA (Domain Generation Algorithm)
            # Characteristic: High base entropy, long random alphanumeric base, low vowel ratio
            is_dga = False
            base_len = len(metrics["base_name"])
            if (
                base_len >= 12
                and metrics["base_entropy"] >= cfg.dga_entropy_threshold
                and (metrics["vowel_ratio"] < 0.18 or metrics["digit_ratio"] > 0.35)
                and "." in clean_domain
            ):
                is_dga = True

            if is_dga:
                cooldown_key = (src_ip, clean_domain, "dga")
                if now - self._alert_cooldowns.get(cooldown_key, 0.0) >= 30.0:
                    self._alert_cooldowns[cooldown_key] = now
                    return {
                        "source": "network",
                        "severity": "high",
                        "category": "DNS Threat",
                        "rule_name": "DGA Domain Detected",
                        "message": (
                            f"Algorithmic DGA domain query '{clean_domain}' detected from {src_ip} "
                            f"(entropy={metrics['base_entropy']:.2f}, vowel_ratio={metrics['vowel_ratio']:.2f})."
                        ),
                        "meta": {
                            "source_ip": src_ip,
                            "destination_ip": dst_ip,
                            "threat_type": "DGA",
                            "domain": clean_domain,
                            "base_name": metrics["base_name"],
                            "entropy": metrics["base_entropy"],
                            "vowel_ratio": metrics["vowel_ratio"],
                            "query_type": query_type,
                        },
                    }

            # 4. Check for DNS Query Flood / Exfiltration rate
            if rate_1s > cfg.dns_query_rate_threshold:
                cooldown_key = (src_ip, "rate", "flood")
                if now - self._alert_cooldowns.get(cooldown_key, 0.0) >= 30.0:
                    self._alert_cooldowns[cooldown_key] = now
                    return {
                        "source": "network",
                        "severity": "high",
                        "category": "DNS Threat",
                        "rule_name": "DNS Query Rate Anomaly",
                        "message": (
                            f"Host {src_ip} generated abnormal DNS query burst of {rate_1s} queries/sec."
                        ),
                        "meta": {
                            "source_ip": src_ip,
                            "destination_ip": dst_ip,
                            "threat_type": "DNS_RATE_FLOOD",
                            "queries_per_second": rate_1s,
                            "last_domain": clean_domain,
                        },
                    }

        return None
