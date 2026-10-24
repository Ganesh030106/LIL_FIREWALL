"""Live SSL/TLS Certificate & Domain Age Heuristic Validator.

Performs real-time TLS handshake validation, certificate expiry checks,
self-signed detection, and domain age heuristics to enhance phishing prevention
as specified in the project report (Section 5.1).
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("firewall.security.ssl_validator")


def inspect_url_ssl(url: str, timeout: float = 2.0) -> Dict[str, Any]:
    """Inspect SSL/TLS certificate validity and domain heuristics for a target URL."""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    scheme = parsed.scheme.lower()
    port = parsed.port or (443 if scheme == "https" else 80)

    signals: List[str] = []
    is_valid = False
    issuer_str: Optional[str] = None
    subject_str: Optional[str] = None
    expires_at_str: Optional[str] = None
    days_left: Optional[int] = None
    is_self_signed = False
    tls_version: Optional[str] = None
    cipher_name: Optional[str] = None

    # Check if raw IP is used instead of domain
    is_ip_host = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname))
    if is_ip_host:
        signals.append("Destination uses raw IP address instead of registered domain")

    if scheme == "http":
        signals.append("Insecure plaintext HTTP (No TLS encryption)")
        return {
            "has_ssl": False,
            "is_valid": False,
            "issuer": None,
            "subject": None,
            "expires_at": None,
            "days_until_expiration": None,
            "is_self_signed": False,
            "tls_version": None,
            "cipher": None,
            "domain_age_heuristic": _estimate_domain_age_risk(hostname),
            "signals": signals,
        }

    # Scheme is HTTPS: Attempt TLS handshake
    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()
                cipher_tuple = ssock.cipher()
                cipher_name = cipher_tuple[0] if cipher_tuple else None
                is_valid = True

                # Extract Issuer
                issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
                issuer_str = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown CA"

                # Extract Subject
                subject_dict = dict(x[0] for x in cert.get("subject", ()))
                subject_str = subject_dict.get("commonName") or hostname

                # Check Self-Signed
                if issuer_dict.get("commonName") == subject_dict.get("commonName") and issuer_dict.get("organizationName") == subject_dict.get("organizationName"):
                    is_self_signed = True
                    signals.append("Self-signed certificate detected")

                # Check Expiration date
                not_after_str = cert.get("notAfter")
                if not_after_str:
                    # Format: 'May 12 23:59:59 2026 GMT'
                    expires_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    expires_at_str = expires_dt.isoformat()
                    now = datetime.now(timezone.utc)
                    delta = expires_dt - now
                    days_left = delta.days

                    if days_left < 0:
                        is_valid = False
                        signals.append(f"SSL Certificate expired {abs(days_left)} days ago")
                    elif days_left < 14:
                        signals.append(f"SSL Certificate expiring soon ({days_left} days remaining)")

    except ssl.SSLCertVerificationError as e:
        signals.append(f"Untrusted or invalid SSL certificate ({e.verify_message or 'verification error'})")
    except ssl.SSLError as e:
        signals.append(f"SSL handshake error: {e.reason or str(e)}")
    except (socket.timeout, TimeoutError):
        signals.append("SSL handshake connection timed out")
    except Exception as e:
        signals.append(f"TLS connection failed ({type(e).__name__})")

    domain_age_risk = _estimate_domain_age_risk(hostname)
    if "High Risk" in domain_age_risk:
        signals.append(f"Domain age analysis: {domain_age_risk}")

    return {
        "has_ssl": True,
        "is_valid": is_valid,
        "issuer": issuer_str,
        "subject": subject_str,
        "expires_at": expires_at_str,
        "days_until_expiration": days_left,
        "is_self_signed": is_self_signed,
        "tls_version": tls_version,
        "cipher": cipher_name,
        "domain_age_heuristic": domain_age_risk,
        "signals": signals,
    }


def _estimate_domain_age_risk(hostname: str) -> str:
    """Analyze domain patterns, suspicious TLDs, and lexical indicators to estimate domain age risk."""
    if not hostname:
        return "Unknown"

    parts = hostname.lower().split(".")
    if len(parts) >= 2:
        tld = parts[-1]
        # Disposable / high-churn free domains often used in fresh phishing attacks
        high_risk_tlds = {"xyz", "top", "pw", "cc", "club", "buzz", "work", "gq", "cf", "tk", "ml", "ga"}
        if tld in high_risk_tlds:
            return "High Risk (Frequent short-lived phishing TLD)"

    # Check for excessive hyphens or numbers typical of freshly generated phishing domains
    num_digits = sum(c.isdigit() for c in hostname)
    num_hyphens = hostname.count("-")
    if num_digits > 4 or num_hyphens > 2:
        return "High Risk (Algorithmic / DGA-like pattern indicating newly spun domain)"

    return "Normal Enterprise Age Profile"
