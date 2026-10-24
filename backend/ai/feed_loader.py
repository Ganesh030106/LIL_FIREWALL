"""Threat Intelligence Feed Loader for Volcano AI Firewall.
Manages automated ingestion and parsing of local and remote IoC feeds
(e.g., abuse.ch Feodo Tracker, URLhaus, and local blocklists)
with graceful offline degradation and zero-crash error handling.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from config import get_settings
from ai.threat_correlation import ThreatIntelligence

logger = logging.getLogger("volcano.feeds")

IPV4_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
HEX_HASH_PATTERN = re.compile(r"^[a-fA-F0-9]{32,64}$")


class FeedLoader:
    """Loads and syncs threat intelligence indicators from local and external feeds."""

    def __init__(self, threat_intel: ThreatIntelligence) -> None:
        self.threat_intel = threat_intel
        self._lock = threading.RLock()
        self._feed_statuses: Dict[str, Dict[str, Any]] = {}
        self._last_refresh = 0.0

    def get_feed_statuses(self) -> List[Dict[str, Any]]:
        """Return status information for all configured feeds."""
        with self._lock:
            return list(self._feed_statuses.values())

    def load_local_blocklist(self, filepath: Optional[str | Path] = None) -> int:
        """Parse local blocklist text file and register IoCs."""
        cfg = get_settings()
        target_path = Path(filepath or cfg.local_blocklist_path)

        # Fallback to local default if relative
        if not target_path.is_absolute():
            base_dir = Path(__file__).resolve().parent.parent
            target_path = base_dir / str(filepath or cfg.local_blocklist_path).replace("backend/", "")

        status_entry: Dict[str, Any] = {
            "name": "Local Blocklist",
            "source_type": "file",
            "location": str(target_path),
            "status": "loading",
            "item_count": 0,
            "last_updated": time.time(),
            "error": None,
        }

        if not target_path.exists():
            status_entry["status"] = "not_found"
            status_entry["error"] = f"File {target_path} not found"
            with self._lock:
                self._feed_statuses["Local Blocklist"] = status_entry
            logger.warning("Local blocklist file not found at %s", target_path)
            return 0

        count = 0
        try:
            with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    entry = line.strip()
                    if not entry or entry.startswith("#"):
                        continue

                    # Check type
                    if IPV4_PATTERN.match(entry):
                        try:
                            ipaddress.IPv4Address(entry)
                            self.threat_intel.mark_ip_malicious(entry, reason="Local Blocklist", confidence=1.0)
                            count += 1
                        except ValueError:
                            pass
                    elif HEX_HASH_PATTERN.match(entry):
                        self.threat_intel.add_malware_hash(entry)
                        count += 1
                    elif "." in entry and not entry.startswith("http"):
                        self.threat_intel.add_domain_to_blacklist(entry)
                        count += 1

            status_entry["status"] = "synced"
            status_entry["item_count"] = count
            status_entry["last_updated"] = time.time()
            logger.info("Loaded %d indicators from local blocklist.", count)
        except Exception as exc:
            status_entry["status"] = "error"
            status_entry["error"] = str(exc)
            logger.error("Failed to load local blocklist: %s", exc)

        with self._lock:
            self._feed_statuses["Local Blocklist"] = status_entry
        return count

    def fetch_remote_feed(self, url: str, name: str) -> int:
        """Fetch and parse a remote threat feed URL with timeout and graceful offline fallback."""
        status_entry: Dict[str, Any] = {
            "name": name,
            "source_type": "remote",
            "location": url,
            "status": "fetching",
            "item_count": 0,
            "last_updated": time.time(),
            "error": None,
        }

        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Volcano-AI-Firewall-IoC-Loader/1.0",
                "Accept": "text/plain, text/csv, */*",
            },
        )

        count = 0
        try:
            with urllib.request.urlopen(req, timeout=6.0) as resp:
                content = resp.read().decode("utf-8", errors="ignore")

            for line in content.splitlines():
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#"):
                    continue

                parts = [p.strip().strip('"').strip("'") for p in clean_line.split(",")]
                for part in parts:
                    if IPV4_PATTERN.match(part):
                        try:
                            ipaddress.IPv4Address(part)
                            self.threat_intel.mark_ip_malicious(part, reason=name, confidence=0.9)
                            count += 1
                            break
                        except ValueError:
                            pass
                    elif "." in part and not part.startswith("http") and "/" not in part:
                        self.threat_intel.add_domain_to_blacklist(part)
                        count += 1
                        break

            status_entry["status"] = "synced"
            status_entry["item_count"] = count
            status_entry["last_updated"] = time.time()
            logger.info("Feed '%s' synced %d indicators.", name, count)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
            status_entry["status"] = "degraded_offline"
            status_entry["error"] = f"Network unavailable or unreachable: {exc}"
            logger.warning("Threat feed '%s' unreachable (%s); using local blocklist cache.", name, exc)
        except Exception as exc:
            status_entry["status"] = "failed"
            status_entry["error"] = str(exc)
            logger.warning("Error parsing feed '%s': %s", name, exc)

        with self._lock:
            self._feed_statuses[name] = status_entry
        return count

    def refresh_all_feeds(self) -> Dict[str, Any]:
        """Perform synchronization across all local and remote threat intelligence feeds."""
        cfg = get_settings()
        local_count = self.load_local_blocklist()

        feed_names = {
            "https://feodotracker.abuse.ch/downloads/ipblocklist.csv": "Feodo Tracker Botnet C2",
            "https://urlhaus.abuse.ch/downloads/csv_recent/": "URLhaus Malware Distribution",
        }

        remote_counts = {}
        for url in cfg.feed_urls:
            name = feed_names.get(url, f"Threat Feed ({url.split('/')[2] if '//' in url else url})")
            cnt = self.fetch_remote_feed(url, name)
            remote_counts[name] = cnt

        self._last_refresh = time.time()
        return {
            "local_indicators": local_count,
            "remote_feeds": remote_counts,
            "feeds": self.get_feed_statuses(),
            "refreshed_at": self._last_refresh,
        }

    def lookup(self, indicator: str) -> Dict[str, Any]:
        """Lookup an IP, domain, or file hash in the ingested threat intelligence repository."""
        target = indicator.strip().lower()
        is_ip_malicious = self.threat_intel.is_ip_malicious(target)
        is_domain_blacklisted = self.threat_intel.is_domain_blacklisted(target)
        is_hash_malicious = self.threat_intel.is_malware_hash(target)

        matched = is_ip_malicious or is_domain_blacklisted or is_hash_malicious
        reputation = self.threat_intel.get_reputation_summary(target) if is_ip_malicious else None

        return {
            "target": indicator,
            "is_threat": matched,
            "type": "ip" if IPV4_PATTERN.match(target) else ("hash" if HEX_HASH_PATTERN.match(target) else "domain"),
            "is_ip_malicious": is_ip_malicious,
            "is_domain_blacklisted": is_domain_blacklisted,
            "is_malware_hash": is_hash_malicious,
            "reputation": reputation,
        }
