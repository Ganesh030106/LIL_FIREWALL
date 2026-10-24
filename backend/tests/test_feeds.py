"""Unit tests for Threat Intelligence Feeds and GeoIP Fallback."""

from __future__ import annotations

from ai.threat_correlation import ThreatIntelligence
from ai.feed_loader import FeedLoader
from security.geoip_service import GeoIPService


def test_threat_intelligence_local_blocklist() -> None:
    intel = ThreatIntelligence()
    # Add known malicious IP and domain
    intel.mark_ip_malicious("185.220.101.5", reason="Tor Exit Node", confidence=0.95)
    intel.add_domain_to_blacklist("phish-update-bank.top")

    assert intel.is_ip_malicious("185.220.101.5") is True
    assert intel.is_ip_malicious("8.8.8.8") is False

    assert intel.is_domain_blacklisted("phish-update-bank.top") is True
    assert intel.is_domain_blacklisted("google.com") is False


def test_feed_loader_graceful_offline_degradation() -> None:
    intel = ThreatIntelligence()
    loader = FeedLoader(intel)

    # Attempt to load from an unreachable endpoint
    count = loader.fetch_remote_feed(
        url="http://192.0.2.1:9999/non_existent.csv",
        name="Offline Test Feed",
    )
    assert count == 0

    statuses = loader.get_feed_statuses()
    offline_status = next((s for s in statuses if s["name"] == "Offline Test Feed"), None)
    assert offline_status is not None
    assert offline_status["status"] == "degraded_offline"
    assert offline_status["item_count"] == 0


def test_geoip_service_fallback() -> None:
    geoip = GeoIPService(db_path="/non/existent/GeoLite2-City.mmdb")

    # 1. Private IP returns local network metadata
    local_info = geoip.lookup("192.168.1.50")
    assert isinstance(local_info, dict)
    assert local_info["ip"] == "192.168.1.50"
    assert local_info["country"] == "Local Network"
    assert local_info["is_private"] is True

    # 2. Public IP gracefully returns None when MMDB file is absent
    public_info = geoip.lookup("8.8.8.8")
    assert public_info is None

    # 3. enrich_meta does not crash
    meta: dict = {}
    geoip.enrich_meta("192.168.1.50", meta)
    assert "geoip" in meta
    assert meta["geoip"]["country"] == "Local Network"

    public_meta: dict = {}
    geoip.enrich_meta("8.8.8.8", public_meta)
    # Should safely leave meta untouched without raising exceptions
    assert "geoip" not in public_meta
