"""GeoIP Enrichment Service for Volcano AI Firewall.
Provides IP geolocation metadata (country, city, coordinates) using MaxMind GeoLite2 MMDB.
Degrades gracefully if database file or maxminddb library is absent.
"""

from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from config import get_settings

logger = logging.getLogger("volcano.geoip")


class GeoIPService:
    """Provides IP geolocation enrichment with graceful offline/missing database degradation."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path
        self._reader: Any = None
        self._initialized = False
        self._available = False
        self._warned = False

    def _init_db(self) -> None:
        if self._initialized:
            return
        self._initialized = True

        cfg = get_settings()
        target_path_str = self.db_path or cfg.geoip_database_path
        target_path = Path(target_path_str)

        if not target_path.exists():
            if not self._warned:
                logger.info("GeoLite2 database not found at %s. Geolocation enrichment disabled.", target_path)
                self._warned = True
            self._available = False
            return

        try:
            import maxminddb  # type: ignore

            self._reader = maxminddb.open_database(str(target_path))
            self._available = True
            logger.info("GeoLite2 database loaded from %s.", target_path)
        except ImportError:
            try:
                import geoip2.database  # type: ignore

                self._reader = geoip2.database.Reader(str(target_path))
                self._available = True
                logger.info("GeoLite2 database loaded via geoip2 from %s.", target_path)
            except ImportError:
                if not self._warned:
                    logger.info("maxminddb or geoip2 library not installed. Geolocation enrichment disabled.")
                    self._warned = True
                self._available = False
        except Exception as e:
            logger.warning("Error opening GeoLite2 database at %s: %s", target_path, e)
            self._available = False

    def is_available(self) -> bool:
        self._init_db()
        return self._available

    def is_private_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local
        except ValueError:
            return False

    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        """Lookup geolocation for an IP address. Returns None if unavailable or private."""
        if not ip:
            return None

        # Check for private or loopback ranges
        if self.is_private_ip(ip):
            return {
                "ip": ip,
                "country": "Local Network",
                "country_code": "LAN",
                "city": "Private Subnet",
                "latitude": 0.0,
                "longitude": 0.0,
                "is_private": True,
            }

        self._init_db()
        if not self._available or not self._reader:
            return None

        try:
            # Query reader
            if hasattr(self._reader, "city"):
                response = self._reader.city(ip)
                return {
                    "ip": ip,
                    "country": response.country.name or "Unknown",
                    "country_code": response.country.iso_code or "XX",
                    "city": response.city.name or "Unknown",
                    "latitude": float(response.location.latitude or 0.0),
                    "longitude": float(response.location.longitude or 0.0),
                    "is_private": False,
                }
            else:
                data = self._reader.get(ip)
                if not data:
                    return None
                country_data = data.get("country", {})
                city_data = data.get("city", {})
                location_data = data.get("location", {})
                return {
                    "ip": ip,
                    "country": country_data.get("names", {}).get("en", "Unknown"),
                    "country_code": country_data.get("iso_code", "XX"),
                    "city": city_data.get("names", {}).get("en", "Unknown"),
                    "latitude": float(location_data.get("latitude", 0.0)),
                    "longitude": float(location_data.get("longitude", 0.0)),
                    "is_private": False,
                }
        except Exception as e:
            logger.debug("GeoIP lookup failed for %s: %s", ip, e)
            return None

    def enrich_meta(self, ip: Optional[str], meta: Dict[str, Any]) -> Dict[str, Any]:
        """Convenience function to inject 'geoip' object into alert metadata if available."""
        if not ip:
            return meta
        geo = self.lookup(ip)
        if geo:
            meta["geoip"] = geo
        return meta

    def close(self) -> None:
        if self._reader and hasattr(self._reader, "close"):
            try:
                self._reader.close()
            except Exception:
                pass
            self._reader = None
