"""Nftables Enforcement Backend for Volcano AI Firewall (Phase 2).
Manages dedicated 'volcano' nftables table and sets for real kernel-level packet filtering.
Enforces non-shell argument lists, strict ipaddress validation, allowlist immunity, and dry-run defaults.
"""

from __future__ import annotations

import ipaddress
import logging
import subprocess
import time
from typing import Any, Dict, List, Optional, Set

from config import get_settings
from security.enforcement.base import EnforcementBackend

logger = logging.getLogger("volcano.enforcement.nftables")


class NftablesBackend(EnforcementBackend):
    """Linux nftables kernel packet filter backend."""

    def __init__(
        self,
        dry_run: Optional[bool] = None,
        allowlist: Optional[List[str]] = None,
        table_name: str = "volcano",
        set_name: str = "blocked_ips",
    ) -> None:
        cfg = get_settings()
        self.table_name = table_name
        self.set_name = set_name
        self.allowlist: List[str] = allowlist if allowlist is not None else list(getattr(cfg, "allowlist_ips", ["127.0.0.1", "::1", "0.0.0.0"]))

        # Safe default: Dry run is TRUE unless explicitly configured as live
        if dry_run is not None:
            self.dry_run = dry_run
        else:
            configured_mode = getattr(cfg, "enforcement_mode", "dry_run")
            self.dry_run = configured_mode.lower().strip() != "live"

        self._blocks: Dict[str, Dict[str, Any]] = {}
        logger.info("Initialized NftablesBackend (table=%s, set=%s, dry_run=%s)", self.table_name, self.set_name, self.dry_run)

    def _run_nft(self, args: List[str]) -> subprocess.CompletedProcess:
        """Execute nft command with safe non-shell argument lists."""
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            raise TypeError("nftables commands must be provided as a list of strings")

        if self.dry_run:
            logger.info("[DRY-RUN] Simulating nftables command: %s", " ".join(args))
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

        # LIVE EXECUTION: NEVER use shell=True
        try:
            return subprocess.run(
                args,
                shell=False,
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as err:
            logger.error("nftables command '%s' failed: %s (stderr: %s)", " ".join(args), err, err.stderr)
            raise

    def validate_ip(self, ip_str: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        """Validate string as a strict IP address using ipaddress."""
        if not ip_str or not isinstance(ip_str, str):
            raise ValueError(f"Invalid IP address input: {ip_str}")
        clean = ip_str.strip()
        try:
            return ipaddress.ip_address(clean)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address '{ip_str}': {exc}") from exc

    def is_allowlisted(self, ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Check if an IP is protected by allowlist invariants (loopback, unspecified, configured)."""
        if ip_obj.is_loopback or ip_obj.is_unspecified:
            return True

        ip_str = str(ip_obj)
        if ip_str in self.allowlist:
            return True
        for allowed in self.allowlist:
            if "/" in allowed:
                try:
                    if ip_obj in ipaddress.ip_network(allowed, strict=False):
                        return True
                except ValueError:
                    pass
            else:
                try:
                    if ip_obj == ipaddress.ip_address(allowed):
                        return True
                except ValueError:
                    pass
        return False

    def init_table(self) -> None:
        """Initialize dedicated volcano table and sets if they do not exist."""
        # 1. Add inet table
        self._run_nft(["nft", "add", "table", "inet", self.table_name])
        # 2. Add set for IPv4/IPv6 addresses
        self._run_nft(["nft", "add", "set", "inet", self.table_name, self.set_name, "{ type ipv4_addr; flags timeout; }"])
        # 3. Add base input chain
        self._run_nft(["nft", "add", "chain", "inet", self.table_name, "input", "{ type filter hook input priority -10; policy accept; }"])
        # 4. Add drop rule for the set
        self._run_nft(["nft", "add", "rule", "inet", self.table_name, "input", "ip", "saddr", f"@{self.set_name}", "drop"])

    def apply_block(self, ip: str, ttl: Optional[float] = None) -> bool:
        """Apply block to an IP address with optional TTL in seconds."""
        ip_obj = self.validate_ip(ip)

        # Enforce allowlist protection invariant
        if self.is_allowlisted(ip_obj):
            logger.warning("Refused to apply nftables block on allowlisted IP %s", ip)
            return False

        clean_ip = str(ip_obj)
        if ttl is not None and ttl > 0:
            element_expr = f"{{ {clean_ip} timeout {int(ttl)}s }}"
        else:
            element_expr = f"{{ {clean_ip} }}"

        cmd = ["nft", "add", "element", "inet", self.table_name, self.set_name, element_expr]
        self._run_nft(cmd)

        now = time.time()
        self._blocks[clean_ip] = {
            "ip": clean_ip,
            "ttl": ttl,
            "created_at": now,
            "expires_at": (now + ttl) if ttl else None,
            "backend": "nftables",
            "dry_run": self.dry_run,
        }
        return True

    def remove_block(self, ip: str) -> bool:
        """Remove block for an IP address."""
        ip_obj = self.validate_ip(ip)
        clean_ip = str(ip_obj)

        cmd = ["nft", "delete", "element", "inet", self.table_name, self.set_name, f"{{ {clean_ip} }}"]
        self._run_nft(cmd)
        self._blocks.pop(clean_ip, None)
        return True

    def list_blocks(self) -> List[Dict[str, Any]]:
        """List all currently active network blocks."""
        return [dict(v) for v in self._blocks.values()]

    def snapshot(self) -> Dict[str, Any]:
        """Create point-in-time snapshot of the active firewall rules."""
        return {
            "backend": "nftables",
            "table": f"inet {self.table_name}",
            "set": self.set_name,
            "blocked_ips": sorted(list(self._blocks.keys())),
            "blocks": [dict(v) for v in self._blocks.values()],
            "timestamp": time.time(),
            "dry_run": self.dry_run,
        }

    def restore(self, snapshot_data: Dict[str, Any]) -> bool:
        """Restore firewall state from snapshot data."""
        target_ips: Set[str] = set(snapshot_data.get("blocked_ips", []))
        current_ips: Set[str] = set(self._blocks.keys())

        # Remove IPs that are currently blocked but absent in the snapshot
        for ip in (current_ips - target_ips):
            try:
                self.remove_block(ip)
            except Exception as exc:
                logger.warning("Failed to remove block during restore: %s", exc)

        # Re-apply IPs present in the snapshot
        for ip in (target_ips - current_ips):
            try:
                self.apply_block(ip)
            except Exception as exc:
                logger.warning("Failed to apply block during restore: %s", exc)

        return True
