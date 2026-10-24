"""Base EnforcementBackend Interface for Volcano AI Firewall."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class EnforcementBackend(ABC):
    """Abstract interface for firewall containment backends (nftables, iptables, software)."""

    @abstractmethod
    def apply_block(self, ip: str, ttl: Optional[float] = None) -> bool:
        """Apply a network block for an IP address with optional TTL in seconds."""
        pass

    @abstractmethod
    def remove_block(self, ip: str) -> bool:
        """Remove a network block for an IP address."""
        pass

    @abstractmethod
    def list_blocks(self) -> List[Dict[str, Any]]:
        """List all currently active network blocks."""
        pass

    @abstractmethod
    def snapshot(self) -> Dict[str, Any]:
        """Create a point-in-time snapshot of the backend rules/sets."""
        pass

    @abstractmethod
    def restore(self, snapshot_data: Dict[str, Any]) -> bool:
        """Restore backend state to a previously saved snapshot."""
        pass
