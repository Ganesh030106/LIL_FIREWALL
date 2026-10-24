"""Scanner package for network discovery and port auditing."""

from .port_scanner import PortScanner, get_port_scanner, TOP_20_PORTS, TOP_100_PORTS

__all__ = ["PortScanner", "get_port_scanner", "TOP_20_PORTS", "TOP_100_PORTS"]
