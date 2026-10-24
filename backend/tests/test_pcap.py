"""Unit tests for PCAP Ring Buffer and Packet Forensics."""

from __future__ import annotations

from packet_engine.pcap_buffer import PCAPRingBuffer

try:
    from scapy.all import IP, TCP
except Exception:
    IP, TCP = None, None


def test_pcap_buffer_queue_and_limit() -> None:
    buf = PCAPRingBuffer(maxlen=5)
    assert buf.get_packet_count() == 0

    if IP is not None and TCP is not None:
        for i in range(10):
            pkt = IP(src=f"10.0.0.{i}", dst="8.8.8.8") / TCP(dport=80)
            buf.add_packet(pkt)

        # Buffer should be bounded by maxlen
        assert buf.get_packet_count() == 5

        stats = buf.get_stats()
        assert stats["packet_count"] == 5
        assert stats["capacity"] == 5
        assert stats["newest_timestamp"] is not None

        # Verify binary export
        pcap_data = buf.export_pcap_bytes()
        assert len(pcap_data) > 24  # Standard PCAP file header is 24 bytes
        # Standard pcap magic number: 0xd4c3b2a1 or 0xa1b2c3d4
        magic = pcap_data[:4].hex()
        assert magic in ("d4c3b2a1", "a1b2c3d4")


def test_pcap_buffer_clear() -> None:
    buf = PCAPRingBuffer(maxlen=5)
    if IP is not None:
        buf.add_packet(IP(src="1.1.1.1", dst="2.2.2.2"))
        assert buf.get_packet_count() == 1
        buf.clear()
        assert buf.get_packet_count() == 0
