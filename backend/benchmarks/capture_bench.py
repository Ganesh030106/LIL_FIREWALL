"""Packet Capture and Inspection Benchmark for Volcano AI Firewall.

Measures throughput (packets/sec), CPU utilization, and memory consumption
of the Scapy packet inspection pipeline (PacketAnomalyEngine._handle_packet).
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any, Dict, List

# Ensure backend root is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import psutil
from scapy.all import Ether, IP, TCP, UDP
try:
    from scapy.layers.dns import DNS, DNSQR
except Exception:
    DNS, DNSQR = None, None

from app import PacketAnomalyEngine
from core.rule_engine import RuleEngine
from core.state_engine import StateEngine
from security.ids_engine import IDSEngine
from ai.anomaly_detector import AnomalyDetector
from ai.risk_engine import RiskEngine
from security.brute_force_detector import BruteForceDetector
from security.dns_threat_detector import DNSThreatDetector
from security.beacon_detector import BeaconDetector
from security.lateral_movement_detector import LateralMovementDetector
from storage.memory_store import AlertStore, MetricsStore


def generate_benchmark_packets(count: int = 5000) -> List[Any]:
    """Generate realistic synthetic pcap packet mixture for benchmarking."""
    packets = []
    for i in range(count):
        mod = i % 4
        if mod == 0:
            # TCP connection attempt (SYN packet)
            pkt = Ether() / IP(src=f"192.168.1.{10 + (i % 50)}", dst="10.0.0.1") / TCP(sport=10000 + (i % 20000), dport=80, flags="S")
        elif mod == 1:
            # DNS query packet
            if DNS is not None and DNSQR is not None:
                pkt = Ether() / IP(src=f"192.168.1.{10 + (i % 50)}", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname=f"test{i}.example.com"))
            else:
                pkt = Ether() / IP(src=f"192.168.1.{10 + (i % 50)}", dst="8.8.8.8") / UDP(sport=53000, dport=53)
        elif mod == 2:
            # SSH / high-risk port attempt
            pkt = Ether() / IP(src=f"198.51.100.{1 + (i % 20)}", dst="10.0.0.1") / TCP(sport=40000 + (i % 10000), dport=22, flags="S")
        else:
            # Generic UDP payload
            pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / UDP(sport=5000, dport=5000)

        packets.append(pkt)
    return packets


def run_benchmark(packet_count: int = 5000) -> Dict[str, Any]:
    """Execute packet processing benchmark and report throughput, CPU, and memory."""
    alerts = AlertStore()
    metrics = MetricsStore(watch_directory=".")
    rule_engine = RuleEngine()
    state_engine = StateEngine()
    ids_engine = IDSEngine()
    anomaly_detector = AnomalyDetector()
    risk_engine = RiskEngine()

    engine = PacketAnomalyEngine(
        alerts=alerts,
        metrics=metrics,
        rule_engine=rule_engine,
        state_engine=state_engine,
        ids_engine=ids_engine,
        anomaly_detector=anomaly_detector,
        risk_engine=risk_engine,
        brute_force_detector=BruteForceDetector(),
        dns_threat_detector=DNSThreatDetector(),
        beacon_detector=BeaconDetector(),
        lateral_detector=LateralMovementDetector(),
    )

    print(f"[*] Pre-generating {packet_count} packets for capture benchmark...")
    packets = generate_benchmark_packets(packet_count)

    proc = psutil.Process()
    # Baseline measurement
    _ = proc.cpu_percent(interval=None)
    mem_before_mb = proc.memory_info().rss / (1024 * 1024)

    print("[*] Starting benchmark throughput execution...")
    t_start = time.perf_counter()

    for pkt in packets:
        engine._handle_packet(pkt)

    t_end = time.perf_counter()
    elapsed_seconds = t_end - t_start
    cpu_percent = proc.cpu_percent(interval=None)
    mem_after_mb = proc.memory_info().rss / (1024 * 1024)

    packets_per_second = packet_count / elapsed_seconds if elapsed_seconds > 0 else 0.0

    results = {
        "packets_processed": packet_count,
        "elapsed_seconds": round(elapsed_seconds, 4),
        "packets_per_second": round(packets_per_second, 2),
        "cpu_percent": round(cpu_percent, 2),
        "memory_start_mb": round(mem_before_mb, 2),
        "memory_end_mb": round(mem_after_mb, 2),
        "memory_delta_mb": round(mem_after_mb - mem_before_mb, 2),
    }

    print("\n" + "=" * 60)
    print("  VOLCANO AI FIREWALL - SCAPY CAPTURE BENCHMARK REPORT")
    print("=" * 60)
    print(f" Packets Processed:       {results['packets_processed']:,}")
    print(f" Elapsed Time:            {results['elapsed_seconds']:.4f} s")
    print(f" Throughput:              {results['packets_per_second']:,} packets/sec")
    print(f" CPU Utilization:         {results['cpu_percent']:.1f}%")
    print(f" Memory RSS (Baseline):   {results['memory_start_mb']:.2f} MB")
    print(f" Memory RSS (Peak):       {results['memory_end_mb']:.2f} MB")
    print(f" Memory Delta:            {results['memory_delta_mb']:.2f} MB")
    print("=" * 60 + "\n")

    return results


if __name__ == "__main__":
    count = 5000
    if len(sys.argv) > 1:
        try:
            count = int(sys.argv[1])
        except ValueError:
            count = 5000
    run_benchmark(count)
