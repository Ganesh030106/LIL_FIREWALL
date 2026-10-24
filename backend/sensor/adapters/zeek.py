"""Zeek conn.log TSV Input Adapter for Volcano Sensor."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterator, List, Optional, Union

from sensor.schema import SensorEvent


class ZeekConnLogAdapter:
    """
    Parser for Zeek (formerly Bro) conn.log TSV files.
    Reads header metadata (#fields) and converts each connection row into a normalized SensorEvent.
    """

    def __init__(self, sensor_id: str = "zeek-sensor-01") -> None:
        self.sensor_id = sensor_id

    def parse_file(self, file_path: Union[str, Path]) -> List[SensorEvent]:
        """Parse all events from a Zeek conn.log file on disk."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Zeek log file not found: {file_path}")

        events: List[SensorEvent] = []
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for ev in self.parse_stream(f):
                events.append(ev)
        return events

    def parse_stream(self, lines: Iterator[str]) -> Iterator[SensorEvent]:
        """Streamingly parse Zeek log lines into SensorEvent instances."""
        fields: Optional[List[str]] = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Header metadata lines start with '#'
            if line.startswith("#"):
                if line.startswith("#fields"):
                    # Format: #fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p ...
                    parts = line.split()
                    fields = parts[1:]
                continue

            if not fields:
                # Line arrived before #fields was established
                continue

            values = line.split("\t")
            if len(values) != len(fields):
                # Try fallback whitespace splitting if tab splitting mismatched
                values = line.split()
                if len(values) != len(fields):
                    continue

            record: Dict[str, str] = dict(zip(fields, values))

            # Normalize fields
            try:
                raw_ts = record.get("ts", "0")
                timestamp = float(raw_ts) if raw_ts != "-" else 0.0
            except ValueError:
                timestamp = 0.0

            src_ip = record.get("id.orig_h")
            if src_ip == "-":
                src_ip = None

            dst_ip = record.get("id.resp_h")
            if dst_ip == "-":
                dst_ip = None

            try:
                raw_sport = record.get("id.orig_p", "-")
                src_port = int(raw_sport) if raw_sport != "-" else None
            except ValueError:
                src_port = None

            try:
                raw_dport = record.get("id.resp_p", "-")
                dst_port = int(raw_dport) if raw_dport != "-" else None
            except ValueError:
                dst_port = None

            proto = record.get("proto", "TCP").upper()
            if proto == "-":
                proto = "UNKNOWN"

            yield SensorEvent(
                sensor_id=self.sensor_id,
                timestamp=timestamp,
                event_type="flow",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                data={
                    "adapter": "zeek",
                    "conn_state": record.get("conn_state"),
                    "duration": record.get("duration"),
                    "service": record.get("service"),
                    "orig_bytes": record.get("orig_bytes"),
                    "resp_bytes": record.get("resp_bytes"),
                    "uid": record.get("uid"),
                },
            )
