"""NetFlow v9 Input Adapter for Volcano Sensor.

Implementation Details:
- Parses NetFlow v9 packet headers (RFC 3954, 20 bytes).
- Supports Template FlowSet (ID=0) and Data FlowSet (ID >= 256).
- Maps common NetFlow fields: IPv4 source/destination, L4 source/destination port, protocol, bytes, packets.
- Emits normalized SensorEvent instances for flow records.

Explicitly Skipped in this initial Phase 3 implementation:
- Options Template FlowSets (ID=1) and Option Data records.
- IPv6 128-bit address fields (IPV6_SRC_ADDR, IPV6_DST_ADDR).
- IPFIX (v10) enterprise-specific vendor extensions.
- NetFlow v5/v7 legacy formats.
"""

from __future__ import annotations

import socket
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

from sensor.schema import SensorEvent

# NetFlow v9 Field Type IDs (RFC 3954)
FIELD_IN_BYTES = 1
FIELD_IN_PKTS = 2
FIELD_PROTOCOL = 4
FIELD_L4_SRC_PORT = 7
FIELD_IPV4_SRC_ADDR = 8
FIELD_L4_DST_PORT = 11
FIELD_IPV4_DST_ADDR = 12


class NetFlowV9Parser:
    """Parses binary NetFlow v9 packets into normalized SensorEvent instances."""

    def __init__(self, sensor_id: str = "netflow-sensor-01") -> None:
        self.sensor_id = sensor_id
        # Map: template_id -> list of (field_type, field_length)
        self.templates: Dict[int, List[Tuple[int, int]]] = {}

    def parse_packet(self, data: bytes) -> List[SensorEvent]:
        """Parse raw NetFlow v9 UDP packet payload."""
        if len(data) < 20:
            return []

        version, count, sys_uptime, unix_secs, seq_num, source_id = struct.unpack("!HHIIII", data[:20])
        if version != 9:
            return []

        events: List[SensorEvent] = []
        offset = 20
        total_len = len(data)

        while offset + 4 <= total_len:
            flowset_id, flowset_len = struct.unpack("!HH", data[offset:offset + 4])
            if flowset_len < 4 or offset + flowset_len > total_len:
                break

            flowset_data = data[offset + 4:offset + flowset_len]

            if flowset_id == 0:
                # Template FlowSet
                self._parse_template_flowset(flowset_data)
            elif flowset_id >= 256:
                # Data FlowSet
                template_id = flowset_id
                template = self.templates.get(template_id)
                if template:
                    events.extend(self._parse_data_flowset(flowset_data, template, unix_secs))

            offset += flowset_len

        return events

    def _parse_template_flowset(self, data: bytes) -> None:
        offset = 0
        while offset + 4 <= len(data):
            template_id, field_count = struct.unpack("!HH", data[offset:offset + 4])
            offset += 4
            fields: List[Tuple[int, int]] = []
            for _ in range(field_count):
                if offset + 4 > len(data):
                    break
                ftype, flen = struct.unpack("!HH", data[offset:offset + 4])
                fields.append((ftype, flen))
                offset += 4
            self.templates[template_id] = fields

    def _parse_data_flowset(
        self,
        data: bytes,
        template: List[Tuple[int, int]],
        unix_secs: int,
    ) -> List[SensorEvent]:
        events: List[SensorEvent] = []
        record_len = sum(flen for _, flen in template)
        if record_len <= 0:
            return []

        offset = 0
        while offset + record_len <= len(data):
            record_data = data[offset:offset + record_len]
            event = self._decode_record(record_data, template, unix_secs)
            if event:
                events.append(event)
            offset += record_len

        return events

    def _decode_record(
        self,
        data: bytes,
        template: List[Tuple[int, int]],
        unix_secs: int,
    ) -> Optional[SensorEvent]:
        offset = 0
        extracted: Dict[int, Any] = {}

        for ftype, flen in template:
            field_bytes = data[offset:offset + flen]
            offset += flen

            if ftype in (FIELD_IPV4_SRC_ADDR, FIELD_IPV4_DST_ADDR) and flen == 4:
                extracted[ftype] = socket.inet_ntoa(field_bytes)
            elif ftype in (FIELD_L4_SRC_PORT, FIELD_L4_DST_PORT) and flen == 2:
                extracted[ftype] = struct.unpack("!H", field_bytes)[0]
            elif ftype == FIELD_PROTOCOL and flen == 1:
                proto_num = struct.unpack("!B", field_bytes)[0]
                proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
                extracted[ftype] = proto_map.get(proto_num, f"IP-{proto_num}")
            elif ftype == FIELD_IN_BYTES:
                extracted[ftype] = int.from_bytes(field_bytes, byteorder="big")
            elif ftype == FIELD_IN_PKTS:
                extracted[ftype] = int.from_bytes(field_bytes, byteorder="big")

        src_ip = extracted.get(FIELD_IPV4_SRC_ADDR)
        dst_ip = extracted.get(FIELD_IPV4_DST_ADDR)
        src_port = extracted.get(FIELD_L4_SRC_PORT)
        dst_port = extracted.get(FIELD_L4_DST_PORT)
        protocol = extracted.get(FIELD_PROTOCOL, "TCP")

        return SensorEvent(
            sensor_id=self.sensor_id,
            timestamp=float(unix_secs) if unix_secs else time.time(),
            event_type="flow",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            data={
                "adapter": "netflow_v9",
                "bytes": extracted.get(FIELD_IN_BYTES, 0),
                "pkts": extracted.get(FIELD_IN_PKTS, 0),
            },
        )
