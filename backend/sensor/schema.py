"""Versioned Event Schema for Volcano AI Firewall Sensor and Collector Architecture."""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator

CURRENT_SCHEMA_VERSION = "1.0"
SUPPORTED_SCHEMA_VERSIONS = frozenset(["1.0"])


class SensorEvent(BaseModel):
    """Normalized security or network telemetry event emitted by a sensor."""

    schema_version: str = Field(
        default=CURRENT_SCHEMA_VERSION,
        description="Version of the event schema for backwards-compatibility checking",
    )
    event_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex,
        description="Globally unique identifier for the event",
    )
    sensor_id: str = Field(
        default="sensor-default",
        description="Identifier of the emitting sensor instance",
    )
    timestamp: float = Field(
        default_factory=time.time,
        description="Epoch timestamp when the event was observed",
    )
    event_type: str = Field(
        description="Event classification (e.g., alert, flow, dns, brute_force, beacon, lateral)",
    )
    src_ip: Optional[str] = Field(default=None, description="Source IPv4/IPv6 address")
    dst_ip: Optional[str] = Field(default=None, description="Destination IPv4/IPv6 address")
    src_port: Optional[int] = Field(default=None, description="Source port")
    dst_port: Optional[int] = Field(default=None, description="Destination port")
    protocol: Optional[str] = Field(default=None, description="Protocol (TCP, UDP, ICMP, DNS)")
    data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Detector-specific metadata, alert payload, or flow metrics",
    )

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, v: str) -> str:
        if v not in SUPPORTED_SCHEMA_VERSIONS:
            raise ValueError(
                f"Unsupported schema version: '{v}'. Supported versions: {sorted(SUPPORTED_SCHEMA_VERSIONS)}"
            )
        return v


class SensorEventBatch(BaseModel):
    """Batch wrapper for emitting multiple sensor events over network transports."""

    schema_version: str = Field(
        default=CURRENT_SCHEMA_VERSION,
        description="Version of the batch schema",
    )
    sensor_id: str = Field(description="Identifier of the emitting sensor")
    events: List[SensorEvent] = Field(
        default_factory=list,
        description="List of normalized events",
    )

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, v: str) -> str:
        if v not in SUPPORTED_SCHEMA_VERSIONS:
            raise ValueError(
                f"Unsupported schema version: '{v}'. Supported versions: {sorted(SUPPORTED_SCHEMA_VERSIONS)}"
            )
        return v
