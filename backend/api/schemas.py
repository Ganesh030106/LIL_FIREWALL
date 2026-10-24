from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(slots=True)
class AlertRecord:
    id: int
    timestamp: str
    source: str
    severity: str
    category: str
    message: str
    meta: Dict[str, Any]
    status: str = "new"
    assignee: Optional[str] = None
    notes: Optional[str] = None


class URLCheckRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)


class KillSwitchRequest(BaseModel):
    confirm: bool = Field(default=True)
    interface: Optional[str] = None
    dry_run: bool = Field(default=False)


class ThreatSummary(BaseModel):
    risk_score: float
    threat_level: str
    recommended_action: str
    confidence: float
    top_signals: List[str]
    category_breakdown: Dict[str, int]
    severity_breakdown: Dict[str, int]


# --- Authentication & Users ---

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=100)


class ChangePasswordRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    current_password: str = Field(..., min_length=1, max_length=100)
    new_password: str = Field(..., min_length=8, max_length=100)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]


class UserCreateRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6, max_length=100)
    role: str = Field(default="viewer")


class UserRoleUpdateRequest(BaseModel):
    role: str = Field(..., description="Role to assign: admin, analyst, or viewer")


# --- Alert Triage ---

class AlertTriageRequest(BaseModel):
    status: Optional[str] = Field(default=None, description="new, acknowledged, investigating, resolved, false_positive")
    assignee: Optional[str] = Field(default=None)
    notes: Optional[str] = Field(default=None)


class AlertBulkRequest(BaseModel):
    alert_ids: List[int]
    action: str = Field(..., description="'status' or 'delete'")
    status_value: Optional[str] = None


# --- Notifications & Settings ---

class NotificationTestRequest(BaseModel):
    channel: Optional[str] = Field(default="all", description="slack, discord, telegram, smtp, or all")
    message: Optional[str] = Field(default=None, description="Optional custom test message")


class SettingsUpdateRequest(BaseModel):
    port_scan_threshold: Optional[int] = None
    port_scan_window: Optional[float] = None
    ddos_threshold: Optional[int] = None
    ddos_window: Optional[float] = None
    ransomware_rate_threshold: Optional[int] = None
    ransomware_window: Optional[float] = None
    brute_force_threshold: Optional[int] = None
    brute_force_window: Optional[float] = None
    brute_force_ports: Optional[List[int]] = None
    dns_tunneling_subdomain_length: Optional[int] = None
    dns_tunneling_entropy: Optional[float] = None
    dns_query_rate_threshold: Optional[int] = None
    dga_entropy_threshold: Optional[float] = None
    allowlist_ips: Optional[List[str]] = None
    quarantine_default_duration: Optional[float] = None
    killswitch_dry_run: Optional[bool] = None
    killswitch_interface: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    discord_webhook_url: Optional[str] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = None
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_recipient: Optional[str] = None
    notification_min_severity: Optional[str] = None
    notification_cooldown: Optional[float] = None
    feed_refresh_interval: Optional[int] = None
    feed_urls: Optional[List[str]] = None
    local_blocklist_path: Optional[str] = None
    llm_provider: Optional[str] = None
    llm_api_key: Optional[str] = None
    llm_api_base: Optional[str] = None
    llm_model: Optional[str] = None


class DatabaseMaintenanceRequest(BaseModel):
    action: str = Field(default="checkpoint", description="Action: 'checkpoint', 'vacuum', 'integrity', 'prune', 'optimize'")
    mode: Optional[str] = Field(default="TRUNCATE", description="WAL checkpoint mode: 'PASSIVE', 'FULL', 'RESTART', 'TRUNCATE'")
    max_alert_age_days: Optional[int] = Field(default=30)
    max_audit_age_days: Optional[int] = Field(default=90)
