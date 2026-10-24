from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(slots=True)
class DeviceProfile:
    mac_address: str
    last_seen: float
    risk_score: float = 0.0
    threat_count: int = 0
    alert_history: List[str] = field(default_factory=list)
    behavioral_tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.alert_history is None:
            self.alert_history = []
        if self.behavioral_tags is None:
            self.behavioral_tags = []
        if self.metadata is None:
            self.metadata = {}


@dataclass(slots=True)
class UserProfile:
    user_id: str
    last_seen: float
    risk_score: float = 0.0
    threat_count: int = 0
    access_patterns: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    alert_history: List[str] = field(default_factory=list)
    behavioral_tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.access_patterns is None:
            self.access_patterns = defaultdict(int)
        if self.alert_history is None:
            self.alert_history = []
        if self.behavioral_tags is None:
            self.behavioral_tags = []
        if self.metadata is None:
            self.metadata = {}


class RiskEngine:
    def __init__(self) -> None:
        self._device_profiles: Dict[str, DeviceProfile] = {}
        self._user_profiles: Dict[str, UserProfile] = {}
        self._session_risk: Dict[str, float] = {}
        self._lock = threading.RLock()

    def update_device_risk(self, mac_address: str, threat_detected: bool = False, threat_severity: str = "low") -> float:
        with self._lock:
            if mac_address not in self._device_profiles:
                self._device_profiles[mac_address] = DeviceProfile(
                    mac_address=mac_address,
                    last_seen=time.time(),
                    risk_score=0.0,
                )

            profile = self._device_profiles[mac_address]
            profile.last_seen = time.time()

            if threat_detected:
                profile.threat_count += 1
                severity_weight = {"low": 0.1, "medium": 0.3, "high": 0.5, "critical": 0.8}
                weight = severity_weight.get(threat_severity, 0.1)
                decay_factor = 0.95
                profile.risk_score = profile.risk_score * decay_factor + weight * (1 - decay_factor)
                profile.risk_score = min(1.0, profile.risk_score)

            return profile.risk_score

    def update_user_risk(self, user_id: str, threat_detected: bool = False, threat_severity: str = "low") -> float:
        with self._lock:
            if user_id not in self._user_profiles:
                self._user_profiles[user_id] = UserProfile(
                    user_id=user_id,
                    last_seen=time.time(),
                    risk_score=0.0,
                )

            profile = self._user_profiles[user_id]
            profile.last_seen = time.time()

            if threat_detected:
                profile.threat_count += 1
                severity_weight = {"low": 0.1, "medium": 0.25, "high": 0.4, "critical": 0.7}
                weight = severity_weight.get(threat_severity, 0.1)
                decay_factor = 0.98
                profile.risk_score = profile.risk_score * decay_factor + weight * (1 - decay_factor)
                profile.risk_score = min(1.0, profile.risk_score)

            return profile.risk_score

    def update_session_risk(self, session_id: str, risk_delta: float) -> float:
        with self._lock:
            current_risk = self._session_risk.get(session_id, 0.0)
            new_risk = max(0.0, min(1.0, current_risk + risk_delta))
            self._session_risk[session_id] = new_risk
            return new_risk

    def get_device_profile(self, mac_address: str) -> Optional[DeviceProfile]:
        with self._lock:
            return self._device_profiles.get(mac_address)

    def get_user_profile(self, user_id: str) -> Optional[UserProfile]:
        with self._lock:
            return self._user_profiles.get(user_id)

    def list_high_risk_devices(self, threshold: float = 0.5) -> List[DeviceProfile]:
        with self._lock:
            return [p for p in self._device_profiles.values() if p.risk_score >= threshold]

    def list_high_risk_users(self, threshold: float = 0.5) -> List[UserProfile]:
        with self._lock:
            return [p for p in self._user_profiles.values() if p.risk_score >= threshold]

    def get_risk_stats(self) -> Dict[str, Any]:
        with self._lock:
            avg_device_risk = sum(p.risk_score for p in self._device_profiles.values()) / len(self._device_profiles) if self._device_profiles else 0.0
            avg_user_risk = sum(p.risk_score for p in self._user_profiles.values()) / len(self._user_profiles) if self._user_profiles else 0.0
            return {
                "devices_profiled": len(self._device_profiles),
                "users_profiled": len(self._user_profiles),
                "avg_device_risk": round(avg_device_risk, 3),
                "avg_user_risk": round(avg_user_risk, 3),
                "high_risk_devices": sum(1 for p in self._device_profiles.values() if p.risk_score >= 0.7),
                "high_risk_users": sum(1 for p in self._user_profiles.values() if p.risk_score >= 0.7),
            }
