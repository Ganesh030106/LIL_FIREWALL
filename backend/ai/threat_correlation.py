from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(slots=True)
class ThreatIndicator:
    indicator_type: str
    value: str
    confidence: float
    timestamp: float
    source: str


class ThreatIntelligence:
    def __init__(self) -> None:
        self._ip_reputation: Dict[str, Dict[str, Any]] = {}
        self._domain_blacklist: set[str] = set()
        self._known_malware_hashes: set[str] = set()
        self._threat_indicators: Dict[str, List[ThreatIndicator]] = defaultdict(list)

    def mark_ip_malicious(self, ip: str, reason: str, confidence: float = 1.0) -> None:
        self._ip_reputation[ip] = {
            "malicious": True,
            "reason": reason,
            "confidence": confidence,
        }

    def mark_ip_safe(self, ip: str) -> None:
        if ip in self._ip_reputation:
            del self._ip_reputation[ip]

    def is_ip_malicious(self, ip: str, min_confidence: float = 0.8) -> bool:
        rep = self._ip_reputation.get(ip)
        if rep and rep.get("malicious"):
            return rep.get("confidence", 0.0) >= min_confidence
        return False

    def add_domain_to_blacklist(self, domain: str) -> None:
        self._domain_blacklist.add(domain.lower())

    def is_domain_blacklisted(self, domain: str) -> bool:
        return domain.lower() in self._domain_blacklist

    def add_malware_hash(self, file_hash: str) -> None:
        self._known_malware_hashes.add(file_hash.lower())

    def is_malware_hash(self, file_hash: str) -> bool:
        return file_hash.lower() in self._known_malware_hashes

    def add_indicator(self, target: str, indicator: ThreatIndicator) -> None:
        self._threat_indicators[target].append(indicator)

    def get_indicators_for_target(self, target: str) -> List[ThreatIndicator]:
        return self._threat_indicators.get(target, [])

    def get_reputation_summary(self, ip: str) -> Dict[str, Any]:
        rep = self._ip_reputation.get(ip, {})
        indicators = self.get_indicators_for_target(ip)
        return {
            "ip": ip,
            "is_malicious": self.is_ip_malicious(ip),
            "reputation": rep,
            "indicators_count": len(indicators),
            "indicators": [
                {
                    "type": ind.indicator_type,
                    "value": ind.value,
                    "confidence": ind.confidence,
                    "source": ind.source,
                }
                for ind in indicators[:5]
            ],
        }


class ThreatCorrelationEngine:
    def __init__(self) -> None:
        self._attack_chains: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._incident_clusters: List[List[Dict[str, Any]]] = []

    def correlate_indicators(self, indicators: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not indicators:
            return None

        sorted_indicators = sorted(indicators, key=lambda x: x.get("timestamp", 0))
        attack_type = self._detect_attack_pattern(sorted_indicators)

        if attack_type:
            incident = {
                "type": attack_type,
                "indicators": sorted_indicators,
                "confidence": self._calculate_correlation_confidence(indicators),
                "first_seen": sorted_indicators[0].get("timestamp"),
                "last_seen": sorted_indicators[-1].get("timestamp"),
            }
            return incident
        return None

    def _detect_attack_pattern(self, indicators: List[Dict[str, Any]]) -> Optional[str]:
        indicator_types = [ind.get("type") for ind in indicators]

        if "port_scan" in indicator_types:
            if "login_attempt" in indicator_types or "auth_failure" in indicator_types:
                return "targeted_intrusion"
            if "malware_detected" in indicator_types:
                return "reconnaissance_phase"
            return "port_scan"

        if "anomaly_detected" in indicator_types:
            if "data_exfiltration" in indicator_types:
                return "data_exfiltration"
            if "lateral_movement" in indicator_types:
                return "lateral_movement"

        if "ransomware_activity" in indicator_types:
            return "ransomware_attack"

        if len(indicator_types) >= 3 and len(set(indicator_types)) >= 2:
            return "multi_stage_attack"

        return None

    def _calculate_correlation_confidence(self, indicators: List[Dict[str, Any]]) -> float:
        if not indicators:
            return 0.0

        confidences = [ind.get("confidence", 0.5) for ind in indicators]
        time_proximity = self._calculate_time_proximity(indicators)

        avg_confidence = sum(confidences) / len(confidences)
        return min(1.0, avg_confidence * 0.7 + time_proximity * 0.3)

    def _calculate_time_proximity(self, indicators: List[Dict[str, Any]]) -> float:
        if len(indicators) < 2:
            return 1.0

        timestamps = sorted([ind.get("timestamp", 0) for ind in indicators])
        time_span = timestamps[-1] - timestamps[0]

        if time_span == 0:
            return 1.0
        if time_span < 60:
            return 1.0
        elif time_span < 300:
            return 0.8
        elif time_span < 3600:
            return 0.6
        else:
            return 0.3

    def cluster_incidents(self, incidents: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        clusters = []
        unclustered = list(incidents)

        while unclustered:
            seed = unclustered.pop(0)
            cluster = [seed]

            related = [inc for inc in unclustered if self._are_incidents_related(seed, inc)]
            cluster.extend(related)
            unclustered = [inc for inc in unclustered if inc not in related]

            clusters.append(cluster)

        return clusters

    def _are_incidents_related(self, incident1: Dict[str, Any], incident2: Dict[str, Any]) -> bool:
        type_match = incident1.get("type") == incident2.get("type")
        time_proximity = abs(incident1.get("first_seen", 0) - incident2.get("first_seen", 0)) < 300
        return type_match and time_proximity
