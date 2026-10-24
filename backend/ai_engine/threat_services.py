from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np

from api.schemas import ThreatSummary
from model_generator import (
    HEAVY_KEYWORDS,
    URL_SHORTENERS,
    SUSPICIOUS_TLDS,
    extract_features,
    calculate_entropy,
    _extract_domain,
)
from storage.memory_store import AlertStore, MetricsStore


class PhishingDetector:
    def __init__(self, model_path: Optional[Path] = None) -> None:
        self.model_path = model_path or (Path(__file__).resolve().parent.parent / "phishing_model.joblib")
        self._artifact = self._load_or_bootstrap()

    def _load_or_bootstrap(self) -> Dict[str, Any]:
        if not self.model_path.exists():
            from model_generator import train_model

            train_model(self.model_path)
        try:
            return joblib.load(self.model_path)
        except Exception:
            from model_generator import train_model

            train_model(self.model_path)
            return joblib.load(self.model_path)

    @property
    def model(self) -> Any:
        return self._artifact["model"]

    def predict(self, url: str) -> Dict[str, Any]:
        lowered = url.lower().strip()
        features = extract_features(lowered)

        # Handle backward compatibility: check expected feature count of loaded model
        expected_features = getattr(self.model, "n_features_in_", len(features))
        if expected_features == 4:
            # Legacy 4-feature shape: [url_length, has_raw_ip, keyword_hits, suspicious_tokens]
            from model_generator import URL_IP_PATTERN
            has_raw_ip = 1.0 if URL_IP_PATTERN.search(lowered) else 0.0
            kw_hits = float(sum(kw in lowered for kw in HEAVY_KEYWORDS))
            susp_tokens = float(sum(token in lowered for token in ("@", "//", "-secure", "account", "oauth", "reset")))
            vec = [float(len(url)), has_raw_ip, kw_hits, susp_tokens]
            feature_vector = np.asarray([vec], dtype=np.float32)
        else:
            feature_vector = np.asarray([features[:expected_features]], dtype=np.float32)

        model_probability = float(self.model.predict_proba(feature_vector)[0][1])
        heuristic = self._heuristic_scores(lowered)

        # Inspect SSL Certificate and domain age heuristics
        try:
            from security.ssl_validator import inspect_url_ssl
            ssl_info = inspect_url_ssl(url, timeout=1.5)
        except Exception:
            ssl_info = {"has_ssl": False, "is_valid": True, "signals": [], "domain_age_heuristic": "Normal"}

        all_signals = list(heuristic["signals"])
        if ssl_info.get("signals"):
            for s in ssl_info["signals"]:
                if s not in all_signals:
                    all_signals.append(s)

        ssl_risk = 0.0
        if ssl_info.get("has_ssl") and not ssl_info.get("is_valid"):
            ssl_risk += 0.40
        elif not ssl_info.get("has_ssl") and any(kw in lowered for kw in ("login", "signin", "bank", "account", "secure", "auth", "verify")):
            ssl_risk += 0.30

        if "High Risk" in ssl_info.get("domain_age_heuristic", ""):
            ssl_risk += 0.20

        final_risk = round(min(1.0, (model_probability * 0.5) + (heuristic["heuristic_risk_score"] * 0.3) + (ssl_risk * 0.2)), 4)
        classification = "Phishing" if final_risk >= 0.5 else "Safe"

        return {
            "url": url,
            "classification": classification,
            "safety_classification": classification,
            "is_safe": classification == "Safe",
            "model_probability": round(model_probability, 4),
            "heuristic_risk_score": heuristic["heuristic_risk_score"],
            "final_risk_score": final_risk,
            "ssl_info": ssl_info,
            "feature_risk_scores": heuristic["feature_risk_scores"],
            "signals": all_signals,
            "feature_order": self._artifact.get("feature_order", []),
        }

    def _heuristic_scores(self, url: str) -> Dict[str, Any]:
        domain = _extract_domain(url)
        raw_ip = 1.0 if re.search(r"(?:(?:https?://)?)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)", url) else 0.0
        long_url = 1.0 if len(url) > 75 else 0.0
        is_short = 1.0 if any(short in domain for short in URL_SHORTENERS) else 0.0
        is_puny = 1.0 if "xn--" in domain else 0.0
        susp_tld = 1.0 if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0.0
        
        entropy = calculate_entropy(domain) if domain else 0.0
        high_entropy = 1.0 if entropy > 3.6 else (0.5 if entropy > 3.2 else 0.0)

        subdomain_count = max(0, domain.count(".") - 1) if domain else 0
        deep_subdomain = 1.0 if subdomain_count >= 3 else (0.5 if subdomain_count == 2 else 0.0)

        keyword_hits = [keyword for keyword in HEAVY_KEYWORDS if keyword in url]
        keyword_score = min(1.0, len(keyword_hits) / 3.0)
        suspicious_tokens = [token for token in ("@", "//", "-secure", "account", "oauth", "reset", "billing", "recover") if token in url]
        token_score = min(1.0, len(suspicious_tokens) / 3.0)

        heuristic_risk = round(min(1.0, (
            (raw_ip * 0.25) +
            (is_short * 0.15) +
            (is_puny * 0.15) +
            (susp_tld * 0.15) +
            (high_entropy * 0.1) +
            (deep_subdomain * 0.1) +
            (long_url * 0.05) +
            (keyword_score * 0.15) +
            (token_score * 0.1)
        )), 4)

        return {
            "heuristic_risk_score": heuristic_risk,
            "feature_risk_scores": {
                "raw_ip_in_url": raw_ip,
                "is_url_shortener": is_short,
                "is_punycode": is_puny,
                "suspicious_tld": susp_tld,
                "domain_entropy_score": high_entropy,
                "deep_subdomain": deep_subdomain,
                "long_url": long_url,
                "keyword_density": round(keyword_score, 4),
                "suspicious_tokens": round(token_score, 4),
            },
            "signals": {
                "domain": domain,
                "domain_entropy": round(entropy, 3),
                "matched_keywords": keyword_hits,
                "matched_tokens": suspicious_tokens,
                "matched_tld": [tld for tld in SUSPICIOUS_TLDS if domain.endswith(tld)],
            },
        }


class ThreatCorrelator:
    def __init__(self, alerts: AlertStore, metrics: MetricsStore) -> None:
        self.alerts = alerts
        self.metrics = metrics

    def summarize(self) -> Dict[str, Any]:
        current_alerts = self.alerts.list()
        metrics_snapshot = self.metrics.snapshot()
        category_breakdown = Counter(alert["category"] for alert in current_alerts)
        severity_breakdown = Counter(alert["severity"] for alert in current_alerts)

        score = 0.08
        if metrics_snapshot["current_packet_velocity"] >= 100:
            score += 0.35
        elif metrics_snapshot["current_packet_velocity"] >= 40:
            score += 0.2

        if metrics_snapshot["port_monitoring_active"]:
            score += 0.12
        if metrics_snapshot["file_change_rate"] >= 3.0:
            score += 0.22
        elif metrics_snapshot["file_change_rate"] >= 1.5:
            score += 0.12

        score += min(0.2, severity_breakdown.get("critical", 0) * 0.08)
        score += min(0.1, severity_breakdown.get("high", 0) * 0.04)
        score = round(min(1.0, score), 4)

        if score >= 0.8:
            threat_level = "Critical"
            recommended_action = "Isolate the host and investigate active compromise indicators immediately."
        elif score >= 0.6:
            threat_level = "High"
            recommended_action = "Triage the latest alerts and block suspicious endpoints or file activity."
        elif score >= 0.35:
            threat_level = "Elevated"
            recommended_action = "Monitor the host closely and inspect recent network and filesystem events."
        else:
            threat_level = "Low"
            recommended_action = "Continue passive monitoring; no immediate response required."

        top_signals: List[str] = []
        if category_breakdown.get("DDoS Attack"):
            top_signals.append("Traffic burst anomaly detected")
        if category_breakdown.get("Port Scan"):
            top_signals.append("Port scan pattern detected")
        if category_breakdown.get("Ransomware Alert"):
            top_signals.append("Ransomware-like filesystem activity detected")
        if category_breakdown.get("Isolation Event"):
            top_signals.append("Containment action was triggered")
        if not top_signals:
            top_signals.append("No active alert clusters detected")

        confidence = round(min(0.98, 0.45 + (score * 0.5) + (0.03 * len(top_signals))), 4)

        return ThreatSummary(
            risk_score=score,
            threat_level=threat_level,
            recommended_action=recommended_action,
            confidence=confidence,
            top_signals=top_signals,
            category_breakdown=dict(category_breakdown),
            severity_breakdown=dict(severity_breakdown),
        ).model_dump()


class FirewallInsightEngine:
    def __init__(self, alerts: AlertStore, metrics: MetricsStore) -> None:
        self.alerts = alerts
        self.metrics = metrics

    def summarize(self) -> Dict[str, Any]:
        with self.metrics._lock:
            top_ports = sorted(
                (
                    {
                        "port": port,
                        "protocol": info.get("protocol", "UNKNOWN"),
                        "count": int(info.get("count", 0)),
                        "last_seen": info.get("last_seen"),
                    }
                    for port, info in self.metrics.port_activity.items()
                ),
                key=lambda item: item["count"],
                reverse=True,
            )[:10]

            protocol_distribution = dict(sorted(self.metrics.protocol_breakdown.items(), key=lambda item: item[1], reverse=True))
            top_sources = sorted(
                (
                    {
                        "source_ip": src_ip,
                        "direction": info.get("direction", "unknown"),
                        "count": int(info.get("count", 0)),
                        "last_protocol": info.get("last_protocol", "UNKNOWN"),
                    }
                    for src_ip, info in self.metrics.source_ip_activity.items()
                ),
                key=lambda item: item["count"],
                reverse=True,
            )[:10]

        recent_scan_alerts = [
            {
                "id": alert["id"],
                "timestamp": alert["timestamp"],
                "source_ip": alert["meta"].get("source_ip"),
                "protocol": alert["meta"].get("protocol", "UNKNOWN"),
                "ports": alert["meta"].get("unique_ports", []),
            }
            for alert in self.alerts.list()
            if alert["category"] == "Port Scan"
        ][-10:]

        return {
            "top_ports": top_ports,
            "protocol_distribution": protocol_distribution,
            "top_sources": top_sources,
            "recent_scan_alerts": recent_scan_alerts,
            "alert_count": len(self.alerts.list()),
        }
