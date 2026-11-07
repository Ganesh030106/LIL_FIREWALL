"""Grounded LLM Copilot Adapter for Volcano AI Firewall.
Provides contextual, telemetry-grounded AI security assistance using external LLMs
(OpenAI-compatible endpoints, Anthropic, or generic local models)
with seamless zero-crash fallback to the local rule-based intent engine.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from config import get_settings
from copilot.security_copilot import SecurityCopilot, QueryIntent

logger = logging.getLogger("volcano.copilot.llm")


class GroundedCopilot:
    """Grounded security assistant augmenting LLM prompts with real-time firewall state."""

    def __init__(
        self,
        fallback_copilot: Optional[SecurityCopilot] = None,
        threat_correlator: Optional[Any] = None,
        alerts: Optional[Any] = None,
        metrics: Optional[Any] = None,
        rule_engine: Optional[Any] = None,
        response_engine: Optional[Any] = None,
    ) -> None:
        self.fallback_copilot = fallback_copilot or SecurityCopilot()
        self.threat_correlator = threat_correlator
        self.alerts = alerts
        self.metrics = metrics
        self.rule_engine = rule_engine
        self.response_engine = response_engine
        self._lock = threading.RLock()

    def set_dependencies(
        self,
        threat_correlator: Optional[Any] = None,
        alerts: Optional[Any] = None,
        metrics: Optional[Any] = None,
        rule_engine: Optional[Any] = None,
        response_engine: Optional[Any] = None,
    ) -> None:
        with self._lock:
            if threat_correlator:
                self.threat_correlator = threat_correlator
            if alerts:
                self.alerts = alerts
            if metrics:
                self.metrics = metrics
            if rule_engine:
                self.rule_engine = rule_engine
            if response_engine:
                self.response_engine = response_engine

    def _build_telemetry_context(self) -> str:
        """Serialize current firewall telemetry for prompt grounding."""
        context_parts = []

        # 1. Threat summary
        if self.threat_correlator:
            try:
                summary = self.threat_correlator.summarize()
                context_parts.append(
                    f"Overall Threat Level: {summary.get('threat_level')} "
                    f"(Risk Score: {summary.get('risk_score')}, Confidence: {summary.get('confidence')})\n"
                    f"Top Threat Signals: {', '.join(summary.get('top_signals', []))}"
                )
            except Exception:
                pass

        # 2. Recent alerts
        if self.alerts:
            try:
                recent = self.alerts.list()[-8:]
                alert_lines = []
                for a in recent:
                    src = (a.get("meta") or {}).get("source_ip", "N/A")
                    alert_lines.append(f"- [{a.get('severity', 'MED').upper()}] {a.get('category')}: {a.get('message')} (IP: {src})")
                context_parts.append(f"Recent Alerts ({len(self.alerts.list())} total):\n" + ("\n".join(alert_lines) if alert_lines else "None"))
            except Exception:
                pass

        # 3. Active firewall rules
        if self.rule_engine:
            try:
                rules = self.rule_engine.list_rules()
                rule_names = [f"#{r.id} {r.name} ({r.action.value.upper()})" for r in rules[:8]]
                context_parts.append(f"Active Rules ({len(rules)} total): {', '.join(rule_names)}")
            except Exception:
                pass

        # 4. Active autonomous blocks
        if self.response_engine:
            try:
                active_blocks = self.response_engine.list_active_responses()
                block_ips = [f"{b.target_ip} ({int(b.duration)}s)" for b in active_blocks[:6]]
                context_parts.append(f"Active IP Blocks ({len(active_blocks)} active): {', '.join(block_ips) if block_ips else 'None'}")
            except Exception:
                pass

        # 5. Network activity
        if self.metrics:
            try:
                snap = self.metrics.snapshot()
                context_parts.append(
                    f"Traffic Velocity: {snap.get('current_packet_velocity', 0)} pps, "
                    f"Protocol Breakdown: {snap.get('protocol_breakdown', {})}"
                )
            except Exception:
                pass

        return "\n\n".join(context_parts)

    def query(self, user_query: str) -> Dict[str, Any]:
        """Process user security query using grounded LLM or rule-based fallback."""
        clean_q = user_query.strip()
        if not clean_q:
            return {"answer": "Please provide a question or security command.", "confidence": 1.0, "grounded": False}

        cfg = get_settings()
        api_key = (cfg.llm_api_key or os.getenv("VOLCANO_LLM_API_KEY") or os.getenv("OPENAI_API_KEY") or "").strip()

        # If no LLM key configured or provider is mock, use deterministic rule fallback
        if not api_key or cfg.llm_provider.lower() == "mock":
            return self._query_fallback(clean_q)

        telemetry_context = self._build_telemetry_context()

        system_prompt = (
            "You are the Contextual Firewall Security Copilot, an AI assistant for a local Security Operations Center (SOC).\n"
            "You have READ-ONLY access to real-time firewall telemetry.\n"
            "You cannot execute arbitrary commands or disable defenses without human authorization.\n"
            "Answer the operator's question concisely, referencing specific IP addresses, alerts, or telemetry from the context below.\n\n"
            f"=== LIVE FIREWALL TELEMETRY ===\n{telemetry_context}\n================================"
        )

        api_url = (cfg.llm_api_base or "https://api.openai.com/v1").rstrip("/") + "/chat/completions"
        payload = {
            "model": cfg.llm_model or "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": clean_q},
            ],
            "temperature": 0.2,
            "max_tokens": 450,
        }

        req = urllib.request.Request(
            api_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "Volcano-Copilot/2.0",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                choice = data.get("choices", [{}])[0]
                answer = choice.get("message", {}).get("content", "").strip()
                if answer:
                    return {
                        "answer": answer,
                        "confidence": 0.95,
                        "grounded": True,
                        "provider": cfg.llm_provider,
                        "model": cfg.llm_model,
                    }
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
            logger.warning("LLM provider query failed (%s); falling back to rule engine.", exc)
            fallback = self._query_fallback(clean_q)
            fallback["note"] = f"LLM provider unreachable ({exc}); answered via local rule parser."
            return fallback
        except Exception as exc:
            logger.warning("Unexpected error during LLM query (%s); using fallback.", exc)
            fallback = self._query_fallback(clean_q)
            fallback["note"] = "Local fallback used due to an internal query error."
            return fallback

        return self._query_fallback(clean_q)

    def _query_fallback(self, query: str) -> Dict[str, Any]:
        """Local deterministic response generation using SecurityCopilot intent regex."""
        q_lower = query.lower()

        # Advanced SOC Question Handlers
        if "top" in q_lower and ("threat" in q_lower or "five" in q_lower or "alert" in q_lower):
            raw_alerts = self.alerts.list() if self.alerts else []
            top_alerts = sorted(raw_alerts, key=lambda a: (0 if a.get("severity") == "critical" else (1 if a.get("severity") == "high" else 2)))[:5]
            if top_alerts:
                lines = [f"{i+1}. [{a.get('severity', 'MED').upper()}] {a.get('category')}: {a.get('message')} (Source: {(a.get('meta') or {}).get('source_ip', 'Internal')})" for i, a in enumerate(top_alerts)]
                return {
                    "answer": f"Top Threat Activity Identified:\n" + "\n".join(lines) + "\n\nSuggested Action: Inspect incidents in the Incident Workspace and execute targeted containment playbooks.",
                    "confidence": 0.96,
                    "grounded": True,
                    "provider": "local_threat_engine",
                }
            else:
                return {
                    "answer": "No active high-priority threats recorded. Perimeter status is nominal.",
                    "confidence": 0.95,
                    "grounded": True,
                    "provider": "local_threat_engine",
                }
        elif "incident" in q_lower:
            from security.correlation_engine import correlation_engine
            incidents = correlation_engine.correlate_alerts(self.alerts.list() if self.alerts else [])
            if incidents:
                inc_summaries = [f"• {inc['incident_id'] if 'incident_id' in inc else 'INC-AUTO'}: {inc['title']} [{inc['severity'].upper()}] - Kill Chain Stage: {inc.get('kill_chain_stage', 'Initial Access')}" for inc in incidents[:4]]
                return {
                    "answer": f"Current Active Correlated Security Incidents ({len(incidents)} total):\n" + "\n".join(inc_summaries) + "\n\nAll incidents are tracked in the Incidents Tab with full kill-chain progression.",
                    "confidence": 0.94,
                    "grounded": True,
                    "provider": "local_incident_engine",
                }
            else:
                return {
                    "answer": "No active incidents currently clustered. All incoming traffic is within nominal parameters.",
                    "confidence": 0.92,
                    "grounded": True,
                    "provider": "local_incident_engine",
                }
        elif "predict" in q_lower or "forecast" in q_lower or "early warning" in q_lower:
            from security.predictive_engine import predictive_engine
            snap = self.metrics.snapshot() if self.metrics else {}
            preds = predictive_engine.evaluate_predictions(telemetry=snap, recent_alerts=self.alerts.list() if self.alerts else [])
            if preds:
                pred_lines = [f"• [{p['severity'].upper()}] {p['threat_type']} (Confidence: {int(p['confidence']*100)}%, Horizon: {p['time_horizon']}): {p['recommended_preventative_action']}" for p in preds[:3]]
                return {
                    "answer": f"Predictive Early-Warning Forecast:\n" + "\n".join(pred_lines),
                    "confidence": 0.93,
                    "grounded": True,
                    "provider": "local_predictive_engine",
                }
            else:
                return {
                    "answer": "No early-warning trajectory anomalies detected. Velocity derivatives are steady.",
                    "confidence": 0.90,
                    "grounded": True,
                    "provider": "local_predictive_engine",
                }
        elif "why" in q_lower and "block" in q_lower:
            active_blocks = self.response_engine.list_active_responses() if self.response_engine else []
            if active_blocks:
                b = active_blocks[0]
                return {
                    "answer": f"Host {b.target_ip} was contained for {int(b.duration)}s due to: '{b.reason}'. Enforced via autonomous kernel DROP rule with auto-unblock TTL.",
                    "confidence": 0.95,
                    "grounded": True,
                    "provider": "local_response_engine",
                }
            else:
                return {
                    "answer": "No hosts are currently contained in the autonomous quarantine table.",
                    "confidence": 0.92,
                    "grounded": True,
                    "provider": "local_response_engine",
                }
        elif "device" in q_lower and ("risk" in q_lower or "high" in q_lower):
            return {
                "answer": "Device Risk Analytics:\nDiscovered hosts are monitored for heuristic risk scoring based on abnormal port access, protocol diversity, and authentication failures. Inspect the Network Tab under 'Device Profiles' to view MAC/IP mappings.",
                "confidence": 0.90,
                "grounded": True,
                "provider": "local_device_engine",
            }
        elif "mitre" in q_lower or "attack" in q_lower:
            from security.mitre_mapper import mitre_mapper
            summary = mitre_mapper.summarize_matrix(self.alerts.list() if self.alerts else [])
            active_techs = [f"{t['id']} ({t['name']})" for t in summary['techniques'] if t['active']]
            return {
                "answer": f"MITRE ATT&CK Matrix Analysis:\n- Active Techniques ({summary['active_techniques']}): {', '.join(active_techs) if active_techs else 'None currently active.'}\n- Enterprise Coverage: {summary['coverage_percentage']}% of monitored tactics active.",
                "confidence": 0.95,
                "grounded": True,
                "provider": "local_mitre_engine",
            }
        elif "posture" in q_lower or "grade" in q_lower:
            from security.posture_engine import posture_engine
            rules_cnt = len(self.rule_engine.list_rules()) if self.rule_engine else 0
            crit_cnt = sum(1 for a in (self.alerts.list() if self.alerts else []) if a.get("severity") == "critical" and a.get("status") != "resolved")
            p = posture_engine.calculate_posture(rules_count=rules_cnt, unhandled_critical_alerts=crit_cnt)
            recs = " ".join(f"\n• {r}" for r in p["recommendations"])
            return {
                "answer": f"Security Posture Index: {p['score']}/100 (Grade {p['grade']} - {p['grade_label']}).\nKey Hardening Recommendations:{recs}",
                "confidence": 0.92,
                "grounded": True,
                "provider": "local_posture_engine",
            }
        elif "recommend" in q_lower or "mitigat" in q_lower:
            crit_alerts = [a for a in (self.alerts.list() if self.alerts else []) if a.get("severity") == "critical" and a.get("status") != "resolved"]
            if crit_alerts:
                src_ips = list(set((a.get("meta") or {}).get("source_ip", "Unknown") for a in crit_alerts[:3]))
                return {
                    "answer": f"Recommended SOC Mitigation Actions:\n1. Isolate hostile source IP(s): {', '.join(src_ips)} using 1-Click Autonomous Block.\n2. Review L7 DPI inspection logs for SQLi/XSS attack vectors.\n3. Verify that canary tripwire honeypots remain untouched.\n4. Deploy targeted DROP rules for exposed administrative ports.",
                    "confidence": 0.90,
                    "grounded": True,
                    "provider": "local_recommendation_engine",
                }
            else:
                return {
                    "answer": "All critical alerts are triaged. Recommend continuing passive telemetry monitoring and keeping threat intelligence feeds updated.",
                    "confidence": 0.90,
                    "grounded": True,
                    "provider": "local_recommendation_engine",
                }

        intent: QueryIntent = self.fallback_copilot.parse_query(query)
        response_data: Dict[str, Any] = {"intent": intent.intent_type, "entity": intent.entity}

        # Provide context data based on intent
        if intent.intent_type == "list":
            if self.alerts and "alert" in query.lower():
                response_data["type"] = "alerts"
                response_data["items"] = [f"[{a.get('severity')}] {a.get('category')}: {a.get('message')}" for a in self.alerts.list()[-5:]]
            elif self.rule_engine and "rule" in query.lower():
                response_data["type"] = "rules"
                response_data["items"] = [f"#{r.id} {r.name} ({r.action.value})" for r in self.rule_engine.list_rules()]
        elif intent.intent_type == "stats" and self.threat_correlator:
            summary = self.threat_correlator.summarize()
            response_data["reason"] = f"Threat Level is {summary.get('threat_level')} with risk score {summary.get('risk_score')}."
            response_data["confidence"] = summary.get("confidence", 0.85)

        answer = self.fallback_copilot.generate_response(intent, response_data)
        return {
            "answer": answer,
            "confidence": intent.confidence,
            "grounded": False,
            "provider": "local_intent_parser",
        }
