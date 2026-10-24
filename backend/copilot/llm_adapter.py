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
            "You are Volcano Security Copilot, an AI assistant for a local firewall Security Operations Center (SOC).\n"
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
