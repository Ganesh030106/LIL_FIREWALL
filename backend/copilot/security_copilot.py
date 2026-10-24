from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(slots=True)
class QueryIntent:
    intent_type: str
    entity: Optional[str]
    action: str
    confidence: float


class SecurityCopilot:
    def __init__(self) -> None:
        self.intent_patterns = {
            "explain": r"(?:why|explain|what).*(?:block|allow|detect|flag|alert|quarantine)",
            "list": r"(?:show|list|get|display).*(?:alert|threat|device|rule|user)",
            "search": r"(?:find|search|show).*(?:ip|device|user|threat)",
            "action": r"(?:block|allow|quarantine|isolate|kill).*(?:ip|device|port|session)",
            "report": r"(?:generate|create|show).*(?:report|summary|timeline)",
            "stats": r"(?:what|show|get).*(?:threat|risk|incident|attack).*(?:today|yesterday|this week)",
        }

    def parse_query(self, query: str) -> QueryIntent:
        query_lower = query.lower().strip()

        for intent_type, pattern in self.intent_patterns.items():
            if re.search(pattern, query_lower):
                entity = self._extract_entity(query_lower)
                action = self._extract_action(query_lower)
                return QueryIntent(
                    intent_type=intent_type,
                    entity=entity,
                    action=action,
                    confidence=0.85,
                )

        return QueryIntent(intent_type="unknown", entity=None, action="help", confidence=0.5)

    def _extract_entity(self, query: str) -> Optional[str]:
        ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        domain_pattern = r"[\w\-]+\.[\w\-]+"
        mac_pattern = r"(?:[0-9A-Fa-f]{2}:){5}(?:[0-9A-Fa-f]{2})"

        if match := re.search(ip_pattern, query):
            return match.group()
        if match := re.search(mac_pattern, query):
            return match.group()
        if match := re.search(domain_pattern, query):
            return match.group()

        return None

    def _extract_action(self, query: str) -> str:
        actions = ["block", "allow", "quarantine", "isolate", "monitor", "report"]
        for action in actions:
            if action in query:
                return action
        return "info"

    def generate_response(self, intent: QueryIntent, data: Dict[str, Any]) -> str:
        if intent.intent_type == "explain":
            return self._explain_decision(data)
        elif intent.intent_type == "list":
            return self._list_items(data)
        elif intent.intent_type == "search":
            return self._search_result(data)
        elif intent.intent_type == "report":
            return self._generate_report(data)
        elif intent.intent_type == "stats":
            return self._show_stats(data)
        else:
            return "I didn't understand that query. Try asking about alerts, threats, devices, or rules."

    def _explain_decision(self, data: Dict[str, Any]) -> str:
        if "reason" in data:
            confidence = data.get("confidence", 0.0)
            return f"**Decision Explanation**\n\nReason: {data['reason']}\nConfidence: {confidence:.2%}\nTriggered Indicators: {', '.join(data.get('indicators', []))}"
        return "No explanation available for this decision."

    def _list_items(self, data: Dict[str, Any]) -> str:
        items = data.get("items", [])
        item_type = data.get("type", "items")
        if not items:
            return f"No {item_type} found."
        lines = [f"**{item_type.title()}** ({len(items)} total)\n"]
        for item in items[:10]:
            lines.append(f"- {item}")
        if len(items) > 10:
            lines.append(f"... and {len(items) - 10} more")
        return "\n".join(lines)

    def _search_result(self, data: Dict[str, Any]) -> str:
        result = data.get("result")
        if not result:
            return f"No results found for '{data.get('query')}'."
        return f"**Search Result**\n\n{result}"

    def _generate_report(self, data: Dict[str, Any]) -> str:
        title = data.get("title", "Security Report")
        summary = data.get("summary", "")
        details = data.get("details", {})
        lines = [f"# {title}\n", f"**Summary**: {summary}\n"]
        for key, value in details.items():
            lines.append(f"- **{key}**: {value}")
        return "\n".join(lines)

    def _show_stats(self, data: Dict[str, Any]) -> str:
        stats = data.get("stats", {})
        lines = ["**Threat Statistics**\n"]
        for key, value in stats.items():
            lines.append(f"- {key}: {value}")
        return "\n".join(lines)
