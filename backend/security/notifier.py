"""Multi-Channel Notification Dispatcher for Volcano AI Firewall.
Dispatches critical security alerts to Slack, Discord, Telegram, and SMTP email.
Includes severity filtering, per-channel cooldown throttling, and test endpoints.
"""

from __future__ import annotations

import json
import logging
import smtplib
import threading
import time
import urllib.error
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, Optional, Tuple

from config import get_settings

logger = logging.getLogger("volcano.notifier")

SEVERITY_LEVELS: Dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "warning": 2,
    "low": 1,
    "info": 0,
}


class NotificationDispatcher:
    """Handles alert notifications across multiple communication channels."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # Cooldown map: (channel, key) -> timestamp
        self._cooldowns: Dict[Tuple[str, str], float] = {}

    def is_severity_eligible(self, alert_severity: str) -> bool:
        """Check if an alert's severity meets the configured minimum threshold."""
        cfg = get_settings()
        min_level = SEVERITY_LEVELS.get(cfg.notification_min_severity.lower(), 3)
        current_level = SEVERITY_LEVELS.get(alert_severity.lower(), 0)
        return current_level >= min_level

    def _is_cooling_down(self, channel: str, key: str, cooldown_seconds: float) -> bool:
        with self._lock:
            now = time.monotonic()
            last_sent = self._cooldowns.get((channel, key), 0.0)
            if now - last_sent < cooldown_seconds:
                return True
            self._cooldowns[(channel, key)] = now
            return False

    def dispatch_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch alert to all configured channels if severity threshold is met."""
        severity = str(alert.get("severity", "medium")).lower()
        if not self.is_severity_eligible(severity):
            return {"dispatched": False, "reason": "severity_below_threshold"}

        cfg = get_settings()
        cooldown_sec = cfg.notification_cooldown
        cat = alert.get("category", "Security Alert")
        src_ip = (alert.get("meta") or {}).get("source_ip", "unknown")
        cooldown_key = f"{cat}:{src_ip}"

        results: Dict[str, Any] = {}

        # 1. Slack
        if cfg.slack_webhook_url and cfg.slack_webhook_url.strip():
            if not self._is_cooling_down("slack", cooldown_key, cooldown_sec):
                threading.Thread(
                    target=self._dispatch_slack_worker,
                    args=(cfg.slack_webhook_url, alert),
                    daemon=True,
                ).start()
                results["slack"] = "dispatched"
            else:
                results["slack"] = "throttled"

        # 2. Discord
        if cfg.discord_webhook_url and cfg.discord_webhook_url.strip():
            if not self._is_cooling_down("discord", cooldown_key, cooldown_sec):
                threading.Thread(
                    target=self._dispatch_discord_worker,
                    args=(cfg.discord_webhook_url, alert),
                    daemon=True,
                ).start()
                results["discord"] = "dispatched"
            else:
                results["discord"] = "throttled"

        # 3. Telegram
        if cfg.telegram_bot_token and cfg.telegram_chat_id:
            if not self._is_cooling_down("telegram", cooldown_key, cooldown_sec):
                threading.Thread(
                    target=self._dispatch_telegram_worker,
                    args=(cfg.telegram_bot_token, cfg.telegram_chat_id, alert),
                    daemon=True,
                ).start()
                results["telegram"] = "dispatched"
            else:
                results["telegram"] = "throttled"

        # 4. SMTP Email
        if cfg.smtp_host and cfg.smtp_recipient:
            if not self._is_cooling_down("email", cooldown_key, cooldown_sec):
                threading.Thread(
                    target=self._dispatch_email_worker,
                    args=(cfg, alert),
                    daemon=True,
                ).start()
                results["email"] = "dispatched"
            else:
                results["email"] = "throttled"

        return {"dispatched": True, "channels": results}

    def _dispatch_slack_worker(self, url: str, alert: Dict[str, Any]) -> None:
        self.send_slack(url, alert)

    def _dispatch_discord_worker(self, url: str, alert: Dict[str, Any]) -> None:
        self.send_discord(url, alert)

    def _dispatch_telegram_worker(self, token: str, chat_id: str, alert: Dict[str, Any]) -> None:
        self.send_telegram(token, chat_id, alert)

    def _dispatch_email_worker(self, cfg: Any, alert: Dict[str, Any]) -> None:
        self.send_email(cfg, alert)

    # ──────────────────────────────────────────────────────────────────────────
    # Individual Channel Senders
    # ──────────────────────────────────────────────────────────────────────────

    def send_slack(self, webhook_url: str, alert: Dict[str, Any]) -> Tuple[bool, str]:
        """Post formatted notification to Slack incoming webhook."""
        if not webhook_url or not webhook_url.startswith("http"):
            return False, "Invalid or missing Slack webhook URL."

        sev = str(alert.get("severity", "HIGH")).upper()
        cat = alert.get("category", "Firewall Alert")
        msg = alert.get("message", "No description")
        meta = alert.get("meta") or {}
        src_ip = meta.get("source_ip", "N/A")

        payload = {
            "text": f"🚨 *[Volcano AI Firewall]* *{sev} Alert:* {cat}",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"🚨 Volcano Alert: {cat}"},
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Severity:*\n`{sev}`"},
                        {"type": "mrkdwn", "text": f"*Source IP:*\n`{src_ip}`"},
                    ],
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Details:*\n{msg}"},
                },
            ],
        }

        try:
            req = urllib.request.Request(
                webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "Volcano-Firewall/2.0"},
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                if resp.status == 200:
                    return True, "Slack notification delivered."
                return False, f"Slack returned status {resp.status}."
        except Exception as exc:
            logger.warning("Slack notification failed: %s", exc)
            return False, str(exc)

    def send_discord(self, webhook_url: str, alert: Dict[str, Any]) -> Tuple[bool, str]:
        """Post embedded alert message to Discord webhook."""
        if not webhook_url or not webhook_url.startswith("http"):
            return False, "Invalid or missing Discord webhook URL."

        sev = str(alert.get("severity", "high")).lower()
        color = 15158332 if sev == "critical" else (15105570 if sev == "high" else 3447003)
        cat = alert.get("category", "Firewall Alert")
        msg = alert.get("message", "No description")
        meta = alert.get("meta") or {}

        payload = {
            "content": f"🚨 **[Volcano AI Firewall Alert]** - {sev.upper()}",
            "embeds": [
                {
                    "title": f"{cat}",
                    "description": msg,
                    "color": color,
                    "fields": [
                        {"name": "Severity", "value": sev.upper(), "inline": True},
                        {"name": "Source IP", "value": str(meta.get("source_ip", "N/A")), "inline": True},
                        {"name": "Rule", "value": str(alert.get("rule_name") or meta.get("rule_name", "N/A")), "inline": True},
                    ],
                    "footer": {"text": "Volcano AI Firewall Live Security Engine"},
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
            ],
        }

        try:
            req = urllib.request.Request(
                webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "Volcano-Firewall/2.0"},
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                if resp.status in (200, 204):
                    return True, "Discord notification delivered."
                return False, f"Discord returned status {resp.status}."
        except Exception as exc:
            logger.warning("Discord notification failed: %s", exc)
            return False, str(exc)

    def send_telegram(self, bot_token: str, chat_id: str, alert: Dict[str, Any]) -> Tuple[bool, str]:
        """Post alert message to Telegram bot chat."""
        if not bot_token or not chat_id:
            return False, "Telegram bot token or chat ID is missing."

        sev = str(alert.get("severity", "HIGH")).upper()
        cat = alert.get("category", "Firewall Alert")
        msg = alert.get("message", "")
        meta = alert.get("meta") or {}
        src_ip = meta.get("source_ip", "N/A")

        text = (
            f"🚨 *[Volcano AI Firewall]*\n"
            f"*Severity:* `{sev}`\n"
            f"*Category:* *{cat}*\n"
            f"*Source IP:* `{src_ip}`\n"
            f"*Details:* {msg}"
        )

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}

        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=6.0) as resp:
                if resp.status == 200:
                    return True, "Telegram notification delivered."
                return False, f"Telegram API returned status {resp.status}."
        except Exception as exc:
            logger.warning("Telegram notification failed: %s", exc)
            return False, str(exc)

    def send_email(self, cfg: Any, alert: Dict[str, Any]) -> Tuple[bool, str]:
        """Send formatted alert email over SMTP."""
        if not cfg.smtp_host or not cfg.smtp_recipient:
            return False, "SMTP host or recipient address is not configured."

        sev = str(alert.get("severity", "HIGH")).upper()
        cat = alert.get("category", "Firewall Alert")
        msg = alert.get("message", "")
        meta = alert.get("meta") or {}

        subject = f"[Volcano Firewall] {sev}: {cat}"
        sender = cfg.smtp_user or "volcano-alerts@localhost"
        recipient = cfg.smtp_recipient

        email_text = (
            f"Volcano AI Firewall Alert Notification\n"
            f"======================================\n\n"
            f"Severity: {sev}\n"
            f"Category: {cat}\n"
            f"Source IP: {meta.get('source_ip', 'N/A')}\n"
            f"Timestamp: {time.ctime()}\n\n"
            f"Message:\n{msg}\n\n"
            f"Metadata:\n{json.dumps(meta, indent=2)}\n"
        )

        message = MIMEMultipart()
        message["From"] = sender
        message["To"] = recipient
        message["Subject"] = subject
        message.attach(MIMEText(email_text, "plain"))

        try:
            port = cfg.smtp_port or 587
            if port == 465:
                server = smtplib.SMTP_SSL(cfg.smtp_host, port, timeout=10)
            else:
                server = smtplib.SMTP(cfg.smtp_host, port, timeout=10)
                server.starttls()

            if cfg.smtp_user and cfg.smtp_password:
                server.login(cfg.smtp_user, cfg.smtp_password)

            server.sendmail(sender, [recipient], message.as_string())
            server.quit()
            return True, f"Email delivered to {recipient} via {cfg.smtp_host}."
        except Exception as exc:
            logger.warning("SMTP email delivery failed: %s", exc)
            return False, str(exc)

    # ──────────────────────────────────────────────────────────────────────────
    # Diagnostic / Test Endpoints
    # ──────────────────────────────────────────────────────────────────────────

    def test_channels(self, target_channel: str = "all", custom_text: Optional[str] = None) -> Dict[str, Any]:
        """Test configured notification channels with a diagnostic ping."""
        cfg = get_settings()
        sample_alert = {
            "severity": "high",
            "category": "Test Notification",
            "message": custom_text or "This is a diagnostic connectivity test from Volcano AI Firewall.",
            "meta": {"source_ip": "127.0.0.1", "test": True},
            "timestamp": time.time(),
        }

        results: Dict[str, Any] = {}
        target = target_channel.lower().strip()

        if target in ("slack", "all"):
            if cfg.slack_webhook_url:
                ok, msg = self.send_slack(cfg.slack_webhook_url, sample_alert)
                results["slack"] = {"status": "success" if ok else "failed", "detail": msg}
            else:
                results["slack"] = {"status": "unconfigured", "detail": "slack_webhook_url is empty"}

        if target in ("discord", "all"):
            if cfg.discord_webhook_url:
                ok, msg = self.send_discord(cfg.discord_webhook_url, sample_alert)
                results["discord"] = {"status": "success" if ok else "failed", "detail": msg}
            else:
                results["discord"] = {"status": "unconfigured", "detail": "discord_webhook_url is empty"}

        if target in ("telegram", "all"):
            if cfg.telegram_bot_token and cfg.telegram_chat_id:
                ok, msg = self.send_telegram(cfg.telegram_bot_token, cfg.telegram_chat_id, sample_alert)
                results["telegram"] = {"status": "success" if ok else "failed", "detail": msg}
            else:
                results["telegram"] = {"status": "unconfigured", "detail": "telegram_bot_token or telegram_chat_id missing"}

        if target in ("email", "smtp", "all"):
            if cfg.smtp_host and cfg.smtp_recipient:
                ok, msg = self.send_email(cfg, sample_alert)
                results["email"] = {"status": "success" if ok else "failed", "detail": msg}
            else:
                results["email"] = {"status": "unconfigured", "detail": "smtp_host or smtp_recipient missing"}

        return {"channel_requested": target, "results": results}
