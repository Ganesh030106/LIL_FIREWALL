"""Central configuration module for Volcano AI Firewall.
Loads settings from environment variables and backend/settings.json with sane defaults.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


BASE_DIR = Path(__file__).resolve().parent
SETTINGS_JSON_PATH = BASE_DIR / "settings.json"


class FirewallSettings(BaseModel):
    # Detection Thresholds
    port_scan_threshold: int = Field(default=15, description="Number of unique ports touched within window to trigger alert")
    port_scan_window: float = Field(default=10.0, description="Sliding window in seconds for port scan tracking")
    ddos_threshold: int = Field(default=100, description="Packet velocity per second threshold for DDoS alert")
    ddos_window: float = Field(default=1.0, description="Window in seconds for DDoS packet tracking")
    ransomware_rate_threshold: int = Field(default=15, description="File system events count within window to trigger ransomware alert")
    ransomware_window: float = Field(default=5.0, description="Sliding window in seconds for ransomware tracking")

    # Brute Force Detection
    brute_force_threshold: int = Field(default=5, description="Max connection attempts to auth ports before alert")
    brute_force_window: float = Field(default=10.0, description="Sliding window in seconds for brute force tracking")
    brute_force_ports: List[int] = Field(default=[22, 3389, 21, 445], description="Target ports monitored for brute force")

    # DNS Threat Detection
    dns_tunneling_subdomain_length: int = Field(default=45, description="Subdomain character length threshold")
    dns_tunneling_entropy: float = Field(default=3.8, description="Shannon entropy threshold for DNS tunneling")
    dns_query_rate_threshold: int = Field(default=25, description="DNS queries per second from single source threshold")
    dga_entropy_threshold: float = Field(default=3.5, description="Entropy threshold for algorithmic domain generation")

    # C2 Beaconing Detection
    beacon_min_events: int = Field(default=10, description="Minimum connection events required to evaluate beaconing")
    beacon_max_jitter: float = Field(default=0.15, description="Maximum coefficient of variation (jitter) to classify as beaconing")
    beacon_cooldown: float = Field(default=60.0, description="Cooldown in seconds between duplicate beacon alerts for same tuple")

    # Lateral Movement Detection
    lateral_min_hosts: int = Field(default=5, description="Min internal hosts contacted on admin ports to trigger lateral movement alert")
    lateral_window: float = Field(default=300.0, description="Sliding window in seconds for lateral movement tracking")
    lateral_cooldown: float = Field(default=300.0, description="Cooldown in seconds between lateral movement alerts for same source IP")

    # Real Enforcement Backend (nftables / software)
    enforcement_backend: str = Field(default="software", description="Firewall backend: 'software' or 'nftables'")
    enforcement_mode: str = Field(default="dry_run", description="Enforcement execution mode: 'dry_run' or 'live'")
    containment_mode: str = Field(default="live", description="Containment execution mode: 'live' or 'dry_run'")
    containment_dry_run: bool = Field(default=False, description="Run containment actions in dry-run simulation mode")

    # Distributed Rate Limiting & Profile (Phase 3)
    rate_limit_backend: str = Field(default="memory", description="Rate limiter backend: 'memory' or 'redis'")
    redis_url: str = Field(default="redis://localhost:6379/0", description="Redis connection URL")
    profile: str = Field(default="development", description="System operational profile: 'development' or 'production'")
    allow_sqlite_production: bool = Field(default=False, description="Allow SQLite execution in production profile")

    # Safe Response & Allowlist
    allowlist_ips: List[str] = Field(default=["127.0.0.1", "::1", "0.0.0.0"], description="IPs that can never be blocked or quarantined")
    quarantine_default_duration: float = Field(default=3600.0, description="Default quarantine duration in seconds")
    login_failure_auto_block: bool = Field(default=False, description="Automatically quarantine IP on brute force login failures via ResponseEngine")
    killswitch_dry_run: bool = Field(default=False, description="Simulate network isolation without disabling physical interface")
    killswitch_interface: Optional[str] = Field(default=None, description="Network interface name for killswitch")

    # Multi-Channel Notifications
    slack_webhook_url: Optional[str] = Field(default="", description="Slack Incoming Webhook URL")
    discord_webhook_url: Optional[str] = Field(default="", description="Discord Webhook URL")
    telegram_bot_token: Optional[str] = Field(default="", description="Telegram Bot Token")
    telegram_chat_id: Optional[str] = Field(default="", description="Telegram Chat ID")
    smtp_host: Optional[str] = Field(default="", description="SMTP host for email alerts")
    smtp_port: int = Field(default=587, description="SMTP server port")
    smtp_user: Optional[str] = Field(default="", description="SMTP username")
    smtp_password: Optional[str] = Field(default="", description="SMTP password")
    smtp_recipient: Optional[str] = Field(default="", description="Alert notification recipient email")
    notification_min_severity: str = Field(default="high", description="Minimum alert severity for dispatching notifications (high/critical)")
    notification_cooldown: float = Field(default=60.0, description="Cooldown seconds between notifications to avoid spam")

    # Threat Intelligence Feeds
    feed_refresh_interval: int = Field(default=3600, description="Interval in seconds to refresh external IoC feeds")
    feed_urls: List[str] = Field(
        default=[
            "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
            "https://urlhaus.abuse.ch/downloads/csv_recent/",
        ],
        description="Remote threat feed URLs"
    )
    local_blocklist_path: str = Field(default="backend/data/blocklist.txt", description="Path to local IP/domain blocklist file")

    # GeoIP & Analytics
    geoip_database_path: str = Field(default="backend/data/GeoLite2-City.mmdb", description="MaxMind GeoLite2 City MMDB file path")

    # LLM Copilot Adapter
    llm_provider: str = Field(default="mock", description="LLM provider: 'openai', 'generic', 'anthropic', 'mock'")
    llm_api_key: Optional[str] = Field(default="", description="API key for LLM provider")
    llm_api_base: Optional[str] = Field(default="https://api.openai.com/v1", description="API base URL for generic/OpenAI compatible LLMs")
    llm_model: str = Field(default="gpt-4o-mini", description="Model name for LLM queries")

    # Core System & Auth Settings
    jwt_secret_key: str = Field(default="", description="Secret key for signing JWT tokens")
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    jwt_access_token_expire_minutes: int = Field(default=120, description="Token lifetime in minutes")
    watch_directory: str = Field(default="./sandbox", description="Path to watched directory for ransomware honeypot")
    db_path: str = Field(default="backend/volcano.db", description="Database URI or SQLite path")
    allowed_origins: List[str] = Field(default=["*"], description="CORS allowed origins")

    # Database Maintenance & Storage Retention
    db_auto_checkpoint_minutes: int = Field(default=30, description="Interval in minutes for background WAL auto-checkpoint")
    db_alert_retention_days: int = Field(default=30, description="Days to retain security alerts before pruning")
    db_audit_retention_days: int = Field(default=90, description="Days to retain audit logs before pruning")
    db_max_alerts_limit: int = Field(default=50000, description="Max alerts to retain in local database before oldest resolved are pruned")
    db_pool_size: int = Field(default=10, description="PostgreSQL connection pool size")
    db_max_overflow: int = Field(default=20, description="PostgreSQL connection pool max overflow")
    db_pool_pre_ping: bool = Field(default=True, description="PostgreSQL pool pre-ping connection liveness check")
    db_pool_recycle: int = Field(default=180, description="PostgreSQL connection pool recycling interval in seconds")
    db_connect_timeout: int = Field(default=5, description="PostgreSQL connection timeout in seconds")
    metrics_enabled: bool = Field(default=False, description="Expose /metrics time-series endpoint")
    metrics_bearer_token: Optional[str] = Field(default="", description="Optional bearer token for protecting /metrics")
    metrics_sink: str = Field(default="memory", description="Metrics sink backend ('memory' or 'prometheus')")
    search_backend: str = Field(default="sql", description="Alert search indexer backend ('sql' or 'opensearch')")
    opensearch_url: str = Field(default="http://localhost:9200", description="OpenSearch node or cluster URL")
    opensearch_index: str = Field(default="volcano-alerts", description="OpenSearch index name for alerts")
    ws_broker: str = Field(default="memory", description="WebSocket broadcast broker ('memory' or 'redis')")
    ws_channel: str = Field(default="volcano:ws:broadcast", description="Redis Pub/Sub channel for WebSocket broadcasts")


KNOWN_SAMPLE_SECRETS = {
    "volcano-secret-key-change-in-production",
    "change-this-to-a-very-secure-random-key-in-production-32chars",
    "volcano-production-jwt-secret-replace-me",
    "secret",
    "changeme",
    "your-secret-key",
    "default_secret",
}

_settings_lock = threading.RLock()
_current_settings: Optional[FirewallSettings] = None


def load_settings() -> FirewallSettings:
    """Load settings from settings.json or env vars, falling back to defaults."""
    global _current_settings
    with _settings_lock:
        data: Dict[str, Any] = {}

        # 1. Load from settings.json if present
        if SETTINGS_JSON_PATH.exists():
            try:
                with open(SETTINGS_JSON_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception as e:
                print(f"[Config] Error reading settings.json: {e}")

        # 2. Override with env vars where available
        if "VOLCANO_PORT_SCAN_THRESHOLD" in os.environ:
            data["port_scan_threshold"] = int(os.environ["VOLCANO_PORT_SCAN_THRESHOLD"])
        if "VOLCANO_DDOS_THRESHOLD" in os.environ:
            data["ddos_threshold"] = int(os.environ["VOLCANO_DDOS_THRESHOLD"])
        if "VOLCANO_RANSOMWARE_THRESHOLD" in os.environ:
            data["ransomware_rate_threshold"] = int(os.environ["VOLCANO_RANSOMWARE_THRESHOLD"])
        if "VOLCANO_DB_PATH" in os.environ:
            data["db_path"] = os.environ["VOLCANO_DB_PATH"]
        if "VOLCANO_WATCH_DIRECTORY" in os.environ:
            data["watch_directory"] = os.environ["VOLCANO_WATCH_DIRECTORY"]
        if "VOLCANO_ALLOWED_ORIGINS" in os.environ:
            data["allowed_origins"] = [x.strip() for x in os.environ["VOLCANO_ALLOWED_ORIGINS"].split(",") if x.strip()]

        jwt_key_env = os.environ.get("VOLCANO_JWT_SECRET_KEY") or os.environ.get("VOLCANO_JWT_SECRET")
        if jwt_key_env:
            data["jwt_secret_key"] = jwt_key_env.strip()

        if "VOLCANO_LLM_API_KEY" in os.environ:
            data["llm_api_key"] = os.environ["VOLCANO_LLM_API_KEY"]
            if data.get("llm_provider") == "mock":
                data["llm_provider"] = "openai"
        if "VOLCANO_SLACK_WEBHOOK" in os.environ:
            data["slack_webhook_url"] = os.environ["VOLCANO_SLACK_WEBHOOK"]
        if "VOLCANO_DISCORD_WEBHOOK" in os.environ:
            data["discord_webhook_url"] = os.environ["VOLCANO_DISCORD_WEBHOOK"]
        if "VOLCANO_LOGIN_FAILURE_AUTO_BLOCK" in os.environ:
            val = os.environ["VOLCANO_LOGIN_FAILURE_AUTO_BLOCK"].strip().lower()
            data["login_failure_auto_block"] = val in ("true", "1", "yes", "on")
        if "VOLCANO_BEACON_MIN_EVENTS" in os.environ:
            try:
                data["beacon_min_events"] = int(os.environ["VOLCANO_BEACON_MIN_EVENTS"].strip())
            except ValueError:
                pass
        if "VOLCANO_BEACON_MAX_JITTER" in os.environ:
            try:
                data["beacon_max_jitter"] = float(os.environ["VOLCANO_BEACON_MAX_JITTER"].strip())
            except ValueError:
                pass
        if "VOLCANO_LATERAL_MIN_HOSTS" in os.environ:
            try:
                data["lateral_min_hosts"] = int(os.environ["VOLCANO_LATERAL_MIN_HOSTS"].strip())
            except ValueError:
                pass
        if "VOLCANO_LATERAL_WINDOW" in os.environ:
            try:
                data["lateral_window"] = float(os.environ["VOLCANO_LATERAL_WINDOW"].strip())
            except ValueError:
                pass
        if "VOLCANO_ENFORCEMENT_BACKEND" in os.environ:
            data["enforcement_backend"] = os.environ["VOLCANO_ENFORCEMENT_BACKEND"].strip().lower()
        if "VOLCANO_ENFORCEMENT_MODE" in os.environ:
            data["enforcement_mode"] = os.environ["VOLCANO_ENFORCEMENT_MODE"].strip().lower()
        if "VOLCANO_CONTAINMENT_MODE" in os.environ:
            data["containment_mode"] = os.environ["VOLCANO_CONTAINMENT_MODE"].strip().lower()
        if "VOLCANO_CONTAINMENT_DRY_RUN" in os.environ:
            data["containment_dry_run"] = os.environ["VOLCANO_CONTAINMENT_DRY_RUN"].strip().lower() in ("true", "1", "yes")
        if "VOLCANO_DRY_RUN" in os.environ:
            data["containment_dry_run"] = os.environ["VOLCANO_DRY_RUN"].strip().lower() in ("true", "1", "yes")
        if "VOLCANO_RATE_LIMIT_BACKEND" in os.environ:
            data["rate_limit_backend"] = os.environ["VOLCANO_RATE_LIMIT_BACKEND"].strip().lower()
        if "VOLCANO_REDIS_URL" in os.environ:
            data["redis_url"] = os.environ["VOLCANO_REDIS_URL"].strip()
        if "VOLCANO_PROFILE" in os.environ:
            data["profile"] = os.environ["VOLCANO_PROFILE"].strip().lower()
        elif "VOLCANO_ENV" in os.environ:
            data["profile"] = os.environ["VOLCANO_ENV"].strip().lower()
        if "VOLCANO_ALLOW_SQLITE_PRODUCTION" in os.environ:
            data["allow_sqlite_production"] = os.environ["VOLCANO_ALLOW_SQLITE_PRODUCTION"].strip().lower() in ("true", "1", "yes")
        if "VOLCANO_DB_POOL_SIZE" in os.environ:
            data["db_pool_size"] = int(os.environ["VOLCANO_DB_POOL_SIZE"])
        if "VOLCANO_DB_MAX_OVERFLOW" in os.environ:
            data["db_max_overflow"] = int(os.environ["VOLCANO_DB_MAX_OVERFLOW"])
        if "VOLCANO_DB_POOL_PRE_PING" in os.environ:
            data["db_pool_pre_ping"] = os.environ["VOLCANO_DB_POOL_PRE_PING"].strip().lower() in ("true", "1", "yes")
        if "VOLCANO_DB_POOL_RECYCLE" in os.environ:
            data["db_pool_recycle"] = int(os.environ["VOLCANO_DB_POOL_RECYCLE"])
        if "VOLCANO_DB_CONNECT_TIMEOUT" in os.environ:
            data["db_connect_timeout"] = int(os.environ["VOLCANO_DB_CONNECT_TIMEOUT"])
        if "VOLCANO_METRICS_ENABLED" in os.environ:
            data["metrics_enabled"] = os.environ["VOLCANO_METRICS_ENABLED"].strip().lower() in ("true", "1", "yes")
        if "VOLCANO_METRICS_BEARER_TOKEN" in os.environ:
            data["metrics_bearer_token"] = os.environ["VOLCANO_METRICS_BEARER_TOKEN"].strip()
        if "VOLCANO_METRICS_SINK" in os.environ:
            data["metrics_sink"] = os.environ["VOLCANO_METRICS_SINK"].strip().lower()
        if "VOLCANO_SEARCH_BACKEND" in os.environ:
            data["search_backend"] = os.environ["VOLCANO_SEARCH_BACKEND"].strip().lower()
        if "VOLCANO_OPENSEARCH_URL" in os.environ:
            data["opensearch_url"] = os.environ["VOLCANO_OPENSEARCH_URL"].strip()
        if "VOLCANO_OPENSEARCH_INDEX" in os.environ:
            data["opensearch_index"] = os.environ["VOLCANO_OPENSEARCH_INDEX"].strip()
        if "VOLCANO_WS_BROKER" in os.environ:
            data["ws_broker"] = os.environ["VOLCANO_WS_BROKER"].strip().lower()
        if "VOLCANO_WS_CHANNEL" in os.environ:
            data["ws_channel"] = os.environ["VOLCANO_WS_CHANNEL"].strip()

        # Enforce safe startup secret validation
        volcano_env = os.environ.get("VOLCANO_ENV", "development").lower().strip()
        jwt_key = str(data.get("jwt_secret_key") or "").strip()

        if not jwt_key or jwt_key in KNOWN_SAMPLE_SECRETS:
            if volcano_env == "development":
                secret_file = BASE_DIR / ".secret_key"
                cached_key = ""
                if secret_file.exists():
                    try:
                        cached_key = secret_file.read_text(encoding="utf-8").strip()
                    except Exception:
                        cached_key = ""
                if not cached_key:
                    import secrets
                    cached_key = secrets.token_urlsafe(32)
                    try:
                        secret_file.write_text(cached_key, encoding="utf-8")
                        try:
                            os.chmod(secret_file, 0o600)
                        except Exception:
                            pass
                    except Exception as exc:
                        print(f"[Config] Warning: could not persist dev secret key: {exc}")
                data["jwt_secret_key"] = cached_key
                print(
                    "[WARNING] Insecure or missing VOLCANO_JWT_SECRET_KEY in development mode (VOLCANO_ENV=development). "
                    "An auto-generated key was stored in backend/.secret_key with 0600 permissions. DO NOT USE IN PRODUCTION."
                )
            else:
                raise RuntimeError(
                    "FATAL: Insecure or missing VOLCANO_JWT_SECRET_KEY. "
                    "Production deployments refuse to start without a unique, secure secret key. "
                    "Provide a secure key via VOLCANO_JWT_SECRET_KEY or set VOLCANO_ENV=development for local development."
                )

        _current_settings = FirewallSettings(**data)
        return _current_settings


def get_settings() -> FirewallSettings:
    """Return cached settings or initialize them."""
    global _current_settings
    if _current_settings is None:
        return load_settings()
    return _current_settings


def save_settings(new_settings: FirewallSettings | Dict[str, Any]) -> FirewallSettings:
    """Persist settings to settings.json and update runtime cache."""
    global _current_settings
    with _settings_lock:
        if isinstance(new_settings, dict):
            existing = get_settings().model_dump()
            existing.update(new_settings)
            validated = FirewallSettings(**existing)
        else:
            validated = new_settings

        SETTINGS_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(SETTINGS_JSON_PATH, "w", encoding="utf-8") as f:
            json.dump(validated.model_dump(), f, indent=2)

        _current_settings = validated
        return _current_settings
