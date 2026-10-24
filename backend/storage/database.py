from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from config import get_settings

from sqlalchemy import (
    Boolean,
    Column,
    Float,
    Integer,
    MetaData,
    Table,
    Text,
    create_engine,
    event,
    func,
    select,
    text,
)
from sqlalchemy.engine import Engine

from core.rule_engine import FirewallRule, RuleAction, RulePriority
from ai.risk_engine import DeviceProfile

logger = logging.getLogger("volcano.database")


class Database:
    """
    Resilient Dual-Engine Database for Volcano AI Firewall.
    - Cloud PostgreSQL when available (with pool_pre_ping and keep-alive recycling).
    - Automatic graceful fallback to SQLite in WAL mode if PostgreSQL is unreachable or fails.
    - Thread-safe and zero-crash deployment architecture.
    """

    def __init__(self, db_path: str = "volcano.db") -> None:
        self.metadata = MetaData()
        self.local_db_path: Optional[Path] = None
        self.engine, self.is_postgres = self._create_resilient_engine(db_path)
        self._define_tables()
        self._init_schema()

    def _create_resilient_engine(self, db_path: str) -> Tuple[Engine, bool]:
        try:
            cfg = get_settings()
        except Exception:
            cfg = None

        pool_size = int(os.getenv("VOLCANO_DB_POOL_SIZE", str(getattr(cfg, "db_pool_size", 10))))
        max_overflow = int(os.getenv("VOLCANO_DB_MAX_OVERFLOW", str(getattr(cfg, "db_max_overflow", 20))))
        pool_pre_ping_env = os.getenv("VOLCANO_DB_POOL_PRE_PING")
        if pool_pre_ping_env is not None:
            pool_pre_ping = pool_pre_ping_env.strip().lower() in ("1", "true", "yes")
        else:
            pool_pre_ping = getattr(cfg, "db_pool_pre_ping", True)
        pool_recycle = int(os.getenv("VOLCANO_DB_POOL_RECYCLE", str(getattr(cfg, "db_pool_recycle", 180))))
        connect_timeout = int(os.getenv("VOLCANO_DB_CONNECT_TIMEOUT", str(getattr(cfg, "db_connect_timeout", 5))))

        is_pg = db_path.startswith("postgres://") or db_path.startswith("postgresql://")

        if is_pg:
            pg_url = db_path
            if pg_url.startswith("postgres://"):
                pg_url = pg_url.replace("postgres://", "postgresql://", 1)

            try:
                engine = create_engine(
                    pg_url,
                    pool_pre_ping=pool_pre_ping,
                    pool_recycle=pool_recycle,
                    pool_size=pool_size,
                    max_overflow=max_overflow,
                    connect_args={"connect_timeout": connect_timeout},
                )
                # Verify connection health
                with engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
                logger.info(
                    f"[Database] Connected to PostgreSQL with pooling (pool_size={pool_size}, "
                    f"max_overflow={max_overflow}, pool_pre_ping={pool_pre_ping}, pool_recycle={pool_recycle}s, "
                    f"connect_timeout={connect_timeout}s)."
                )
                return engine, True
            except Exception as exc:
                logger.warning(
                    f"[Database] PostgreSQL connection failed ({exc}). Falling back to local SQLite with WAL mode."
                )

        # SQLite Fallback / Default - check production profile refusal
        profile = os.getenv("VOLCANO_PROFILE", getattr(cfg, "profile", "development")).strip().lower()
        allow_sqlite_prod_env = os.getenv("VOLCANO_ALLOW_SQLITE_PRODUCTION")
        if allow_sqlite_prod_env is not None:
            allow_sqlite_prod = allow_sqlite_prod_env.strip().lower() in ("1", "true", "yes")
        else:
            allow_sqlite_prod = getattr(cfg, "allow_sqlite_production", False)

        if profile == "production" and not allow_sqlite_prod:
            reason = (
                "Production profile (VOLCANO_PROFILE=production) refuses to start with SQLite backend. "
                "Production deployments require PostgreSQL 16 for connection pooling, multi-worker safety, "
                "and concurrent transaction persistence. "
                "To override for isolated testing or single-container staging, set VOLCANO_ALLOW_SQLITE_PRODUCTION=true."
            )
            logger.critical(f"[Database] Startup aborted: {reason}")
            raise RuntimeError(reason)

        if profile == "production" and allow_sqlite_prod:
            logger.warning(
                "[Database] VOLCANO_PROFILE=production is using SQLite because VOLCANO_ALLOW_SQLITE_PRODUCTION=true is explicitly set. "
                "Concurrency and multi-worker limitations may occur."
            )

        local_db = Path(db_path if not is_pg else "volcano.db")
        if not local_db.is_absolute():
            local_db = Path("backend") / local_db.name
        local_db.parent.mkdir(parents=True, exist_ok=True)
        self.local_db_path = local_db
        sqlite_url = f"sqlite:///{local_db.resolve().as_posix()}"

        engine = create_engine(
            sqlite_url,
            connect_args={"check_same_thread": False, "timeout": 15},
        )

        @event.listens_for(engine, "connect")
        def _set_sqlite_pragmas(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode = WAL")
            cursor.execute("PRAGMA synchronous = NORMAL")
            cursor.execute("PRAGMA busy_timeout = 10000")
            cursor.execute("PRAGMA wal_autocheckpoint = 1000")
            cursor.execute("PRAGMA cache_size = -64000")
            cursor.execute("PRAGMA temp_store = MEMORY")
            cursor.close()

        logger.info(f"[Database] Initialized SQLite WAL engine at: {local_db}")
        return engine, False

    def _define_tables(self) -> None:
        self.firewall_rules_t = Table(
            "firewall_rules",
            self.metadata,
            Column("id", Integer, primary_key=True),
            Column("name", Text, nullable=False),
            Column("src_ip", Text, nullable=True),
            Column("dst_ip", Text, nullable=True),
            Column("src_port", Integer, nullable=True),
            Column("dst_port", Integer, nullable=True),
            Column("protocol", Text, nullable=True),
            Column("action", Text, nullable=False),
            Column("priority", Integer, nullable=True),
            Column("enabled", Boolean, default=True),
            Column("description", Text, nullable=True),
            Column("created_at", Text, nullable=True),
            Column("metadata", Text, nullable=True),
        )

        self.alerts_t = Table(
            "alerts",
            self.metadata,
            Column("id", Integer, primary_key=True, autoincrement=True),
            Column("timestamp", Text, nullable=False, index=True),
            Column("source", Text, nullable=False),
            Column("severity", Text, nullable=False, index=True),
            Column("category", Text, nullable=False),
            Column("message", Text, nullable=False),
            Column("metadata", Text, nullable=True),
            Column("status", Text, default="new"),
            Column("assignee", Text, nullable=True),
            Column("notes", Text, nullable=True),
            Column("created_at", Text, default=lambda: datetime.now(timezone.utc).isoformat()),
        )

        self.device_profiles_t = Table(
            "device_profiles",
            self.metadata,
            Column("mac_address", Text, primary_key=True),
            Column("risk_score", Float, default=0.0),
            Column("threat_count", Integer, default=0),
            Column("last_seen", Text, nullable=True),
            Column("behavioral_tags", Text, nullable=True),
            Column("alert_history", Text, nullable=True),
            Column("metadata", Text, nullable=True),
        )

        self.user_profiles_t = Table(
            "user_profiles",
            self.metadata,
            Column("user_id", Text, primary_key=True),
            Column("risk_score", Float, default=0.0),
            Column("threat_count", Integer, default=0),
            Column("last_seen", Text, nullable=True),
            Column("access_patterns", Text, nullable=True),
            Column("behavioral_tags", Text, nullable=True),
            Column("alert_history", Text, nullable=True),
            Column("metadata", Text, nullable=True),
        )

        self.audit_logs_t = Table(
            "audit_logs",
            self.metadata,
            Column("id", Integer, primary_key=True, autoincrement=True),
            Column("timestamp", Text, nullable=False, index=True),
            Column("user_id", Text, nullable=True),
            Column("action", Text, nullable=False),
            Column("resource", Text, nullable=True),
            Column("changes", Text, nullable=True),
            Column("status", Text, default="success"),
        )

        self.users_t = Table(
            "users",
            self.metadata,
            Column("id", Integer, primary_key=True, autoincrement=True),
            Column("username", Text, unique=True, nullable=False),
            Column("password_hash", Text, nullable=False),
            Column("role", Text, default="observer"),
            Column("created_at", Text, nullable=True),
            Column("last_login", Text, nullable=True),
            Column("active", Boolean, default=True),
            Column("must_change_password", Boolean, default=False),
            Column("failed_login_attempts", Integer, default=0),
            Column("locked_until", Text, nullable=True),
        )

        self.sensor_tokens_t = Table(
            "sensor_tokens",
            self.metadata,
            Column("id", Integer, primary_key=True, autoincrement=True),
            Column("token_id", Text, unique=True, nullable=False),
            Column("sensor_id", Text, nullable=False),
            Column("token_hash", Text, nullable=False, index=True),
            Column("description", Text, default=""),
            Column("created_at", Text, default=lambda: datetime.now(timezone.utc).isoformat()),
            Column("revoked", Boolean, default=False),
            Column("revoked_at", Text, nullable=True),
        )

    def _init_schema(self) -> None:
        try:
            self.metadata.create_all(self.engine)
            with self.engine.begin() as conn:
                for col, typ in [("status", "TEXT DEFAULT 'new'"), ("assignee", "TEXT"), ("notes", "TEXT")]:
                    try:
                        conn.execute(text(f"ALTER TABLE alerts ADD COLUMN {col} {typ}"))
                    except Exception:
                        pass
                try:
                    conn.execute(text("ALTER TABLE users ADD COLUMN must_change_password BOOLEAN DEFAULT 0"))
                except Exception:
                    pass
                try:
                    conn.execute(text("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0"))
                except Exception:
                    pass
                try:
                    conn.execute(text("ALTER TABLE users ADD COLUMN locked_until TEXT"))
                except Exception:
                    pass
            self.seed_default_users()
        except Exception as exc:
            logger.error(f"[Database] Schema creation error: {exc}")

    def save_rule(self, rule: FirewallRule) -> None:
        meta = dict(rule.meta or {})
        if getattr(rule, "app_name", None):
            meta["app_name"] = rule.app_name
        rule_data = {
            "id": rule.id,
            "name": rule.name,
            "src_ip": rule.src_ip,
            "dst_ip": rule.dst_ip,
            "src_port": rule.src_port,
            "dst_port": rule.dst_port,
            "protocol": rule.protocol,
            "action": rule.action.value if hasattr(rule.action, "value") else str(rule.action),
            "priority": rule.priority.value if hasattr(rule.priority, "value") else int(rule.priority),
            "enabled": rule.enabled,
            "description": rule.description,
            "created_at": rule.created_at,
            "metadata": json.dumps(meta),
        }

        with self.engine.begin() as conn:
            # Check existing
            stmt = select(self.firewall_rules_t.c.id).where(self.firewall_rules_t.c.id == rule.id)
            existing = conn.execute(stmt).scalar_one_or_none()
            if existing is not None:
                update_stmt = (
                    self.firewall_rules_t.update()
                    .where(self.firewall_rules_t.c.id == rule.id)
                    .values(**rule_data)
                )
                conn.execute(update_stmt)
            else:
                insert_stmt = self.firewall_rules_t.insert().values(**rule_data)
                conn.execute(insert_stmt)

    def load_rules(self) -> List[FirewallRule]:
        rules = []
        with self.engine.connect() as conn:
            stmt = select(self.firewall_rules_t)
            rows = conn.execute(stmt).fetchall()
            for row in rows:
                meta = {}
                if row.metadata:
                    try:
                        meta = json.loads(row.metadata)
                    except Exception:
                        pass
                rules.append(
                    FirewallRule(
                        id=row.id,
                        name=row.name,
                        src_ip=row.src_ip,
                        dst_ip=row.dst_ip,
                        src_port=row.src_port,
                        dst_port=row.dst_port,
                        protocol=row.protocol,
                        app_name=meta.get("app_name"),
                        action=RuleAction(row.action),
                        priority=RulePriority(row.priority) if row.priority is not None else RulePriority.NORMAL,
                        enabled=bool(row.enabled),
                        description=row.description or "",
                        created_at=row.created_at or "",
                        meta=meta,
                    )
                )
        return rules

    def save_alert(self, alert_dict: Dict[str, Any]) -> None:
        meta_str = json.dumps(alert_dict.get("meta", {}))
        alert_data = {
            "timestamp": alert_dict.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "source": alert_dict.get("source", "system"),
            "severity": alert_dict.get("severity", "info"),
            "category": alert_dict.get("category", "General"),
            "message": alert_dict.get("message", ""),
            "metadata": meta_str,
            "status": alert_dict.get("status", "new") or "new",
            "assignee": alert_dict.get("assignee"),
            "notes": alert_dict.get("notes"),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        with self.engine.begin() as conn:
            conn.execute(self.alerts_t.insert().values(**alert_data))

    def get_recent_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        alerts = []
        with self.engine.connect() as conn:
            stmt = select(self.alerts_t).order_by(self.alerts_t.c.id.desc()).limit(limit)
            rows = conn.execute(stmt).fetchall()
            for row in rows:
                meta = {}
                if row.metadata:
                    try:
                        meta = json.loads(row.metadata)
                    except Exception:
                        pass
                alerts.append(
                    {
                        "id": row.id,
                        "timestamp": row.timestamp,
                        "source": row.source,
                        "severity": row.severity,
                        "category": row.category,
                        "message": row.message,
                        "status": getattr(row, "status", "new") or "new",
                        "assignee": getattr(row, "assignee", None),
                        "notes": getattr(row, "notes", None),
                        "meta": meta,
                    }
                )
        return alerts

    def get_alert(self, alert_id: int) -> Optional[Dict[str, Any]]:
        with self.engine.connect() as conn:
            stmt = select(self.alerts_t).where(self.alerts_t.c.id == alert_id)
            row = conn.execute(stmt).fetchone()
            if not row:
                return None
            meta = {}
            if row.metadata:
                try:
                    meta = json.loads(row.metadata)
                except Exception:
                    pass
            return {
                "id": row.id,
                "timestamp": row.timestamp,
                "source": row.source,
                "severity": row.severity,
                "category": row.category,
                "message": row.message,
                "status": getattr(row, "status", "new") or "new",
                "assignee": getattr(row, "assignee", None),
                "notes": getattr(row, "notes", None),
                "meta": meta,
            }

    def save_device_profile(self, profile: DeviceProfile) -> None:
        data = {
            "mac_address": profile.mac_address,
            "risk_score": float(profile.risk_score),
            "threat_count": int(profile.threat_count),
            "last_seen": str(profile.last_seen),
            "behavioral_tags": json.dumps(profile.behavioral_tags or []),
            "alert_history": json.dumps(profile.alert_history or []),
            "metadata": json.dumps(profile.metadata or {}),
        }
        with self.engine.begin() as conn:
            stmt = select(self.device_profiles_t.c.mac_address).where(
                self.device_profiles_t.c.mac_address == profile.mac_address
            )
            existing = conn.execute(stmt).scalar_one_or_none()
            if existing is not None:
                conn.execute(
                    self.device_profiles_t.update()
                    .where(self.device_profiles_t.c.mac_address == profile.mac_address)
                    .values(**data)
                )
            else:
                conn.execute(self.device_profiles_t.insert().values(**data))

    def load_device_profiles(self) -> List[DeviceProfile]:
        profiles = []
        with self.engine.connect() as conn:
            stmt = select(self.device_profiles_t)
            rows = conn.execute(stmt).fetchall()
            for row in rows:
                profiles.append(
                    DeviceProfile(
                        mac_address=row.mac_address,
                        last_seen=float(row.last_seen) if row.last_seen else 0.0,
                        risk_score=row.risk_score,
                        threat_count=row.threat_count,
                        behavioral_tags=json.loads(row.behavioral_tags) if row.behavioral_tags else [],
                        alert_history=json.loads(row.alert_history) if row.alert_history else [],
                        metadata=json.loads(row.metadata) if row.metadata else {},
                    )
                )
        return profiles

    def log_audit(
        self,
        user_id: Optional[str],
        action: str,
        resource: str,
        changes: Optional[Dict] = None,
        status: str = "success",
    ) -> None:
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        data = {
            "timestamp": timestamp,
            "user_id": user_id,
            "action": action,
            "resource": resource,
            "changes": json.dumps(changes) if changes else None,
            "status": status,
        }
        with self.engine.begin() as conn:
            conn.execute(self.audit_logs_t.insert().values(**data))

    def get_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        logs = []
        with self.engine.connect() as conn:
            stmt = select(self.audit_logs_t).order_by(self.audit_logs_t.c.id.desc()).limit(limit)
            rows = conn.execute(stmt).fetchall()
            for row in rows:
                changes = None
                if row.changes:
                    try:
                        changes = json.loads(row.changes)
                    except Exception:
                        pass
                logs.append(
                    {
                        "id": row.id,
                        "timestamp": row.timestamp,
                        "user_id": row.user_id,
                        "action": row.action,
                        "resource": row.resource,
                        "changes": changes,
                        "status": row.status,
                    }
                )
        return logs

    def seed_default_users(self) -> Optional[str]:
        """Seed initial admin account with a secure generated password on first run.
        Returns the generated admin password if seeded, or None if users already exist.
        """
        import secrets
        from storage.auth import get_password_hash

        try:
            with self.engine.connect() as conn:
                stmt = select(self.users_t.c.id).limit(1)
                existing = conn.execute(stmt).scalar_one_or_none()
            if existing is not None:
                return None

            generated_admin_pw = f"Volcano-{secrets.token_urlsafe(12)}"
            default_users = [
                {
                    "username": "admin",
                    "password_hash": get_password_hash(generated_admin_pw),
                    "role": "admin",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "active": True,
                    "must_change_password": True,
                },
            ]
            with self.engine.begin() as conn:
                conn.execute(self.users_t.insert().values(default_users))

            # Print ONLY to console once — NEVER to loggers or audit logs
            print(f"\n{'=' * 64}")
            print("  [SECURITY NOTICE] Initial admin account created on first run.")
            print("  Username: admin")
            print(f"  Generated Temporary Password: {generated_admin_pw}")
            print("  Action Required: Change password before logging in via /api/auth/change-password")
            print(f"{'=' * 64}\n")

            logger.info("[Database] First-run user bootstrap completed. Generated admin account with must_change_password=True.")
            return generated_admin_pw
        except Exception as e:
            logger.warning(f"[Database] User seed skipped or failed: {e}")
            return None

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        with self.engine.connect() as conn:
            stmt = select(self.users_t).where(self.users_t.c.username == username)
            row = conn.execute(stmt).fetchone()
            if row:
                locked_until_val = getattr(row, "locked_until", None)
                failed_attempts = int(getattr(row, "failed_login_attempts", 0) or 0)
                is_locked = False

                if locked_until_val:
                    now_iso = datetime.now(timezone.utc).isoformat()
                    if now_iso >= str(locked_until_val):
                        # Lockout has expired; automatically unlock
                        self.reset_login_failures(username)
                        locked_until_val = None
                        failed_attempts = 0
                    else:
                        is_locked = True

                return {
                    "id": row.id,
                    "username": row.username,
                    "password_hash": row.password_hash,
                    "role": row.role,
                    "created_at": row.created_at,
                    "last_login": row.last_login,
                    "active": bool(row.active),
                    "must_change_password": bool(getattr(row, "must_change_password", False)),
                    "failed_login_attempts": failed_attempts,
                    "locked_until": locked_until_val,
                    "is_locked": is_locked,
                }
        return None

    def record_login_failure(self, username: str) -> Tuple[int, bool, Optional[str]]:
        """Increment failed login attempts and lock account for 15 minutes if attempts >= 10."""
        with self.engine.begin() as conn:
            stmt = select(self.users_t).where(self.users_t.c.username == username)
            row = conn.execute(stmt).fetchone()
            if not row:
                return 0, False, None

            current_attempts = int(getattr(row, "failed_login_attempts", 0) or 0) + 1
            locked_until_str: Optional[str] = getattr(row, "locked_until", None)
            is_locked = False

            if current_attempts >= 10:
                is_locked = True
                lockout_end = datetime.now(timezone.utc) + timedelta(minutes=15)
                locked_until_str = lockout_end.isoformat()

            update_stmt = (
                self.users_t.update()
                .where(self.users_t.c.username == username)
                .values(failed_login_attempts=current_attempts, locked_until=locked_until_str)
            )
            conn.execute(update_stmt)
            return current_attempts, is_locked, locked_until_str

    def reset_login_failures(self, username: str) -> bool:
        """Reset failed login attempts and clear lockout state."""
        with self.engine.begin() as conn:
            stmt = (
                self.users_t.update()
                .where(self.users_t.c.username == username)
                .values(failed_login_attempts=0, locked_until=None)
            )
            res = conn.execute(stmt)
            return res.rowcount > 0

    def unlock_user(self, username: str) -> bool:
        """Admin unlock for a locked user account."""
        return self.reset_login_failures(username)

    def update_user_password(self, username: str, new_password_hash: str) -> bool:
        """Update password hash and clear must_change_password flag."""
        with self.engine.begin() as conn:
            stmt = (
                self.users_t.update()
                .where(self.users_t.c.username == username)
                .values(password_hash=new_password_hash, must_change_password=False)
            )
            res = conn.execute(stmt)
            return res.rowcount > 0

    def create_user(self, username: str, password_hash: str, role: str = "viewer") -> Dict[str, Any]:
        data = {
            "username": username,
            "password_hash": password_hash,
            "role": role,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "active": True,
        }
        with self.engine.begin() as conn:
            res = conn.execute(self.users_t.insert().values(**data))
            new_id = res.inserted_primary_key[0] if res.inserted_primary_key else None
        return {"id": new_id, "username": username, "role": role}

    def list_users(self) -> List[Dict[str, Any]]:
        users = []
        with self.engine.connect() as conn:
            stmt = select(self.users_t).order_by(self.users_t.c.id.asc())
            rows = conn.execute(stmt).fetchall()
            for r in rows:
                users.append(
                    {
                        "id": r.id,
                        "username": r.username,
                        "role": r.role,
                        "created_at": r.created_at,
                        "last_login": r.last_login,
                        "active": bool(r.active),
                        "must_change_password": bool(getattr(r, "must_change_password", False)),
                        "failed_login_attempts": int(getattr(r, "failed_login_attempts", 0) or 0),
                        "locked_until": getattr(r, "locked_until", None),
                    }
                )
        return users

    def update_user_role(self, username: str, new_role: str) -> bool:
        with self.engine.begin() as conn:
            stmt = (
                self.users_t.update()
                .where(self.users_t.c.username == username)
                .values(role=new_role)
            )
            res = conn.execute(stmt)
            return res.rowcount > 0

    def update_user_last_login(self, username: str) -> bool:
        with self.engine.begin() as conn:
            stmt = (
                self.users_t.update()
                .where(self.users_t.c.username == username)
                .values(last_login=datetime.now(timezone.utc).isoformat())
            )
            res = conn.execute(stmt)
            return res.rowcount > 0

    def update_alert_triage(
        self,
        alert_id: int,
        status: Optional[str] = None,
        assignee: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> bool:
        values: Dict[str, Any] = {}
        if status is not None:
            values["status"] = status
        if assignee is not None:
            values["assignee"] = assignee
        if notes is not None:
            values["notes"] = notes
        if not values:
            return False
        with self.engine.begin() as conn:
            stmt = self.alerts_t.update().where(self.alerts_t.c.id == alert_id).values(**values)
            res = conn.execute(stmt)
            return res.rowcount > 0

    def bulk_update_alerts(self, alert_ids: List[int], action: str, status_value: Optional[str] = None) -> int:
        with self.engine.begin() as conn:
            stmt: Any
            if action == "delete":
                stmt = self.alerts_t.delete().where(self.alerts_t.c.id.in_(alert_ids))
            elif action == "status" and status_value:
                stmt = self.alerts_t.update().where(self.alerts_t.c.id.in_(alert_ids)).values(status=status_value)
            elif action in ("resolve", "resolved"):
                stmt = self.alerts_t.update().where(self.alerts_t.c.id.in_(alert_ids)).values(status="resolved")
            elif action in ("dismiss", "dismissed"):
                stmt = self.alerts_t.update().where(self.alerts_t.c.id.in_(alert_ids)).values(status="dismissed")
            else:
                return 0
            res = conn.execute(stmt)
            return res.rowcount

    def get_database_status(self) -> Dict[str, Any]:
        """Return diagnostic metrics, file sizes, page allocation, and integrity check."""
        status: Dict[str, Any] = {
            "is_postgres": self.is_postgres,
            "engine": "postgresql" if self.is_postgres else "sqlite",
            "journal_mode": "wal" if not self.is_postgres else "n/a",
            "file_size_bytes": 0,
            "file_size_mb": 0.0,
            "wal_size_bytes": 0,
            "wal_size_mb": 0.0,
            "page_size": 0,
            "page_count": 0,
            "freelist_count": 0,
            "integrity": "unknown",
            "table_counts": {},
        }

        # Table row counts
        with self.engine.connect() as conn:
            for tbl_name, tbl_obj in [
                ("alerts", self.alerts_t),
                ("rules", self.firewall_rules_t),
                ("users", self.users_t),
                ("audit_logs", self.audit_logs_t),
                ("devices", self.device_profiles_t),
            ]:
                try:
                    count = conn.execute(select(func.count()).select_from(tbl_obj)).scalar() or 0
                    status["table_counts"][tbl_name] = count
                except Exception:
                    status["table_counts"][tbl_name] = 0

            if not self.is_postgres:
                # SQLite specifics
                try:
                    status["journal_mode"] = conn.execute(text("PRAGMA journal_mode")).scalar() or "wal"
                    status["page_size"] = conn.execute(text("PRAGMA page_size")).scalar() or 0
                    status["page_count"] = conn.execute(text("PRAGMA page_count")).scalar() or 0
                    status["freelist_count"] = conn.execute(text("PRAGMA freelist_count")).scalar() or 0
                    status["integrity"] = conn.execute(text("PRAGMA quick_check")).scalar() or "ok"
                except Exception as exc:
                    status["integrity"] = f"error: {exc}"

        # File sizes
        if hasattr(self, "local_db_path") and self.local_db_path:
            db_p = Path(self.local_db_path)
            if db_p.exists():
                status["file_size_bytes"] = db_p.stat().st_size
                status["file_path"] = str(db_p.resolve())
            wal_p = Path(f"{self.local_db_path}-wal")
            if wal_p.exists():
                status["wal_size_bytes"] = wal_p.stat().st_size
            shm_p = Path(f"{self.local_db_path}-shm")
            if shm_p.exists():
                status["shm_size_bytes"] = shm_p.stat().st_size

        status["file_size_mb"] = round(status["file_size_bytes"] / (1024 * 1024), 2)
        status["wal_size_mb"] = round(status["wal_size_bytes"] / (1024 * 1024), 2)
        return status

    def checkpoint_wal(self, mode: str = "TRUNCATE") -> Dict[str, Any]:
        """Checkpoint the WAL journal into the main SQLite database.
        Modes: PASSIVE, FULL, RESTART, TRUNCATE.
        TRUNCATE writes all WAL pages into the DB and resets the -wal file to 0 bytes.
        """
        if self.is_postgres:
            return {"status": "skipped", "reason": "PostgreSQL handles WAL internally"}

        valid_modes = {"PASSIVE", "FULL", "RESTART", "TRUNCATE"}
        target_mode = mode.upper() if mode and mode.upper() in valid_modes else "TRUNCATE"

        try:
            with self.engine.connect() as conn:
                row = conn.execute(text(f"PRAGMA wal_checkpoint({target_mode})")).fetchone()
                busy = row[0] if row else 0
                log_pages = row[1] if row else 0
                checkpointed = row[2] if row else 0

            return {
                "status": "success",
                "mode": target_mode,
                "busy": busy,
                "log_pages": log_pages,
                "checkpointed_pages": checkpointed,
            }
        except Exception as exc:
            logger.warning(f"Failed to checkpoint SQLite WAL: {exc}")
            return {"status": "error", "error": str(exc)}

    def vacuum(self) -> Dict[str, Any]:
        """Run VACUUM to defragment storage, rebuild B-trees, and reclaim deleted disk space."""
        before_status = self.get_database_status()
        try:
            # SQLite VACUUM cannot run inside a multi-statement transaction
            with self.engine.connect() as conn:
                conn.execution_options(isolation_level="AUTOCOMMIT")
                if self.is_postgres:
                    conn.execute(text("VACUUM ANALYZE"))
                else:
                    conn.execute(text("VACUUM"))
                    conn.execute(text("PRAGMA optimize"))

            after_status = self.get_database_status()
            reclaimed_bytes = max(0, before_status["file_size_bytes"] - after_status["file_size_bytes"])

            return {
                "status": "success",
                "before_size_bytes": before_status["file_size_bytes"],
                "after_size_bytes": after_status["file_size_bytes"],
                "reclaimed_bytes": reclaimed_bytes,
                "reclaimed_mb": round(reclaimed_bytes / (1024 * 1024), 2),
            }
        except Exception as exc:
            logger.warning(f"VACUUM failed: {exc}")
            return {"status": "error", "error": str(exc)}

    def run_integrity_check(self) -> Dict[str, Any]:
        """Perform comprehensive integrity and foreign key checks."""
        if self.is_postgres:
            return {"status": "healthy", "engine": "postgresql", "errors": []}

        try:
            with self.engine.connect() as conn:
                integrity_rows = conn.execute(text("PRAGMA integrity_check(100)")).fetchall()
                fk_rows = conn.execute(text("PRAGMA foreign_key_check")).fetchall()

            messages = [r[0] for r in integrity_rows] if integrity_rows else ["ok"]
            is_healthy = messages == ["ok"] and len(fk_rows) == 0

            return {
                "status": "healthy" if is_healthy else "corrupted",
                "integrity_check": messages,
                "foreign_key_violations": len(fk_rows),
            }
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def prune_stale_data(
        self,
        max_alert_age_days: int = 30,
        max_audit_age_days: int = 90,
        keep_minimum_alerts: int = 500,
    ) -> Dict[str, Any]:
        """Prune stale resolved/dismissed alerts and old audit logs to maintain lean local storage."""
        now_ts = time.time()
        alert_cutoff = now_ts - (max_alert_age_days * 86400)
        audit_cutoff_dt = datetime.now(timezone.utc) - timedelta(days=max_audit_age_days)
        audit_cutoff_str = audit_cutoff_dt.isoformat()

        pruned_alerts = 0
        pruned_audits = 0

        with self.engine.begin() as conn:
            # Check current alert count
            total_alerts = conn.execute(select(func.count()).select_from(self.alerts_t)).scalar() or 0
            if total_alerts > keep_minimum_alerts:
                stmt = (
                    self.alerts_t.delete()
                    .where(
                        (self.alerts_t.c.timestamp < alert_cutoff)
                        & (self.alerts_t.c.status.in_(["resolved", "false_positive", "dismissed"]))
                    )
                )
                res = conn.execute(stmt)
                pruned_alerts = res.rowcount

            # Prune old audit logs
            audit_stmt = self.audit_logs_t.delete().where(self.audit_logs_t.c.timestamp < audit_cutoff_str)
            audit_res = conn.execute(audit_stmt)
            pruned_audits = audit_res.rowcount

        return {
            "pruned_alerts": pruned_alerts,
            "pruned_audit_logs": pruned_audits,
            "alert_cutoff_timestamp": alert_cutoff,
            "audit_cutoff": audit_cutoff_str,
        }

    def optimize(self) -> Dict[str, Any]:
        """Run PRAGMA optimize for query planner tuning."""
        if self.is_postgres:
            return {"status": "skipped"}
        try:
            with self.engine.connect() as conn:
                conn.execute(text("PRAGMA optimize"))
            return {"status": "success"}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    # -------------------------------------------------------------------------
    # Sensor Token Management (Phase 3 Sensor / Collector Ingest Auth)
    # -------------------------------------------------------------------------

    def create_sensor_token(self, sensor_id: str, description: str = "") -> Tuple[str, Dict[str, Any]]:
        """
        Generate a cryptographically secure sensor secret token, store its SHA-256 hash,
        and return (raw_token, token_metadata).
        """
        raw_secret = secrets.token_urlsafe(32)
        raw_token = f"vst_{raw_secret}"
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        token_id = f"stk_{uuid.uuid4().hex[:12]}"
        now_str = datetime.now(timezone.utc).isoformat()

        with self.engine.begin() as conn:
            conn.execute(
                self.sensor_tokens_t.insert().values(
                    token_id=token_id,
                    sensor_id=sensor_id.strip(),
                    token_hash=token_hash,
                    description=description.strip(),
                    created_at=now_str,
                    revoked=False,
                    revoked_at=None,
                )
            )

        token_record = {
            "token_id": token_id,
            "sensor_id": sensor_id.strip(),
            "description": description.strip(),
            "created_at": now_str,
            "revoked": False,
            "revoked_at": None,
        }
        return raw_token, token_record

    def verify_sensor_token(self, raw_token: str) -> Optional[Dict[str, Any]]:
        """Verify raw sensor token against stored hash; return token record if valid and active."""
        if not raw_token or not isinstance(raw_token, str):
            return None

        clean_token = raw_token.strip()
        if clean_token.startswith("Bearer "):
            clean_token = clean_token[7:].strip()

        token_hash = hashlib.sha256(clean_token.encode("utf-8")).hexdigest()

        with self.engine.connect() as conn:
            stmt = select(self.sensor_tokens_t).where(
                (self.sensor_tokens_t.c.token_hash == token_hash)
                & (self.sensor_tokens_t.c.revoked.is_(False))
            )
            row = conn.execute(stmt).fetchone()
            if row:
                return {
                    "id": row.id,
                    "token_id": row.token_id,
                    "sensor_id": row.sensor_id,
                    "description": row.description,
                    "created_at": row.created_at,
                    "revoked": row.revoked,
                }
        return None

    def revoke_sensor_token(self, token_id: str) -> bool:
        """Revoke a sensor token by token_id."""
        now_str = datetime.now(timezone.utc).isoformat()
        with self.engine.begin() as conn:
            stmt = (
                self.sensor_tokens_t.update()
                .where(self.sensor_tokens_t.c.token_id == token_id)
                .values(revoked=True, revoked_at=now_str)
            )
            res = conn.execute(stmt)
            return res.rowcount > 0

    def list_sensor_tokens(self) -> List[Dict[str, Any]]:
        """List all registered sensor tokens (excluding hashes)."""
        tokens: List[Dict[str, Any]] = []
        with self.engine.connect() as conn:
            stmt = select(
                self.sensor_tokens_t.c.token_id,
                self.sensor_tokens_t.c.sensor_id,
                self.sensor_tokens_t.c.description,
                self.sensor_tokens_t.c.created_at,
                self.sensor_tokens_t.c.revoked,
                self.sensor_tokens_t.c.revoked_at,
            ).order_by(self.sensor_tokens_t.c.id.desc())
            for row in conn.execute(stmt):
                tokens.append({
                    "token_id": row.token_id,
                    "sensor_id": row.sensor_id,
                    "description": row.description,
                    "created_at": row.created_at,
                    "revoked": row.revoked,
                    "revoked_at": row.revoked_at,
                })
        return tokens

