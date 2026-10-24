"""Authentication and Role-Based Access Control (RBAC) module.
Handles JWT token creation/verification, password hashing, and FastAPI route protection.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

import bcrypt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from jwt.exceptions import PyJWTError

from config import get_settings

logger = logging.getLogger("volcano.auth")

security_scheme = HTTPBearer(auto_error=False)


def get_password_hash(password: str) -> str:
    """Hash password securely using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception as e:
        logger.warning(f"Password verification error: {e}")
        return False


def create_access_token(
    user_id: str,
    username: str,
    role: str = "viewer",
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a signed JWT token containing user identity and role."""
    cfg = get_settings()
    if expires_delta is None:
        expires_delta = timedelta(minutes=cfg.jwt_access_token_expire_minutes)

    expire = datetime.now(timezone.utc) + expires_delta
    payload = {
        "sub": str(user_id),
        "user_id": str(user_id),
        "username": username,
        "role": role.lower(),
        "exp": expire,
    }
    encoded = jwt.encode(payload, cfg.jwt_secret_key, algorithm=cfg.jwt_algorithm)
    return encoded if isinstance(encoded, str) else encoded.decode("utf-8")


def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate JWT token."""
    cfg = get_settings()
    try:
        payload = jwt.decode(token, cfg.jwt_secret_key, algorithms=[cfg.jwt_algorithm])
        return payload
    except PyJWTError:
        return None


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """FastAPI dependency to extract and authenticate current user from Bearer token."""
    token = None
    if credentials:
        token = credentials.credentials
    elif authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload


def get_optional_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    authorization: Optional[str] = Header(default=None),
) -> Optional[Dict[str, Any]]:
    """Extract current user if valid token present, otherwise return anonymous fallback."""
    token = None
    if credentials:
        token = credentials.credentials
    elif authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()

    if not token:
        return None
    return verify_token(token)


def require_role(allowed_roles: List[str]) -> Callable:
    """Dependency factory checking that user holds at least one of the allowed roles."""
    normalized_allowed = [r.lower() for r in allowed_roles]

    def _role_checker(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        user_role = (user.get("role") or "viewer").lower()
        if user_role not in normalized_allowed and "admin" not in user_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires one of roles: {allowed_roles}. Current role: '{user_role}'.",
            )
        return user

    return _role_checker


# Convenient role dependencies
require_admin = require_role(["admin"])
require_analyst_or_admin = require_role(["admin", "analyst"])
require_authenticated = require_role(["admin", "analyst", "viewer"])
