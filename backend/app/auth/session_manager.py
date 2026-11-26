import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from functools import wraps
from typing import Optional, Tuple, List
from flask import request, current_app, jsonify, g
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from app.extensions import db
from app.models.user import User
from app.models.session import UserSession
from app.detection.events import (
    record_security_event,
    EVENT_SESSION_CREATED,
    EVENT_SESSION_REVOKED,
)


def generate_session_token() -> str:
    """Generate a cryptographically secure random opaque session token."""
    return secrets.token_urlsafe(48)


def hash_session_token(token: str) -> str:
    """Compute SHA-256 hash of the session token for storage and lookup."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(
    user_id: int,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    lifetime_seconds: Optional[int] = None
) -> Tuple[UserSession, str]:
    """
    Create a new server-side session for a user.
    Stores the SHA-256 hash in the database, returns the raw token to be set in the cookie.
    """
    if lifetime_seconds is None:
        try:
            lifetime_seconds = current_app.config.get("SESSION_LIFETIME_SECONDS", 86400)
        except RuntimeError:
            lifetime_seconds = 86400

    raw_token = generate_session_token()
    token_hash = hash_session_token(raw_token)

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=lifetime_seconds)

    # Sanitize user agent length
    clean_ua = (user_agent[:250] + "...") if user_agent and len(user_agent) > 250 else user_agent

    session_obj = UserSession(
        user_id=user_id,
        session_hash=token_hash,
        ip_address=ip_address,
        user_agent=clean_ua,
        created_at=now,
        last_active_at=now,
        expires_at=expires_at,
        is_revoked=False,
    )
    db.session.add(session_obj)
    db.session.commit()

    record_security_event(
        EVENT_SESSION_CREATED,
        user_id=user_id,
        ip_address=ip_address,
        success=True,
        details={"session_id": session_obj.id},
    )

    return session_obj, raw_token


def get_token_from_request() -> Optional[str]:
    """
    Extract session token from request.
    Prioritizes HttpOnly cookie, then falls back to Authorization header or X-Session-Token.
    """
    cookie_name = "authshield_session"
    try:
        cookie_name = current_app.config.get("SESSION_COOKIE_NAME", "authshield_session")
    except RuntimeError:
        pass

    # 1. HttpOnly Cookie
    token = request.cookies.get(cookie_name)
    if token:
        return token.strip()

    # 2. Authorization Header (Bearer token)
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        bearer_token = auth_header[7:].strip()
        if bearer_token:
            return bearer_token

    # 3. Custom Header (X-Session-Token)
    custom_header = request.headers.get("X-Session-Token")
    if custom_header:
        return custom_header.strip()

    return None


def get_session_by_token(raw_token: str) -> Optional[UserSession]:
    """
    Look up, validate, and touch an active session record.
    Enforces absolute expiry and idle timeout policies.
    """
    if not raw_token:
        return None

    token_hash = hash_session_token(raw_token)
    session_obj = UserSession.query.filter_by(session_hash=token_hash).first()

    if not session_obj or session_obj.is_revoked:
        return None

    now = datetime.now(timezone.utc)

    # Absolute Expiry Check
    if session_obj.is_expired:
        session_obj.is_revoked = True
        session_obj.revoked_at = now
        db.session.commit()
        return None

    # Idle Timeout Check
    try:
        idle_limit = current_app.config.get("SESSION_IDLE_TIMEOUT_SECONDS", 3600)
    except RuntimeError:
        idle_limit = 3600

    if session_obj.is_idle_timeout(idle_limit):
        session_obj.is_revoked = True
        session_obj.revoked_at = now
        db.session.commit()
        return None

    # Update last active timestamp
    session_obj.last_active_at = now
    db.session.commit()

    return session_obj


def revoke_session(session_id: int, user_id: int) -> bool:
    """Revoke a specific session belonging to a user."""
    session_obj = UserSession.query.filter_by(id=session_id, user_id=user_id).first()
    if not session_obj:
        return False

    session_obj.is_revoked = True
    session_obj.revoked_at = datetime.now(timezone.utc)
    db.session.commit()

    record_security_event(
        EVENT_SESSION_REVOKED,
        user_id=user_id,
        success=True,
        details={"session_id": session_id},
    )
    return True


def revoke_other_sessions(user_id: int, current_session_id: Optional[int] = None) -> int:
    """Revoke all sessions for a user except the current active session."""
    query = UserSession.query.filter(
        UserSession.user_id == user_id,
        UserSession.is_revoked == False  # noqa: E712
    )
    if current_session_id is not None:
        query = query.filter(UserSession.id != current_session_id)

    sessions = query.all()
    now = datetime.now(timezone.utc)
    for s in sessions:
        s.is_revoked = True
        s.revoked_at = now

    db.session.commit()
    if sessions:
        record_security_event(
            EVENT_SESSION_REVOKED,
            user_id=user_id,
            success=True,
            details={
                "revoked_count": len(sessions),
                "kept_session_id": current_session_id,
            },
        )
    return len(sessions)


def revoke_all_sessions(user_id: int) -> int:
    """Revoke every active session for a user."""
    return revoke_other_sessions(user_id, current_session_id=None)


def set_session_cookie(response, raw_token: str):
    """Set secure HttpOnly cookie on response."""
    try:
        cfg = current_app.config
        cookie_name = cfg.get("SESSION_COOKIE_NAME", "authshield_session")
        samesite = cfg.get("SESSION_COOKIE_SAMESITE", "Lax")
        secure = cfg.get("SESSION_COOKIE_SECURE", False)
        max_age = cfg.get("SESSION_LIFETIME_SECONDS", 86400)
    except RuntimeError:
        cookie_name = "authshield_session"
        samesite = "Lax"
        secure = False
        max_age = 86400

    response.set_cookie(
        key=cookie_name,
        value=raw_token,
        max_age=max_age,
        httponly=True,
        samesite=samesite,
        secure=secure,
        path="/",
    )
    return response


def clear_session_cookie(response):
    """Clear session cookie from response."""
    try:
        cookie_name = current_app.config.get("SESSION_COOKIE_NAME", "authshield_session")
    except RuntimeError:
        cookie_name = "authshield_session"

    response.delete_cookie(key=cookie_name, path="/")
    return response


def generate_csrf_token(session_id: int) -> str:
    """Generate a signed CSRF token bound to the current session."""
    try:
        secret = current_app.config.get("SECRET_KEY", "fallback-secret")
    except RuntimeError:
        secret = "fallback-secret"
    s = URLSafeTimedSerializer(secret, salt="authshield-csrf")
    return s.dumps({"session_id": session_id})


def verify_csrf_token(token: str, session_id: int, max_age: int = 86400) -> bool:
    """Verify a CSRF token matches the authenticated session."""
    if not token:
        return False
    try:
        secret = current_app.config.get("SECRET_KEY", "fallback-secret")
    except RuntimeError:
        secret = "fallback-secret"
    s = URLSafeTimedSerializer(secret, salt="authshield-csrf")
    try:
        data = s.loads(token, max_age=max_age)
        return data.get("session_id") == session_id
    except (BadSignature, SignatureExpired):
        return False


def login_required(f):
    """
    Decorator that enforces active server-side session authentication.
    Injects g.current_user and g.current_session into Flask application context.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = get_token_from_request()
        if not token:
            return jsonify({
                "error": "Unauthorized",
                "message": "Authentication required. Please log in."
            }), 401

        session_obj = get_session_by_token(token)
        if not session_obj:
            return jsonify({
                "error": "Unauthorized",
                "message": "Session is invalid, expired, or revoked. Please log in again."
            }), 401

        user = db.session.get(User, session_obj.user_id)
        if not user or not user.is_active:
            return jsonify({
                "error": "Unauthorized",
                "message": "Account has been deactivated."
            }), 401

        if user.is_locked:
            return jsonify({
                "error": "Forbidden",
                "message": "Account is temporarily locked."
            }), 403

        # Task 7 & 8: Invalidate sessions established prior to the latest password change
        if user.password_changed_at:
            session_created = session_obj.created_at
            pwd_changed = user.password_changed_at
            if session_created.tzinfo is None:
                session_created = session_created.replace(tzinfo=timezone.utc)
            if pwd_changed.tzinfo is None:
                pwd_changed = pwd_changed.replace(tzinfo=timezone.utc)

            if session_created < pwd_changed:
                session_obj.is_revoked = True
                session_obj.revoked_at = datetime.now(timezone.utc)
                db.session.commit()
                return jsonify({
                    "error": "Unauthorized",
                    "message": "Session has been invalidated due to a password change. Please log in again."
                }), 401

        g.current_user = user
        g.current_session = session_obj
        return f(*args, **kwargs)

    return decorated_function
