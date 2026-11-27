import ipaddress
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any
from flask import current_app, has_app_context, has_request_context, request
from sqlalchemy.exc import SQLAlchemyError
from app.extensions import db
from app.models.security_event import SecurityEvent, hash_attempted_identifier
from app.detection.event_types import (
    is_valid_event_type,
    EVENT_LOGIN_FAILURE,
    EVENT_MFA_FAILURE,
    EVENT_LOGIN_BLOCKED,
    EVENT_ACCOUNT_LOCKED,
)

logger = logging.getLogger("authshield.security_events")

_FAIL2BAN_EVENT_TYPES = frozenset({
    EVENT_LOGIN_FAILURE,
    EVENT_MFA_FAILURE,
    EVENT_LOGIN_BLOCKED,
    EVENT_ACCOUNT_LOCKED,
})

# In-memory ring buffer mirroring recent sanitized events
_RECENT_EVENTS: list[Dict[str, Any]] = []

# Keys whose values must never be recorded in plaintext
_SENSITIVE_EXACT_KEYS = frozenset({
    "password",
    "passwd",
    "pwd",
    "new_password",
    "current_password",
    "old_password",
    "password_hash",
    "totp",
    "totp_code",
    "totp_secret",
    "code",
    "mfa_code",
    "mfa_token",
    "setup_token",
    "session_token",
    "reset_token",
    "token",
    "recovery_code",
    "recovery_codes",
    "cookie",
    "cookies",
    "secret",
    "secret_key",
    "authorization",
    "csrf_token",
    "api_key",
    "attempted_username",
})

_SENSITIVE_SUFFIXES = ("_password", "_secret", "_token", "_cookie", "_totp")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


def sanitize_string(value: Any, max_length: int = 255) -> Optional[str]:
    """Strip control characters (newlines, nulls) and bound string length."""
    if value is None:
        return None
    cleaned = _CONTROL_CHARS_RE.sub(" ", str(value)).strip()
    if len(cleaned) > max_length:
        return cleaned[:max_length]
    return cleaned


def _is_sensitive_key(key: str) -> bool:
    lowered = key.strip().lower()
    if lowered in _SENSITIVE_EXACT_KEYS:
        return True
    return lowered.endswith(_SENSITIVE_SUFFIXES)


def sanitize_details(details: Optional[Dict[str, Any]], _depth: int = 0) -> Dict[str, Any]:
    """
    Recursively sanitize event details, redacting passwords, TOTP codes,
    session cookies, reset tokens, and truncating user-controlled strings.
    """
    if not details or not isinstance(details, dict) or _depth > 4:
        return {}

    sanitized: Dict[str, Any] = {}
    for raw_k, val in details.items():
        key = sanitize_string(raw_k, max_length=64) or "key"
        if _is_sensitive_key(key):
            sanitized[key] = "[REDACTED]"
            continue

        if isinstance(val, dict):
            sanitized[key] = sanitize_details(val, _depth=_depth + 1)
        elif isinstance(val, list):
            sanitized[key] = [
                sanitize_string(item, max_length=256) if isinstance(item, str) else item
                for item in val[:25]
            ]
        elif isinstance(val, str):
            sanitized[key] = sanitize_string(val, max_length=512)
        elif isinstance(val, (int, float, bool)) or val is None:
            sanitized[key] = val
        else:
            sanitized[key] = sanitize_string(val, max_length=256)

    return sanitized


def _parse_valid_ip(candidate: Optional[str]) -> Optional[str]:
    if not candidate:
        return None
    cleaned = sanitize_string(candidate, max_length=45)
    if not cleaned:
        return None
    try:
        return str(ipaddress.ip_address(cleaned))
    except ValueError:
        return None


def resolve_client_ip(explicit_ip: Optional[str] = None) -> Optional[str]:
    """
    Resolve client IP safely.
    Only trusts X-Forwarded-For when the immediate peer address is in TRUSTED_PROXIES.
    """
    if explicit_ip:
        parsed = _parse_valid_ip(explicit_ip)
        return parsed or sanitize_string(explicit_ip, max_length=45)

    if not has_request_context():
        return None

    peer_ip = _parse_valid_ip(request.remote_addr)
    try:
        trusted_proxies = set(current_app.config.get("TRUSTED_PROXIES", []))
    except RuntimeError:
        trusted_proxies = set()

    if peer_ip and peer_ip in trusted_proxies:
        forwarded_for = request.headers.get("X-Forwarded-For", "")
        if forwarded_for:
            # Take right-most untrusted IP in the chain (closest non-proxy client)
            hops = [h.strip() for h in forwarded_for.split(",") if h.strip()]
            for hop in reversed(hops):
                parsed_hop = _parse_valid_ip(hop)
                if parsed_hop and parsed_hop not in trusted_proxies:
                    return parsed_hop
            # If all hops are trusted proxies, fall back to left-most valid IP
            for hop in hops:
                parsed_hop = _parse_valid_ip(hop)
                if parsed_hop:
                    return parsed_hop

    return peer_ip or sanitize_string(request.remote_addr, max_length=45)


def resolve_user_agent(explicit_ua: Optional[str] = None) -> Optional[str]:
    """Extract and sanitize user-agent metadata safely."""
    if explicit_ua is not None:
        return sanitize_string(explicit_ua, max_length=255)
    if has_request_context():
        ua = request.headers.get("User-Agent")
        return sanitize_string(ua, max_length=255)
    return None


def write_fail2ban_auth_log(
    username: Optional[str],
    source_ip: Optional[str],
    timestamp: Optional[datetime] = None,
) -> None:
    """
    Append a Fail2Ban-compatible line to logs/auth.log matching:
      YYYY-MM-DD HH:MM:SS Failed login attempt for user=<safe_user> from <HOST>
    Never writes raw unverified identifiers (uses 'unknown' if user is unknown).
    """
    if not has_app_context():
        return
    if not current_app.config.get("AUTH_LOG_ENABLED", False):
        return

    log_path_str = current_app.config.get("AUTH_LOG_PATH")
    if not log_path_str or not source_ip:
        return

    ts = (timestamp or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M:%S")
    safe_user = re.sub(r"[^A-Za-z0-9_.-]", "_", username or "unknown")[:64]
    line = f"{ts} Failed login attempt for user={safe_user} from {source_ip}\n"

    try:
        log_path = Path(log_path_str)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError as exc:
        logger.warning("Failed to write Fail2Ban auth.log entry: %s", exc)


def record_security_event(
    event_type: str,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    ip_address: Optional[str] = None,
    source_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    attempted_identifier: Optional[str] = None,
    raw_identifier: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    success: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Central security event collector (Step 3.3).
    Validates canonical event_type, redacts secrets, sanitizes inputs,
    computes HMAC for attempted_identifier, persists to security_events in DB,
    and writes structured JSON logs.
    """
    if not is_valid_event_type(event_type):
        raise ValueError(f"Unknown security event type: '{event_type}'")

    resolved_ip = resolve_client_ip(source_ip or ip_address)
    resolved_ua = resolve_user_agent(user_agent)
    safe_details = sanitize_details(details)
    safe_username = sanitize_string(username, max_length=64)

    # Compute keyed HMAC for attempted_identifier when raw_identifier (or username) is supplied
    hmac_identifier = attempted_identifier
    if not hmac_identifier and raw_identifier:
        hmac_identifier = hash_attempted_identifier(raw_identifier)
    elif not hmac_identifier and safe_username:
        hmac_identifier = hash_attempted_identifier(safe_username)

    now = datetime.now(timezone.utc)
    persisted_id: Optional[int] = None

    if has_app_context():
        try:
            event_row = SecurityEvent(
                event_type=event_type,
                user_id=user_id,
                source_ip=resolved_ip,
                user_agent=resolved_ua,
                timestamp=now,
                success=success,
                attempted_identifier=hmac_identifier,
                details=safe_details,
            )
            db.session.add(event_row)
            db.session.commit()
            persisted_id = event_row.id
        except SQLAlchemyError as exc:
            db.session.rollback()
            logger.warning("Failed to persist security event %s to DB: %s", event_type, type(exc).__name__)

    event_payload = {
        "id": persisted_id,
        "event_type": event_type,
        "user_id": user_id,
        "username": safe_username,
        "source_ip": resolved_ip,
        "ip_address": resolved_ip,
        "user_agent": resolved_ua,
        "success": success,
        "attempted_identifier": hmac_identifier,
        "timestamp": now.isoformat(),
        "details": safe_details,
    }

    _RECENT_EVENTS.append(event_payload)
    if len(_RECENT_EVENTS) > 500:
        _RECENT_EVENTS.pop(0)

    if event_type in _FAIL2BAN_EVENT_TYPES:
        write_fail2ban_auth_log(safe_username, resolved_ip, timestamp=now)

    logger.info("SECURITY_EVENT %s", json.dumps(event_payload))

    # Step 4.1: Trigger targeted threat detection after storing trigger events
    if has_app_context() and current_app.config.get("DETECTOR_REALTIME_ENABLED", True):
        try:
            from app.detection.detector import analyze_event, TARGETED_TRIGGER_EVENTS
            if event_type in TARGETED_TRIGGER_EVENTS:
                analyze_event(event_payload)
        except Exception as exc:
            logger.warning("Targeted detection failed for %s: %s", event_type, exc)

    return event_payload


def get_recent_security_events(event_type: Optional[str] = None) -> list[Dict[str, Any]]:
    """Return recent buffered security events, optionally filtered by event_type."""
    if event_type:
        return [e for e in _RECENT_EVENTS if e["event_type"] == event_type]
    return list(_RECENT_EVENTS)


def clear_recent_security_events() -> None:
    """Clear the in-memory security event buffer (useful for isolated tests)."""
    _RECENT_EVENTS.clear()
