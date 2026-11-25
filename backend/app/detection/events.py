import json
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any

logger = logging.getLogger("authshield.security_events")

# Shared canonical event types aligned with Stage 3
EVENT_LOGIN_SUCCESS = "LOGIN_SUCCESS"
EVENT_LOGIN_FAILURE = "LOGIN_FAILURE"
EVENT_MFA_SUCCESS = "MFA_SUCCESS"
EVENT_MFA_FAILURE = "MFA_FAILURE"
EVENT_ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
EVENT_PASSWORD_RESET_REQUESTED = "PASSWORD_RESET_REQUESTED"
EVENT_PASSWORD_RESET_COMPLETED = "PASSWORD_RESET_COMPLETED"
EVENT_SESSION_CREATED = "SESSION_CREATED"
EVENT_SESSION_REVOKED = "SESSION_REVOKED"
EVENT_MFA_ENABLED = "MFA_ENABLED"
EVENT_MFA_DISABLED = "MFA_DISABLED"
EVENT_ADMIN_ACTION = "ADMIN_ACTION"
EVENT_PASSWORD_CHANGED = "PASSWORD_CHANGED"
EVENT_RECOVERY_CODE_USED = "RECOVERY_CODE_USED"
EVENT_USER_REGISTERED = "USER_REGISTERED"

# In-memory ring buffer for recent security events (helpful before Stage 3 DB table is added)
_RECENT_EVENTS: list[Dict[str, Any]] = []


def record_security_event(
    event_type: str,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    ip_address: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Record a structured security event.
    Logs structured metadata safely (never include secrets or raw tokens).
    Will persist to the security_events table once Stage 3 is added.
    """
    event = {
        "event_type": event_type,
        "user_id": user_id,
        "username": username,
        "ip_address": ip_address,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": details or {},
    }

    _RECENT_EVENTS.append(event)
    if len(_RECENT_EVENTS) > 500:
        _RECENT_EVENTS.pop(0)

    logger.info("SECURITY_EVENT %s", json.dumps(event))
    return event


def get_recent_security_events(event_type: Optional[str] = None) -> list[Dict[str, Any]]:
    """Return recorded in-memory security events, optionally filtered by event_type."""
    if event_type:
        return [e for e in _RECENT_EVENTS if e["event_type"] == event_type]
    return list(_RECENT_EVENTS)


def clear_recent_security_events() -> None:
    """Clear the in-memory security event buffer (useful for isolated tests)."""
    _RECENT_EVENTS.clear()
