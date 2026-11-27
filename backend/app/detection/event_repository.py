from datetime import datetime, timezone, timedelta
from typing import Optional, List, Tuple, Dict, Any
from flask import current_app
from app.extensions import db
from app.models.security_event import SecurityEvent
from app.detection.event_types import EVENT_LOGIN_FAILURE, EVENT_LOGIN_BLOCKED


def query_events(
    event_type: Optional[str] = None,
    user_id: Optional[int] = None,
    source_ip: Optional[str] = None,
    success: Optional[bool] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = 100,
    offset: int = 0,
) -> Tuple[List[SecurityEvent], int]:
    """
    Query persisted security events with optional filtering and pagination.
    Returns (events_list, total_matching_count).
    """
    query = SecurityEvent.query

    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)
    if user_id is not None:
        query = query.filter(SecurityEvent.user_id == user_id)
    if source_ip:
        query = query.filter(SecurityEvent.source_ip == source_ip)
    if success is not None:
        query = query.filter(SecurityEvent.success == success)
    if since is not None:
        query = query.filter(SecurityEvent.timestamp >= since)
    if until is not None:
        query = query.filter(SecurityEvent.timestamp <= until)

    total = query.count()
    bounded_limit = max(1, min(limit, 500))
    bounded_offset = max(0, offset)

    events = (
        query.order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
        .offset(bounded_offset)
        .limit(bounded_limit)
        .all()
    )
    return events, total


def count_events(
    event_type: Optional[str] = None,
    user_id: Optional[int] = None,
    source_ip: Optional[str] = None,
    attempted_identifier: Optional[str] = None,
    success: Optional[bool] = None,
    since: Optional[datetime] = None,
) -> int:
    """Fast indexed count query used for threat detection rules and metrics."""
    query = SecurityEvent.query

    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)
    if user_id is not None:
        query = query.filter(SecurityEvent.user_id == user_id)
    if source_ip:
        query = query.filter(SecurityEvent.source_ip == source_ip)
    if attempted_identifier:
        query = query.filter(SecurityEvent.attempted_identifier == attempted_identifier)
    if success is not None:
        query = query.filter(SecurityEvent.success == success)
    if since is not None:
        query = query.filter(SecurityEvent.timestamp >= since)

    return query.count()


def count_total_events() -> int:
    """Return total count of persisted security events."""
    return SecurityEvent.query.count()


def count_account_login_failures(
    user_id: Optional[int] = None,
    attempted_identifier: Optional[str] = None,
    since: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Count LOGIN_FAILURE and LOGIN_BLOCKED events for one target account within a time window.
    Uses indexed user_id or attempted_identifier columns.
    """
    if user_id is None and not attempted_identifier:
        return {
            "total_failures": 0,
            "login_failures": 0,
            "login_blocked": 0,
            "distinct_source_ips": 0,
        }

    query = SecurityEvent.query.filter(
        SecurityEvent.event_type.in_([EVENT_LOGIN_FAILURE, EVENT_LOGIN_BLOCKED])
    )
    if user_id is not None:
        query = query.filter(SecurityEvent.user_id == user_id)
    else:
        query = query.filter(SecurityEvent.attempted_identifier == attempted_identifier)

    if since is not None:
        query = query.filter(SecurityEvent.timestamp >= since)

    rows = query.all()
    login_failures = sum(1 for r in rows if r.event_type == EVENT_LOGIN_FAILURE)
    login_blocked = sum(1 for r in rows if r.event_type == EVENT_LOGIN_BLOCKED)
    distinct_ips = len({r.source_ip for r in rows if r.source_ip})

    return {
        "total_failures": len(rows),
        "login_failures": login_failures,
        "login_blocked": login_blocked,
        "distinct_source_ips": distinct_ips,
    }


def count_ip_distinct_targets(
    source_ip: Optional[str],
    since: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Count distinct target accounts (via HMAC attempted_identifier or user_id)
    targeted from one source_ip within a time window (Step 4.3).
    """
    if not source_ip:
        return {
            "distinct_accounts": 0,
            "total_attempts": 0,
            "unknown_account_attempts": 0,
        }

    query = SecurityEvent.query.filter(
        SecurityEvent.source_ip == source_ip,
        SecurityEvent.event_type.in_([EVENT_LOGIN_FAILURE, EVENT_LOGIN_BLOCKED]),
    )
    if since is not None:
        query = query.filter(SecurityEvent.timestamp >= since)

    rows = query.all()
    distinct_targets = set()
    unknown_count = 0

    for r in rows:
        if r.user_id is None:
            unknown_count += 1
        target_key = r.attempted_identifier or (f"uid:{r.user_id}" if r.user_id is not None else None)
        if target_key:
            distinct_targets.add(target_key)

    return {
        "distinct_accounts": len(distinct_targets),
        "total_attempts": len(rows),
        "unknown_account_attempts": unknown_count,
    }


def purge_expired_events(retention_days: Optional[int] = None) -> int:
    """
    Apply retention policy: delete security_events older than retention_days.
    Returns number of deleted rows.
    """
    if retention_days is None:
        try:
            retention_days = current_app.config.get("EVENT_RETENTION_DAYS", 90)
        except RuntimeError:
            retention_days = 90

    cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, retention_days))
    deleted_count = SecurityEvent.query.filter(SecurityEvent.timestamp < cutoff).delete(
        synchronize_session="fetch"
    )
    db.session.commit()
    return deleted_count
