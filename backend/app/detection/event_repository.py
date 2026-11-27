from datetime import datetime, timezone, timedelta
from typing import Optional, List, Tuple
from flask import current_app
from app.extensions import db
from app.models.security_event import SecurityEvent


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
