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


_SPRAY_METADATA_KEYS = (
    "spray_pattern",
    "spray_cohort",
    "simulation_tag",
    "test_spray_id",
    "campaign_id",
)


def _resolve_target_key(event: SecurityEvent) -> Optional[str]:
    """Return a privacy-preserving target key for aggregating across real and unknown accounts."""
    if event.attempted_identifier:
        return event.attempted_identifier
    if event.user_id is not None:
        return f"uid:{event.user_id}"
    return None


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
        target_key = _resolve_target_key(r)
        if target_key:
            distinct_targets.add(target_key)

    return {
        "distinct_accounts": len(distinct_targets),
        "total_attempts": len(rows),
        "unknown_account_attempts": unknown_count,
    }


def summarize_password_spray_window(
    since: Optional[datetime] = None,
    max_attempts_per_account: int = 2,
) -> Dict[str, Any]:
    """
    Summarize cross-account failed login distribution within a bounded time window
    using safe signals (account distribution, source patterns, and non-secret metadata).
    """
    query = SecurityEvent.query.filter(
        SecurityEvent.event_type.in_([EVENT_LOGIN_FAILURE, EVENT_LOGIN_BLOCKED])
    )
    if since is not None:
        query = query.filter(SecurityEvent.timestamp >= since)

    rows = query.all()
    if not rows:
        return {
            "distinct_accounts": 0,
            "low_attempt_accounts": 0,
            "existing_accounts_targeted": 0,
            "total_attempts": 0,
            "avg_attempts_per_account": 0.0,
            "max_attempts_per_account_observed": 0,
            "distinct_source_ips": 0,
            "primary_source_ip": None,
            "dominant_user_agent_ratio": 0.0,
            "matched_metadata_tags": [],
            "max_metadata_accounts": 0,
        }

    account_attempts: Dict[str, int] = {}
    existing_targets = set()
    ip_counts: Dict[str, int] = {}
    ua_counts: Dict[str, int] = {}
    metadata_targets: Dict[str, set] = {}

    for r in rows:
        target_key = _resolve_target_key(r)
        if target_key:
            account_attempts[target_key] = account_attempts.get(target_key, 0) + 1
            if r.user_id is not None:
                existing_targets.add(target_key)

        if r.source_ip:
            ip_counts[r.source_ip] = ip_counts.get(r.source_ip, 0) + 1

        if r.user_agent:
            ua_counts[r.user_agent] = ua_counts.get(r.user_agent, 0) + 1

        if isinstance(r.details, dict) and target_key:
            for meta_key in _SPRAY_METADATA_KEYS:
                meta_val = r.details.get(meta_key)
                if isinstance(meta_val, str) and meta_val.strip():
                    tag = f"{meta_key}={meta_val.strip()}"
                    metadata_targets.setdefault(tag, set()).add(target_key)

    distinct_accounts = len(account_attempts)
    low_attempt_accounts = sum(
        1 for count in account_attempts.values() if 1 <= count <= max(1, max_attempts_per_account)
    )
    total_attempts = len(rows)
    avg_attempts = round(total_attempts / distinct_accounts, 2) if distinct_accounts else 0.0
    max_observed = max(account_attempts.values()) if account_attempts else 0

    primary_source_ip = None
    if ip_counts:
        top_ip, top_ip_count = max(ip_counts.items(), key=lambda item: item[1])
        if top_ip_count / total_attempts >= 0.7:
            primary_source_ip = top_ip

    ua_total = sum(ua_counts.values())
    dominant_ua_ratio = round(max(ua_counts.values()) / ua_total, 2) if ua_total else 0.0

    matched_tags = [
        {"tag": tag, "distinct_accounts": len(targets)}
        for tag, targets in sorted(
            metadata_targets.items(), key=lambda item: len(item[1]), reverse=True
        )
        if len(targets) >= 2
    ][:5]
    max_metadata_accounts = max((len(t) for t in metadata_targets.values()), default=0)

    return {
        "distinct_accounts": distinct_accounts,
        "low_attempt_accounts": low_attempt_accounts,
        "existing_accounts_targeted": len(existing_targets),
        "total_attempts": total_attempts,
        "avg_attempts_per_account": avg_attempts,
        "max_attempts_per_account_observed": max_observed,
        "distinct_source_ips": len(ip_counts),
        "primary_source_ip": primary_source_ip,
        "dominant_user_agent_ratio": dominant_ua_ratio,
        "matched_metadata_tags": matched_tags,
        "max_metadata_accounts": max_metadata_accounts,
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
