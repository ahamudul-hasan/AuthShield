from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional
from flask import current_app, has_app_context
from app.detection.event_types import EVENT_LOGIN_FAILURE, EVENT_LOGIN_BLOCKED
from app.detection.event_repository import (
    count_account_login_failures,
    count_ip_distinct_targets,
)


@dataclass
class DetectionFinding:
    """Structured finding produced by an individual detection rule."""

    rule_name: str
    alert_type: str
    description: str
    base_points: int
    source_ip: Optional[str] = None
    target_user_id: Optional[int] = None
    attempted_identifier: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


TargetedRuleFn = Callable[[Dict[str, Any]], Optional[DetectionFinding]]
SweepRuleFn = Callable[[], List[DetectionFinding]]

# Registries populated by detection rules
_TARGETED_RULES: List[TargetedRuleFn] = []
_SWEEP_RULES: List[SweepRuleFn] = []


def register_targeted_rule(fn: TargetedRuleFn) -> TargetedRuleFn:
    """Register a rule that inspects targeted account/IP activity after an event."""
    if fn not in _TARGETED_RULES:
        _TARGETED_RULES.append(fn)
    return fn


def register_sweep_rule(fn: SweepRuleFn) -> SweepRuleFn:
    """Register a periodic window-based rule executed during scheduled sweeps."""
    if fn not in _SWEEP_RULES:
        _SWEEP_RULES.append(fn)
    return fn


def get_registered_rules() -> Dict[str, List[str]]:
    """Return names of all registered targeted and sweep detection rules."""
    return {
        "targeted": [fn.__name__ for fn in _TARGETED_RULES],
        "sweep": [fn.__name__ for fn in _SWEEP_RULES],
    }


@register_targeted_rule
def detect_brute_force(event_payload: Dict[str, Any]) -> Optional[DetectionFinding]:
    """
    Step 4.2 — Brute-force detection rule:
    Detects repeated failed login attempts (LOGIN_FAILURE and LOGIN_BLOCKED)
    against one account within a configurable time window.
    Default: 5 failures within 5 minutes -> HIGH severity alert (>= 60 points).
    """
    if event_payload.get("event_type") not in (EVENT_LOGIN_FAILURE, EVENT_LOGIN_BLOCKED):
        return None

    user_id = event_payload.get("user_id")
    attempted_identifier = event_payload.get("attempted_identifier")
    if user_id is None and not attempted_identifier:
        return None

    if has_app_context():
        threshold = int(current_app.config.get("BRUTE_FORCE_THRESHOLD", 5))
        window_minutes = int(current_app.config.get("BRUTE_FORCE_WINDOW_MINUTES", 5))
        points = int(current_app.config.get("BRUTE_FORCE_POINTS", 60))
    else:
        threshold = 5
        window_minutes = 5
        points = 60

    since = datetime.now(timezone.utc) - timedelta(minutes=max(1, window_minutes))
    counts = count_account_login_failures(
        user_id=user_id,
        attempted_identifier=attempted_identifier,
        since=since,
    )

    total_failures = counts["total_failures"]
    if total_failures < max(1, threshold):
        return None

    return DetectionFinding(
        rule_name="brute_force_account",
        alert_type="BRUTE_FORCE",
        description=(
            f"Repeated failed login attempts detected: {total_failures} failed "
            f"or blocked attempts within {window_minutes} minute(s)."
        ),
        base_points=points,
        source_ip=event_payload.get("source_ip"),
        target_user_id=user_id,
        attempted_identifier=attempted_identifier,
        evidence={
            "failed_attempts": total_failures,
            "login_failures": counts["login_failures"],
            "login_blocked": counts["login_blocked"],
            "threshold": threshold,
            "window_minutes": window_minutes,
            "distinct_source_ips": counts["distinct_source_ips"],
        },
    )


@register_targeted_rule
def detect_credential_stuffing(event_payload: Dict[str, Any]) -> Optional[DetectionFinding]:
    """
    Step 4.3 — Credential-stuffing detection rule:
    Detects one source IP attempting logins across many distinct accounts
    (including non-existent accounts via HMAC attempted_identifier) within a window.
    Default: 10 distinct accounts within 10 minutes -> MEDIUM severity indicator (40 points).
    """
    if event_payload.get("event_type") not in (EVENT_LOGIN_FAILURE, EVENT_LOGIN_BLOCKED):
        return None

    source_ip = event_payload.get("source_ip")
    if not source_ip:
        return None

    if has_app_context():
        threshold = int(current_app.config.get("CREDENTIAL_STUFFING_THRESHOLD", 10))
        window_minutes = int(current_app.config.get("CREDENTIAL_STUFFING_WINDOW_MINUTES", 10))
        points = int(current_app.config.get("CREDENTIAL_STUFFING_POINTS", 40))
    else:
        threshold = 10
        window_minutes = 10
        points = 40

    since = datetime.now(timezone.utc) - timedelta(minutes=max(1, window_minutes))
    stats = count_ip_distinct_targets(source_ip=source_ip, since=since)

    distinct_accounts = stats["distinct_accounts"]
    if distinct_accounts < max(1, threshold):
        return None

    return DetectionFinding(
        rule_name="credential_stuffing_ip",
        alert_type="CREDENTIAL_STUFFING",
        description=(
            f"Credential-stuffing indicator from {source_ip}: "
            f"{distinct_accounts} distinct accounts targeted within {window_minutes} minute(s)."
        ),
        base_points=points,
        source_ip=source_ip,
        target_user_id=None,
        attempted_identifier=None,
        evidence={
            "distinct_accounts": distinct_accounts,
            "total_attempts": stats["total_attempts"],
            "unknown_account_attempts": stats["unknown_account_attempts"],
            "threshold": threshold,
            "window_minutes": window_minutes,
        },
    )


def evaluate_targeted_rules(event_payload: Dict[str, Any]) -> List[DetectionFinding]:
    """Run all registered targeted rules scoped to the incoming event's account/IP."""
    findings: List[DetectionFinding] = []
    for rule_fn in _TARGETED_RULES:
        result = rule_fn(event_payload)
        if result is not None:
            findings.append(result)
    return findings


def evaluate_sweep_rules() -> List[DetectionFinding]:
    """Run all registered periodic sweep rules over recent bounded time windows."""
    findings: List[DetectionFinding] = []
    for rule_fn in _SWEEP_RULES:
        results = rule_fn()
        if results:
            findings.extend(results)
    return findings
