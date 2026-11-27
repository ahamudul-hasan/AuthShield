from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional
from flask import current_app, has_app_context
from app.detection.event_types import EVENT_LOGIN_FAILURE, EVENT_LOGIN_BLOCKED
from app.detection.event_repository import (
    count_account_login_failures,
    count_ip_distinct_targets,
    summarize_password_spray_window,
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


@register_sweep_rule
def detect_password_spraying() -> List[DetectionFinding]:
    """
    Step 4.4 — Password-spraying indicator rule (periodic sweep):
    Detects low-and-slow failed login fan-out across many distinct accounts
    (staying under per-account lockout thresholds) using safe behavioral signals:
    account distribution, source/User-Agent patterns, and controlled test metadata.
    Never inspects or stores plaintext passwords.
    """
    if has_app_context():
        threshold = max(2, int(current_app.config.get("PASSWORD_SPRAY_THRESHOLD", 6)))
        window_minutes = max(1, int(current_app.config.get("PASSWORD_SPRAY_WINDOW_MINUTES", 15)))
        max_per_account = max(1, int(current_app.config.get("PASSWORD_SPRAY_MAX_ATTEMPTS_PER_ACCOUNT", 2)))
        points = int(current_app.config.get("PASSWORD_SPRAY_POINTS", 45))
    else:
        threshold = 6
        window_minutes = 15
        max_per_account = 2
        points = 45

    since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    stats = summarize_password_spray_window(
        since=since,
        max_attempts_per_account=max_per_account,
    )

    low_attempt_accounts = stats["low_attempt_accounts"]
    avg_attempts = stats["avg_attempts_per_account"]
    max_avg_allowed = max(2.5, float(max_per_account) + 0.5)

    # Low-and-slow fan-out requires many thinly targeted accounts rather than single-account brute force
    if low_attempt_accounts < threshold or avg_attempts > max_avg_allowed:
        return []

    distinct_ips = stats["distinct_source_ips"]
    shared_ip_concentration = (
        distinct_ips == 1
        or (distinct_ips > 0 and (low_attempt_accounts / distinct_ips) >= 2.0)
    )
    uniform_client_signal = stats["dominant_user_agent_ratio"] >= 0.7
    existing_account_focus = stats["existing_accounts_targeted"] >= max(2, threshold // 2)
    metadata_signal = stats["max_metadata_accounts"] >= max(3, threshold // 2)

    signals_present = [
        name
        for name, active in (
            ("low_per_account_distribution", True),
            ("concentrated_source_ips", shared_ip_concentration),
            ("uniform_user_agent", uniform_client_signal),
            ("existing_account_targeting", existing_account_focus),
            ("controlled_test_metadata", metadata_signal),
        )
        if active
    ]

    # Require at least one corroborating source/distribution/metadata signal beyond account count alone
    if len(signals_present) < 2:
        return []

    return [
        DetectionFinding(
            rule_name="password_spraying_sweep",
            alert_type="PASSWORD_SPRAY",
            description=(
                f"Password-spraying indicator: {low_attempt_accounts} distinct accounts "
                f"averaged {avg_attempts} failed attempts across {distinct_ips} source IP(s) "
                f"within {window_minutes} minute(s)."
            ),
            base_points=points,
            source_ip=stats["primary_source_ip"],
            target_user_id=None,
            attempted_identifier=None,
            evidence={
                "distinct_accounts": stats["distinct_accounts"],
                "low_attempt_accounts": low_attempt_accounts,
                "existing_accounts_targeted": stats["existing_accounts_targeted"],
                "total_attempts": stats["total_attempts"],
                "avg_attempts_per_account": avg_attempts,
                "max_attempts_per_account_observed": stats["max_attempts_per_account_observed"],
                "distinct_source_ips": distinct_ips,
                "dominant_user_agent_ratio": stats["dominant_user_agent_ratio"],
                "matched_metadata_tags": stats["matched_metadata_tags"],
                "safe_signals": signals_present,
                "threshold": threshold,
                "window_minutes": window_minutes,
            },
        )
    ]


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
