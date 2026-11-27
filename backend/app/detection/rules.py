from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional


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

# Registries populated by individual detection rule steps (Steps 4.2–4.7)
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
