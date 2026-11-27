from typing import Any, Dict, List
from app.detection.rules import DetectionFinding

SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"


def classify_severity(score: int) -> str:
    """
    Map a bounded risk score (0–100) into an AuthShield severity band:
    0–29 LOW, 30–59 MEDIUM, 60–79 HIGH, 80–100 CRITICAL.
    """
    clamped = max(0, min(int(score), 100))
    if clamped >= 80:
        return SEVERITY_CRITICAL
    if clamped >= 60:
        return SEVERITY_HIGH
    if clamped >= 30:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW


def calculate_risk(findings: List[DetectionFinding]) -> Dict[str, Any]:
    """
    Aggregate unique rule findings into a bounded risk score (0–100),
    severity label, and contributing signal breakdown.
    """
    if not findings:
        return {
            "risk_score": 0,
            "severity": SEVERITY_LOW,
            "signals": [],
        }

    # Deduplicate by rule_name so the same signal is not double-counted in one evaluation
    seen_rules = set()
    total_points = 0
    signals: List[Dict[str, Any]] = []

    for f in findings:
        if f.rule_name in seen_rules:
            continue
        seen_rules.add(f.rule_name)
        pts = max(0, int(f.base_points))
        total_points += pts
        signals.append({
            "rule": f.rule_name,
            "alert_type": f.alert_type,
            "points": pts,
        })

    bounded_score = max(0, min(total_points, 100))
    return {
        "risk_score": bounded_score,
        "severity": classify_severity(bounded_score),
        "signals": signals,
    }
