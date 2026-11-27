from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from app.detection.rules import DetectionFinding

# Alert store buffer (upgraded to PostgreSQL security_alerts table in Step 4.9)
_ALERTS: List[Dict[str, Any]] = []
_NEXT_ALERT_ID = 1


def build_incident_key(finding: DetectionFinding) -> str:
    """
    Build a deterministic grouping key for identifying incidents (Steps 4.9–4.10).
    """
    target = (
        str(finding.target_user_id)
        if finding.target_user_id is not None
        else (finding.attempted_identifier or "unknown")
    )
    source = finding.source_ip or "unknown"
    return f"{finding.alert_type}:{target}:{source}"


def process_findings(
    findings: List[DetectionFinding],
    risk_assessment: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Convert scored detection findings into security alerts and record them.
    """
    global _NEXT_ALERT_ID
    if not findings:
        return []

    created_or_updated: List[Dict[str, Any]] = []
    now_iso = datetime.now(timezone.utc).isoformat()

    for f in findings:
        alert = {
            "id": _NEXT_ALERT_ID,
            "incident_key": build_incident_key(f),
            "alert_type": f.alert_type,
            "severity": risk_assessment.get("severity", "LOW"),
            "risk_score": risk_assessment.get("risk_score", f.base_points),
            "source_ip": f.source_ip,
            "target_user_id": f.target_user_id,
            "description": f.description,
            "evidence": f.evidence,
            "status": "OPEN",
            "event_count": (
                f.evidence.get("failed_attempts")
                or f.evidence.get("total_attempts")
                or 1
            ),
            "first_seen": now_iso,
            "last_seen": now_iso,
            "created_at": now_iso,
        }
        _NEXT_ALERT_ID += 1
        _ALERTS.append(alert)
        if len(_ALERTS) > 500:
            _ALERTS.pop(0)
        created_or_updated.append(alert)

    return created_or_updated


def get_alerts(
    status: Optional[str] = None,
    alert_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return stored alerts newest-first, optionally filtered by status or alert_type."""
    results = list(reversed(_ALERTS))
    if status:
        results = [a for a in results if a["status"].upper() == status.upper()]
    if alert_type:
        results = [a for a in results if a["alert_type"].upper() == alert_type.upper()]
    return results


def count_active_alerts() -> int:
    """Return count of alerts currently OPEN or INVESTIGATING."""
    return sum(1 for a in _ALERTS if a["status"] in ("OPEN", "INVESTIGATING"))


def clear_alerts() -> None:
    """Clear stored alerts (useful for isolated tests)."""
    global _NEXT_ALERT_ID
    _ALERTS.clear()
    _NEXT_ALERT_ID = 1
