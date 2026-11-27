from typing import Any, Dict, List
from app.detection.rules import DetectionFinding


def build_incident_key(finding: DetectionFinding) -> str:
    """
    Build a deterministic grouping key for deduplicating ongoing incidents (Steps 4.9–4.10).
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
    Handle scored detection findings.
    Full database persistence into security_alerts and deduplication will be added
    in Steps 4.9 and 4.10; returns structured alert previews for now.
    """
    if not findings:
        return []

    alert_previews: List[Dict[str, Any]] = []
    for f in findings:
        alert_previews.append({
            "incident_key": build_incident_key(f),
            "alert_type": f.alert_type,
            "severity": risk_assessment.get("severity", "LOW"),
            "risk_score": risk_assessment.get("risk_score", f.base_points),
            "source_ip": f.source_ip,
            "target_user_id": f.target_user_id,
            "description": f.description,
            "evidence": f.evidence,
            "status": "OPEN",
        })
    return alert_previews
