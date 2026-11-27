"""AuthShield 2.0 security-event collection and threat-detection package."""
from app.detection.detector import (
    analyze_event,
    run_periodic_sweep,
    init_detection_scheduler,
    stop_detection_scheduler,
    TARGETED_TRIGGER_EVENTS,
)
from app.detection.rules import (
    DetectionFinding,
    register_targeted_rule,
    register_sweep_rule,
    get_registered_rules,
)
from app.detection.risk_engine import (
    calculate_risk,
    classify_severity,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)
from app.detection.alert_manager import (
    process_findings,
    build_incident_key,
    get_alerts,
    count_active_alerts,
    clear_alerts,
)

__all__ = [
    "analyze_event",
    "run_periodic_sweep",
    "init_detection_scheduler",
    "stop_detection_scheduler",
    "TARGETED_TRIGGER_EVENTS",
    "DetectionFinding",
    "register_targeted_rule",
    "register_sweep_rule",
    "get_registered_rules",
    "calculate_risk",
    "classify_severity",
    "SEVERITY_LOW",
    "SEVERITY_MEDIUM",
    "SEVERITY_HIGH",
    "SEVERITY_CRITICAL",
    "process_findings",
    "build_incident_key",
    "get_alerts",
    "count_active_alerts",
    "clear_alerts",
]
