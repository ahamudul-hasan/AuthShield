import logging
from typing import Any, Dict, List, Optional
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, current_app, has_app_context
from app.detection.event_types import (
    EVENT_LOGIN_FAILURE,
    EVENT_MFA_FAILURE,
    EVENT_LOGIN_BLOCKED,
    EVENT_ACCOUNT_LOCKED,
    EVENT_LOGIN_SUCCESS,
)
from app.detection.rules import evaluate_targeted_rules, evaluate_sweep_rules
from app.detection.risk_engine import calculate_risk
from app.detection.alert_manager import process_findings

logger = logging.getLogger("authshield.detector")

# Events that trigger immediate targeted rule analysis on the affected account/IP
TARGETED_TRIGGER_EVENTS = frozenset({
    EVENT_LOGIN_FAILURE,
    EVENT_MFA_FAILURE,
    EVENT_LOGIN_BLOCKED,
    EVENT_ACCOUNT_LOCKED,
    EVENT_LOGIN_SUCCESS,
})

_SCHEDULER: Optional[BackgroundScheduler] = None


def analyze_event(event_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Targeted real-time detection pipeline.
    Runs only after relevant failure or auth trigger events, scoped strictly to
    the affected user/identifier and source IP over bounded time windows.
    Never scans the entire security_events table.
    """
    event_type = event_payload.get("event_type")
    if event_type not in TARGETED_TRIGGER_EVENTS:
        return {"analyzed": False, "reason": "non_trigger_event", "alerts": []}

    findings = evaluate_targeted_rules(event_payload)
    if not findings:
        return {"analyzed": True, "findings_count": 0, "alerts": []}

    risk_assessment = calculate_risk(findings)
    alerts = process_findings(findings, risk_assessment)

    return {
        "analyzed": True,
        "findings_count": len(findings),
        "risk_score": risk_assessment["risk_score"],
        "severity": risk_assessment["severity"],
        "alerts": alerts,
    }


def run_periodic_sweep(app: Optional[Flask] = None) -> Dict[str, Any]:
    """
    Periodic window-based detection sweep (e.g. every 60 seconds via APScheduler or CLI).
    Evaluates cross-account and distributed patterns over bounded recent time windows.
    """
    if app is not None and not has_app_context():
        with app.app_context():
            return _execute_sweep()
    return _execute_sweep()


def _execute_sweep() -> Dict[str, Any]:
    findings = evaluate_sweep_rules()
    if not findings:
        return {"swept": True, "findings_count": 0, "alerts": []}

    risk_assessment = calculate_risk(findings)
    alerts = process_findings(findings, risk_assessment)

    return {
        "swept": True,
        "findings_count": len(findings),
        "risk_score": risk_assessment["risk_score"],
        "severity": risk_assessment["severity"],
        "alerts": alerts,
    }


def init_detection_scheduler(app: Flask) -> Optional[BackgroundScheduler]:
    """
    Initialize APScheduler background job to run periodic detection sweeps.
    Avoids duplicate startup under Flask's debug reloader parent process.
    """
    global _SCHEDULER
    if _SCHEDULER is not None and _SCHEDULER.running:
        return _SCHEDULER

    interval_seconds = int(app.config.get("DETECTOR_SWEEP_INTERVAL_SECONDS", 60))
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(
        func=run_periodic_sweep,
        args=[app],
        trigger="interval",
        seconds=max(5, interval_seconds),
        id="detector_periodic_sweep",
        replace_existing=True,
    )
    scheduler.start()
    _SCHEDULER = scheduler
    logger.info("Detection sweep scheduler started (interval=%ss).", interval_seconds)
    return scheduler


def stop_detection_scheduler() -> None:
    """Gracefully shut down the detection background scheduler if running."""
    global _SCHEDULER
    if _SCHEDULER is not None:
        if _SCHEDULER.running:
            _SCHEDULER.shutdown(wait=False)
        _SCHEDULER = None
