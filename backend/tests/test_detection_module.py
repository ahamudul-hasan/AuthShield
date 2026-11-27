import pytest
from app import create_app
from app.extensions import db
import app.detection as detection
from app.detection import (
    analyze_event,
    run_periodic_sweep,
    init_detection_scheduler,
    stop_detection_scheduler,
    DetectionFinding,
    calculate_risk,
    classify_severity,
    process_findings,
    build_incident_key,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)
from app.detection import rules as rules_module
from app.detection.event_types import EVENT_LOGIN_FAILURE, EVENT_USER_REGISTERED
from app.detection.event_collector import record_security_event, clear_recent_security_events


@pytest.fixture
def app():
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        clear_recent_security_events()
        yield app
        stop_detection_scheduler()
        db.session.remove()
        db.drop_all()
        clear_recent_security_events()


def test_import_detection_module_without_frontend():
    """Step 4.1 Check: Detection package and submodules import cleanly standalone."""
    assert hasattr(detection, "analyze_event")
    assert hasattr(detection, "run_periodic_sweep")
    assert hasattr(detection, "DetectionFinding")
    assert hasattr(detection, "calculate_risk")
    assert hasattr(detection, "process_findings")


def test_analyze_event_ignores_non_trigger_events():
    """Non-trigger events (e.g. USER_REGISTERED) must not invoke rule scans."""
    res = analyze_event({"event_type": EVENT_USER_REGISTERED, "source_ip": "127.0.0.1"})
    assert res["analyzed"] is False
    assert res["reason"] == "non_trigger_event"
    assert res["alerts"] == []


def test_risk_scoring_bands_and_clamping():
    """Risk engine clamps scores to 0–100, deduplicates rules, and maps severity bands."""
    assert classify_severity(0) == SEVERITY_LOW
    assert classify_severity(29) == SEVERITY_LOW
    assert classify_severity(30) == SEVERITY_MEDIUM
    assert classify_severity(59) == SEVERITY_MEDIUM
    assert classify_severity(60) == SEVERITY_HIGH
    assert classify_severity(79) == SEVERITY_HIGH
    assert classify_severity(80) == SEVERITY_CRITICAL
    assert classify_severity(150) == SEVERITY_CRITICAL

    findings = [
        DetectionFinding(rule_name="rule_a", alert_type="BRUTE_FORCE", description="A", base_points=60),
        DetectionFinding(rule_name="rule_a", alert_type="BRUTE_FORCE", description="Dup", base_points=60),
        DetectionFinding(rule_name="rule_b", alert_type="SUCCESS_AFTER_FAIL", description="B", base_points=60),
    ]
    risk = calculate_risk(findings)
    # Clamped at 100, deduplicated rule_a
    assert risk["risk_score"] == 100
    assert risk["severity"] == SEVERITY_CRITICAL
    assert len(risk["signals"]) == 2


def test_targeted_and_sweep_rule_pipeline(app, monkeypatch):
    """Targeted rules run on trigger events; sweep rules run during periodic sweeps."""
    sample_targeted_calls = []

    def fake_targeted_rule(payload):
        sample_targeted_calls.append(payload)
        return DetectionFinding(
            rule_name="mock_brute_force",
            alert_type="BRUTE_FORCE",
            description="Repeated test failures",
            base_points=65,
            source_ip=payload.get("source_ip"),
            target_user_id=payload.get("user_id"),
            evidence={"count": 5},
        )

    def fake_sweep_rule():
        return [
            DetectionFinding(
                rule_name="mock_distributed",
                alert_type="DISTRIBUTED_ATTACK",
                description="Distributed probe",
                base_points=35,
                target_user_id=42,
                evidence={"distinct_ips": 4},
            )
        ]

    monkeypatch.setattr(rules_module, "_TARGETED_RULES", [fake_targeted_rule])
    monkeypatch.setattr(rules_module, "_SWEEP_RULES", [fake_sweep_rule])

    # Recording a failure triggers targeted analysis automatically via collector hook
    with app.app_context():
        ev = record_security_event(
            EVENT_LOGIN_FAILURE,
            user_id=7,
            source_ip="203.0.113.5",
            success=False,
        )
        assert len(sample_targeted_calls) == 1
        assert sample_targeted_calls[0]["id"] == ev["id"]

        targeted_out = analyze_event(ev)
        assert targeted_out["analyzed"] is True
        assert targeted_out["severity"] == SEVERITY_HIGH
        assert targeted_out["alerts"][0]["incident_key"] == "BRUTE_FORCE:7:203.0.113.5"

        sweep_out = run_periodic_sweep()
        assert sweep_out["swept"] is True
        assert sweep_out["findings_count"] == 1
        assert sweep_out["severity"] == SEVERITY_MEDIUM


def test_scheduler_and_cli_sweep_command(app):
    """APScheduler starts/stops cleanly and CLI run-detector-sweep executes."""
    scheduler = init_detection_scheduler(app)
    assert scheduler is not None
    assert scheduler.running is True
    assert scheduler.get_job("detector_periodic_sweep") is not None
    stop_detection_scheduler()

    runner = app.test_cli_runner()
    res = runner.invoke(args=["run-detector-sweep"])
    assert res.exit_code == 0
    assert "Detector sweep complete" in res.output
