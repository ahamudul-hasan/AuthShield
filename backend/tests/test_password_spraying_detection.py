from datetime import datetime, timedelta, timezone
from app import create_app
from app.extensions import db
from app.models.security_event import SecurityEvent
from app.detection.event_types import EVENT_LOGIN_FAILURE
from app.detection.event_collector import record_security_event, clear_recent_security_events
from app.detection.detector import run_periodic_sweep
from app.detection.alert_manager import get_alerts, clear_alerts
from app.detection.risk_engine import SEVERITY_MEDIUM
import pytest


@pytest.fixture
def app():
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        clear_alerts()
        clear_recent_security_events()
        yield app
        clear_alerts()
        clear_recent_security_events()
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_distributed_low_and_slow_spray_evades_lockout_but_triggers_sweep(client, app):
    """
    Step 4.4 Check:
    1 failed attempt each across 6 registered accounts spread across 3 IPs avoids
    per-account BRUTE_FORCE (5/account) and single-IP CREDENTIAL_STUFFING (10/IP),
    yet triggers PASSWORD_SPRAY during run_periodic_sweep().
    """
    for idx in range(6):
        res = client.post(
            "/api/auth/register",
            json={
                "username": f"spray_victim_{idx}",
                "email": f"spray_victim_{idx}@example.com",
                "password": "autumn-river-lantern-glass",
            },
        )
        assert res.status_code == 201

    ips = ["203.0.113.10", "203.0.113.11", "203.0.113.12"]
    for idx in range(6):
        resp = client.post(
            "/api/auth/login",
            json={"username": f"spray_victim_{idx}", "password": "Spring2026!Wrong"},
            environ_base={"REMOTE_ADDR": ips[idx % len(ips)]},
            headers={"User-Agent": "SprayAuditAgent/1.0"},
        )
        assert resp.status_code == 401

    # Neither brute force nor single-IP credential stuffing should have fired
    assert len(get_alerts(alert_type="BRUTE_FORCE")) == 0
    assert len(get_alerts(alert_type="CREDENTIAL_STUFFING")) == 0

    sweep_result = run_periodic_sweep()
    assert sweep_result["swept"] is True
    assert sweep_result["findings_count"] == 1
    assert sweep_result["severity"] == SEVERITY_MEDIUM

    alerts = get_alerts(alert_type="PASSWORD_SPRAY")
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["risk_score"] == 45
    assert alert["severity"] == SEVERITY_MEDIUM
    assert alert["event_count"] == 6
    assert alert["source_ip"] is None  # Distributed across 3 IPs
    assert alert["evidence"]["distinct_accounts"] == 6
    assert alert["evidence"]["low_attempt_accounts"] == 6
    assert alert["evidence"]["existing_accounts_targeted"] == 6
    assert alert["evidence"]["distinct_source_ips"] == 3
    assert alert["evidence"]["avg_attempts_per_account"] == 1.0


def test_controlled_test_metadata_signal_and_plaintext_password_exclusion(app):
    """
    Simulate password spraying using controlled test metadata without storing
    plaintext passwords; verify password fields remain redacted while spray metadata triggers.
    """
    with app.app_context():
        for idx in range(6):
            record_security_event(
                EVENT_LOGIN_FAILURE,
                raw_identifier=f"meta_target_{idx}",
                source_ip=f"198.51.100.{20 + idx}",
                user_agent=f"UniqueBrowser/{idx}.0",
                success=False,
                details={
                    "spray_cohort": "spring-audit-01",
                    "password": "NeverStoreMeInPlaintext!",
                },
            )

        # Ensure plaintext password is never persisted in SecurityEvent.details
        events = SecurityEvent.query.filter_by(event_type=EVENT_LOGIN_FAILURE).all()
        assert len(events) == 6
        for ev in events:
            assert ev.details.get("password") == "[REDACTED]"
            assert "NeverStoreMeInPlaintext!" not in str(ev.details)

        sweep_result = run_periodic_sweep()
        assert sweep_result["findings_count"] == 1
        alerts = get_alerts(alert_type="PASSWORD_SPRAY")
        assert len(alerts) == 1
        evidence = alerts[0]["evidence"]
        assert "controlled_test_metadata" in evidence["safe_signals"]
        assert evidence["matched_metadata_tags"] == [
            {"tag": "spray_cohort=spring-audit-01", "distinct_accounts": 6}
        ]


def test_unrelated_multi_ip_typos_without_corroboration_do_not_alert(app):
    """
    6 unrelated unknown-identifier typos from 6 different IPs and 6 distinct User-Agents
    without spray metadata lack corroborating source/distribution signals.
    """
    with app.app_context():
        for idx in range(6):
            record_security_event(
                EVENT_LOGIN_FAILURE,
                raw_identifier=f"typo_unknown_{idx}",
                source_ip=f"192.0.2.{10 + idx}",
                user_agent=f"DistinctClient/{idx}.0",
                success=False,
            )

        sweep_result = run_periodic_sweep()
        assert sweep_result["findings_count"] == 0
        assert len(get_alerts(alert_type="PASSWORD_SPRAY")) == 0


def test_single_account_brute_force_does_not_trigger_password_spray(app):
    """Many attempts against a single account must not trigger PASSWORD_SPRAY."""
    with app.app_context():
        for _ in range(10):
            record_security_event(
                EVENT_LOGIN_FAILURE,
                user_id=55,
                raw_identifier="single_target_user",
                source_ip="203.0.113.55",
                user_agent="Hydra/9.0",
                success=False,
            )

        sweep_result = run_periodic_sweep()
        assert sweep_result["findings_count"] == 0
        assert len(get_alerts(alert_type="PASSWORD_SPRAY")) == 0


def test_spray_window_expiry_and_configurable_threshold(app):
    """Expired spray events outside window are ignored and thresholds are configurable."""
    with app.app_context():
        old_time = datetime.now(timezone.utc) - timedelta(minutes=25)
        for idx in range(6):
            ev = SecurityEvent(
                event_type=EVENT_LOGIN_FAILURE,
                user_id=100 + idx,
                source_ip="203.0.113.77",
                user_agent="OldSprayBot/1.0",
                timestamp=old_time,
                success=False,
                details={},
            )
            db.session.add(ev)
        db.session.commit()

        # Outside default 15-minute window -> 0 findings
        assert run_periodic_sweep()["findings_count"] == 0

        # Configure lower threshold (3) and verify recent 3-account spray triggers
        app.config["PASSWORD_SPRAY_THRESHOLD"] = 3
        for idx in range(3):
            record_security_event(
                EVENT_LOGIN_FAILURE,
                user_id=200 + idx,
                raw_identifier=f"cfg_user_{idx}",
                source_ip="203.0.113.88",
                success=False,
            )

        res = run_periodic_sweep()
        assert res["findings_count"] == 1
        alerts = get_alerts(alert_type="PASSWORD_SPRAY")
        assert len(alerts) == 1
        assert alerts[0]["source_ip"] == "203.0.113.88"
        assert alerts[0]["evidence"]["threshold"] == 3
