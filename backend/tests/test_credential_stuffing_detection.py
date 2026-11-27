from datetime import datetime, timedelta, timezone
import pytest
from app import create_app
from app.extensions import db
from app.models.security_event import SecurityEvent, hash_attempted_identifier
from app.detection.event_types import EVENT_LOGIN_FAILURE
from app.detection.event_collector import record_security_event, clear_recent_security_events
from app.detection.alert_manager import get_alerts, clear_alerts
from app.detection.risk_engine import SEVERITY_MEDIUM


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


def test_below_threshold_distinct_accounts_do_not_alert(app):
    """Fewer than 10 distinct accounts from one IP must not trigger credential stuffing."""
    with app.app_context():
        for i in range(9):
            record_security_event(
                EVENT_LOGIN_FAILURE,
                raw_identifier=f"stuff_target_{i}",
                source_ip="203.0.113.10",
                success=False,
            )

        assert len(get_alerts(alert_type="CREDENTIAL_STUFFING")) == 0


def test_repeated_attempts_against_single_account_do_not_trigger_stuffing(app):
    """Multiple failures against ONE account trigger brute force, not credential stuffing."""
    with app.app_context():
        for _ in range(10):
            record_security_event(
                EVENT_LOGIN_FAILURE,
                user_id=77,
                raw_identifier="single_account",
                source_ip="203.0.113.11",
                success=False,
            )

        assert len(get_alerts(alert_type="CREDENTIAL_STUFFING")) == 0
        assert len(get_alerts(alert_type="BRUTE_FORCE")) >= 1


def test_ten_distinct_accounts_from_same_ip_trigger_credential_stuffing(client, app):
    """
    Step 4.3 Check:
    Generate failed-login events across 10 distinct accounts (including unknown accounts)
    from one simulated source IP and verify a CREDENTIAL_STUFFING alert is created.
    """
    # Register 2 real accounts; other 8 attempts target non-existent accounts
    for idx in range(2):
        assert client.post("/api/auth/register", json={
            "username": f"real_victim_{idx}",
            "email": f"real_victim_{idx}@example.com",
            "password": "guitar-notebook-winter-coffee",
        }).status_code == 201

    attacker_ip = "198.51.100.200"
    usernames = [f"real_victim_{i}" for i in range(2)] + [f"leaked_user_{i}" for i in range(8)]

    for uname in usernames:
        res = client.post(
            "/api/auth/login",
            json={"username": uname, "password": "LeakedPassword!2026"},
            environ_base={"REMOTE_ADDR": attacker_ip},
        )
        assert res.status_code == 401

    alerts = get_alerts(alert_type="CREDENTIAL_STUFFING")
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["alert_type"] == "CREDENTIAL_STUFFING"
    assert alert["severity"] == SEVERITY_MEDIUM
    assert alert["risk_score"] >= 40
    assert alert["source_ip"] == attacker_ip
    assert alert["evidence"]["distinct_accounts"] == 10
    assert alert["evidence"]["unknown_account_attempts"] == 8
    assert alert["evidence"]["window_minutes"] == 10


def test_attempts_from_different_ips_do_not_combine_into_single_ip_stuffing(app):
    """5 accounts from IP A and 5 accounts from IP B should not trigger IP stuffing."""
    with app.app_context():
        for i in range(5):
            record_security_event(
                EVENT_LOGIN_FAILURE,
                raw_identifier=f"user_a_{i}",
                source_ip="192.0.2.10",
                success=False,
            )
            record_security_event(
                EVENT_LOGIN_FAILURE,
                raw_identifier=f"user_b_{i}",
                source_ip="192.0.2.11",
                success=False,
            )

        assert len(get_alerts(alert_type="CREDENTIAL_STUFFING")) == 0


def test_old_attempts_outside_window_are_excluded(app):
    """Attempts older than the 10-minute window must not combine with recent ones."""
    with app.app_context():
        old_time = datetime.now(timezone.utc) - timedelta(minutes=15)
        for i in range(6):
            db.session.add(SecurityEvent(
                event_type=EVENT_LOGIN_FAILURE,
                source_ip="203.0.113.77",
                timestamp=old_time,
                success=False,
                attempted_identifier=hash_attempted_identifier(f"old_acct_{i}"),
                details={},
            ))
        db.session.commit()

        # 5 recent failures from same IP -> only 5 distinct in window (< 10)
        for i in range(5):
            record_security_event(
                EVENT_LOGIN_FAILURE,
                raw_identifier=f"recent_acct_{i}",
                source_ip="203.0.113.77",
                success=False,
            )

        assert len(get_alerts(alert_type="CREDENTIAL_STUFFING")) == 0


def test_configurable_credential_stuffing_threshold(app):
    """Credential stuffing respects custom app config threshold and window."""
    app.config["CREDENTIAL_STUFFING_THRESHOLD"] = 4
    app.config["CREDENTIAL_STUFFING_WINDOW_MINUTES"] = 15

    with app.app_context():
        for i in range(4):
            record_security_event(
                EVENT_LOGIN_FAILURE,
                raw_identifier=f"cfg_acct_{i}",
                source_ip="198.51.100.99",
                success=False,
            )

        alerts = get_alerts(alert_type="CREDENTIAL_STUFFING")
        assert len(alerts) == 1
        assert alerts[0]["evidence"]["threshold"] == 4
        assert alerts[0]["evidence"]["window_minutes"] == 15
        assert alerts[0]["evidence"]["distinct_accounts"] == 4
