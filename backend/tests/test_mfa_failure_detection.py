from datetime import datetime, timedelta, timezone
import pyotp
import pytest
from app import create_app
from app.extensions import db
from app.models.security_event import SecurityEvent
from app.detection.event_types import EVENT_LOGIN_FAILURE, EVENT_MFA_FAILURE
from app.detection.event_collector import record_security_event, clear_recent_security_events
from app.detection.alert_manager import get_alerts, clear_alerts
from app.detection.risk_engine import SEVERITY_HIGH


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


def test_below_threshold_mfa_failures_do_not_alert(app):
    """Fewer than 5 MFA failures within 5 minutes must not create an MFA_FAILURE alert."""
    with app.app_context():
        for _ in range(4):
            record_security_event(
                EVENT_MFA_FAILURE,
                user_id=10,
                raw_identifier="mfa_safe_user",
                source_ip="198.51.100.40",
                success=False,
            )

        assert len(get_alerts(alert_type="MFA_FAILURE")) == 0


def test_password_failures_do_not_combine_with_mfa_failures(app):
    """
    Password failures and MFA failures are monitored independently:
    4 LOGIN_FAILURE + 1 MFA_FAILURE must not trigger MFA_FAILURE or BRUTE_FORCE.
    """
    with app.app_context():
        for _ in range(4):
            record_security_event(
                EVENT_LOGIN_FAILURE,
                user_id=22,
                raw_identifier="mfa_split_user",
                source_ip="198.51.100.41",
                success=False,
            )
        record_security_event(
            EVENT_MFA_FAILURE,
            user_id=22,
            raw_identifier="mfa_split_user",
            source_ip="198.51.100.41",
            success=False,
        )

        assert len(get_alerts(alert_type="MFA_FAILURE")) == 0
        assert len(get_alerts(alert_type="BRUTE_FORCE")) == 0


def test_five_mfa_failures_via_verify_mfa_endpoint_create_high_severity_alert(client, app):
    """
    Step 4.5 Check:
    5 incorrect /api/auth/verify-mfa attempts within 5 minutes create a HIGH-severity
    MFA_FAILURE alert (risk_score >= 60).
    """
    password = "copper-harbor-velvet-lantern"
    assert client.post(
        "/api/auth/register",
        json={"username": "mfa_victim", "email": "mfa_victim@example.com", "password": password},
    ).status_code == 201

    setup_res = client.post(
        "/api/auth/mfa/setup",
        json={"username": "mfa_victim", "password": password},
    )
    assert setup_res.status_code == 200
    setup_data = setup_res.get_json()
    raw_secret = setup_data["secret"]
    totp = pyotp.TOTP(raw_secret)

    enable_res = client.post(
        "/api/auth/mfa/enable",
        json={"setup_token": setup_data["setup_token"], "code": totp.now()},
    )
    assert enable_res.status_code == 200

    # Log in with valid password to receive pending mfa_token
    login_res = client.post(
        "/api/auth/login",
        json={"username": "mfa_victim", "password": password},
        environ_base={"REMOTE_ADDR": "203.0.113.90"},
    )
    assert login_res.status_code == 200
    mfa_token = login_res.get_json()["mfa_token"]

    bad_code = "000000" if totp.now() != "000000" else "111111"
    for _ in range(5):
        verify_res = client.post(
            "/api/auth/verify-mfa",
            json={"mfa_token": mfa_token, "code": bad_code},
            environ_base={"REMOTE_ADDR": "203.0.113.90"},
        )
        assert verify_res.status_code == 401

    alerts = get_alerts(alert_type="MFA_FAILURE")
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["alert_type"] == "MFA_FAILURE"
    assert alert["severity"] == SEVERITY_HIGH
    assert alert["risk_score"] >= 60
    assert alert["source_ip"] == "203.0.113.90"
    assert alert["event_count"] == 5
    assert alert["evidence"]["failed_attempts"] == 5
    assert alert["evidence"]["threshold"] == 5
    assert alert["evidence"]["window_minutes"] == 5


def test_mixed_mfa_endpoints_accumulate_and_report_endpoints(app):
    """MFA failures across verify_mfa and recovery_login accumulate for the account."""
    with app.app_context():
        for idx in range(3):
            record_security_event(
                EVENT_MFA_FAILURE,
                user_id=33,
                source_ip="203.0.113.91",
                success=False,
                details={"reason": "invalid_code"},
            )
        for idx in range(2):
            record_security_event(
                EVENT_MFA_FAILURE,
                user_id=33,
                source_ip="203.0.113.92",
                success=False,
                details={"endpoint": "recovery_login", "reason": "invalid_recovery"},
            )

        alerts = get_alerts(alert_type="MFA_FAILURE")
        assert len(alerts) == 1
        ev = alerts[0]["evidence"]
        assert ev["failed_attempts"] == 5
        assert ev["distinct_source_ips"] == 2
        assert ev["endpoints"] == ["recovery_login", "verify_mfa"]


def test_mfa_failure_window_expiry_and_configurable_threshold(app):
    """MFA failures outside the time window are ignored and thresholds are configurable."""
    with app.app_context():
        old_time = datetime.now(timezone.utc) - timedelta(minutes=10)
        for _ in range(5):
            db.session.add(
                SecurityEvent(
                    event_type=EVENT_MFA_FAILURE,
                    user_id=44,
                    source_ip="198.51.100.44",
                    timestamp=old_time,
                    success=False,
                    details={},
                )
            )
        db.session.commit()

        # One recent failure makes 1 recent + 5 stale = still < 5 within 5 min window
        record_security_event(
            EVENT_MFA_FAILURE,
            user_id=44,
            source_ip="198.51.100.44",
            success=False,
        )
        assert len(get_alerts(alert_type="MFA_FAILURE")) == 0

        # Lower threshold to 3 and add 2 more recent failures -> triggers HIGH alert
        app.config["MFA_FAILURE_THRESHOLD"] = 3
        for _ in range(2):
            record_security_event(
                EVENT_MFA_FAILURE,
                user_id=44,
                source_ip="198.51.100.44",
                success=False,
            )

        alerts = get_alerts(alert_type="MFA_FAILURE")
        assert len(alerts) == 1
        assert alerts[0]["severity"] == SEVERITY_HIGH
        assert alerts[0]["evidence"]["failed_attempts"] == 3
        assert alerts[0]["evidence"]["threshold"] == 3
