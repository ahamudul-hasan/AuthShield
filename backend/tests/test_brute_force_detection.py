from datetime import datetime, timedelta, timezone
import pytest
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.security_event import SecurityEvent, hash_attempted_identifier
from app.auth.password import hash_password
from app.auth.session_manager import create_session
from app.detection.event_types import EVENT_LOGIN_FAILURE, EVENT_LOGIN_BLOCKED
from app.detection.event_collector import record_security_event, clear_recent_security_events
from app.detection.alert_manager import get_alerts, clear_alerts
from app.detection.risk_engine import SEVERITY_HIGH
from app.detection.rules import detect_brute_force


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


def test_normal_user_typos_below_threshold_do_not_alert(app):
    """Fewer than 5 failed attempts (normal user mistakes) must not trigger an alert."""
    with app.app_context():
        for _ in range(4):
            record_security_event(
                EVENT_LOGIN_FAILURE,
                user_id=101,
                source_ip="198.51.100.10",
                success=False,
            )

        assert len(get_alerts(alert_type="BRUTE_FORCE")) == 0


def test_five_failed_logins_create_high_severity_brute_force_alert(client, app):
    """
    Step 4.2 Check:
    Generate five failed-login events within 5 minutes and verify a HIGH severity
    BRUTE_FORCE alert is created with failure count and window evidence, visible to admins.
    """
    pwd = "guitar-notebook-winter-coffee"
    assert client.post("/api/auth/register", json={
        "username": "bf_target",
        "email": "bf_target@example.com",
        "password": pwd,
    }).status_code == 201

    # Generate 5 failed login attempts via API
    for _ in range(5):
        res = client.post("/api/auth/login", json={
            "username": "bf_target",
            "password": "WrongPassword!99",
        })
        assert res.status_code == 401

    alerts = get_alerts(alert_type="BRUTE_FORCE")
    assert len(alerts) >= 1
    alert = alerts[0]
    assert alert["alert_type"] == "BRUTE_FORCE"
    assert alert["severity"] == SEVERITY_HIGH
    assert alert["risk_score"] >= 60
    assert alert["evidence"]["failed_attempts"] == 5
    assert alert["evidence"]["window_minutes"] == 5

    # Verify admin can inspect created alert via /api/alerts and /api/dashboard/summary
    with app.app_context():
        admin = User(
            username="bf_admin",
            email="bf_admin@example.com",
            password_hash=hash_password("sunset-mountain-camera-coffee"),
            password_algorithm="argon2id",
            role="admin",
        )
        db.session.add(admin)
        db.session.commit()
        _, admin_token = create_session(admin.id, ip_address="127.0.0.1", user_agent="AdminConsole")

    admin_client = app.test_client()
    res_alerts = admin_client.get("/api/alerts", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_alerts.status_code == 200
    assert res_alerts.get_json()["total"] >= 1
    assert res_alerts.get_json()["alerts"][0]["alert_type"] == "BRUTE_FORCE"

    res_summary = admin_client.get("/api/dashboard/summary", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_summary.status_code == 200
    assert res_summary.get_json()["active_alerts"] >= 1


def test_login_blocked_events_during_lockout_keep_counting(client, app):
    """Continued attempts after lockout are recorded as LOGIN_BLOCKED and seen by detector."""
    pwd = "ocean-breeze-camera-coffee"
    assert client.post("/api/auth/register", json={
        "username": "lock_bf_user",
        "email": "lock_bf@example.com",
        "password": pwd,
    }).status_code == 201

    for _ in range(5):
        client.post("/api/auth/login", json={"username": "lock_bf_user", "password": "BadPassword1!"})

    # 6th and 7th attempts occur while locked -> LOGIN_BLOCKED (HTTP 403)
    for _ in range(2):
        res_locked = client.post("/api/auth/login", json={"username": "lock_bf_user", "password": "BadPassword2!"})
        assert res_locked.status_code == 403

    latest_alert = get_alerts(alert_type="BRUTE_FORCE")[0]
    assert latest_alert["evidence"]["failed_attempts"] == 7
    assert latest_alert["evidence"]["login_failures"] == 5
    assert latest_alert["evidence"]["login_blocked"] == 2


def test_non_existent_account_brute_force_detected_via_hmac_identifier(app):
    """Repeated attempts on an unknown username trigger alert using attempted_identifier."""
    with app.app_context():
        for _ in range(5):
            record_security_event(
                EVENT_LOGIN_FAILURE,
                user_id=None,
                raw_identifier="phantom_admin_account",
                source_ip="203.0.113.88",
                success=False,
            )

        alerts = get_alerts(alert_type="BRUTE_FORCE")
        assert len(alerts) == 1
        assert alerts[0]["target_user_id"] is None
        assert alerts[0]["evidence"]["failed_attempts"] == 5


def test_failures_outside_time_window_are_excluded(app):
    """Old failures outside the 5-minute window must not combine with recent typos to false-alert."""
    with app.app_context():
        old_time = datetime.now(timezone.utc) - timedelta(minutes=10)
        uid = 505
        for _ in range(4):
            db.session.add(SecurityEvent(
                event_type=EVENT_LOGIN_FAILURE,
                user_id=uid,
                source_ip="192.0.2.50",
                timestamp=old_time,
                success=False,
                attempted_identifier=hash_attempted_identifier("old_user"),
                details={},
            ))
        db.session.commit()

        # 2 recent failures inside window -> total in window = 2 (< 5)
        for _ in range(2):
            ev = record_security_event(
                EVENT_LOGIN_FAILURE,
                user_id=uid,
                source_ip="192.0.2.50",
                success=False,
            )
        assert detect_brute_force(ev) is None
        assert len(get_alerts(alert_type="BRUTE_FORCE")) == 0


def test_configurable_brute_force_thresholds(app):
    """Brute-force threshold and window respect Flask app configuration."""
    app.config["BRUTE_FORCE_THRESHOLD"] = 3
    app.config["BRUTE_FORCE_WINDOW_MINUTES"] = 10

    with app.app_context():
        for _ in range(3):
            record_security_event(
                EVENT_LOGIN_FAILURE,
                user_id=909,
                source_ip="198.51.100.77",
                success=False,
            )

        alerts = get_alerts(alert_type="BRUTE_FORCE")
        assert len(alerts) == 1
        assert alerts[0]["evidence"]["threshold"] == 3
        assert alerts[0]["evidence"]["window_minutes"] == 10
        assert alerts[0]["evidence"]["failed_attempts"] == 3
