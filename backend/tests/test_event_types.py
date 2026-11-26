import re
from pathlib import Path
import pytest
import pyotp
from app import create_app
from app.extensions import db
from app.models.user import User
from app.auth.password import hash_password
from app.auth.session_manager import create_session
from app.detection.event_types import (
    ALL_EVENT_TYPES,
    EVENT_DESCRIPTIONS,
    is_valid_event_type,
    EVENT_LOGIN_SUCCESS,
    EVENT_LOGIN_FAILURE,
    EVENT_MFA_SUCCESS,
    EVENT_MFA_FAILURE,
    EVENT_ACCOUNT_LOCKED,
    EVENT_PASSWORD_RESET_REQUESTED,
    EVENT_PASSWORD_RESET_COMPLETED,
    EVENT_SESSION_CREATED,
    EVENT_SESSION_REVOKED,
    EVENT_MFA_ENABLED,
    EVENT_MFA_DISABLED,
    EVENT_ADMIN_ACTION,
    EVENT_IP_BLOCKED,
    EVENT_IP_UNBLOCKED,
    EVENT_USER_REGISTERED,
    EVENT_LOGIN_BLOCKED,
    EVENT_RATE_LIMITED,
    EVENT_PASSWORD_CHANGED,
    EVENT_RECOVERY_CODE_USED,
)
from app.detection.events import (
    record_security_event,
    get_recent_security_events,
    clear_recent_security_events,
)


@pytest.fixture
def app():
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        clear_recent_security_events()
        yield app
        db.session.remove()
        db.drop_all()
        clear_recent_security_events()


@pytest.fixture
def client(app):
    return app.test_client()


def test_all_19_canonical_event_types_defined():
    """Confirm all 19 canonical event names from Step 3.1 are defined and validated."""
    expected = {
        "LOGIN_SUCCESS",
        "LOGIN_FAILURE",
        "MFA_SUCCESS",
        "MFA_FAILURE",
        "ACCOUNT_LOCKED",
        "PASSWORD_RESET_REQUESTED",
        "PASSWORD_RESET_COMPLETED",
        "SESSION_CREATED",
        "SESSION_REVOKED",
        "MFA_ENABLED",
        "MFA_DISABLED",
        "ADMIN_ACTION",
        "IP_BLOCKED",
        "IP_UNBLOCKED",
        "USER_REGISTERED",
        "LOGIN_BLOCKED",
        "RATE_LIMITED",
        "PASSWORD_CHANGED",
        "RECOVERY_CODE_USED",
    }
    assert ALL_EVENT_TYPES == expected
    assert set(EVENT_DESCRIPTIONS.keys()) == expected
    for name in expected:
        assert is_valid_event_type(name) is True

    assert is_valid_event_type("INVENTED_AD_HOC_EVENT") is False
    with pytest.raises(ValueError, match="Unknown security event type"):
        record_security_event("INVENTED_AD_HOC_EVENT")


def test_auth_routes_emit_canonical_login_lockout_and_session_events(client):
    """Verify registration, login, logout, failure, lockout, and blocked events use shared names."""
    pwd = "guitar-notebook-winter-coffee"

    # 1. Registration -> USER_REGISTERED
    assert client.post("/api/auth/register", json={
        "username": "evt_user",
        "email": "evt_user@example.com",
        "password": pwd,
    }).status_code == 201

    # 2. Login -> SESSION_CREATED, LOGIN_SUCCESS
    res_login = client.post("/api/auth/login", json={"username": "evt_user", "password": pwd})
    assert res_login.status_code == 200
    token = res_login.get_json()["session_token"]

    # 3. Logout -> SESSION_REVOKED
    assert client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"}).status_code == 200

    # 4. 5 failed logins -> LOGIN_FAILURE x5, ACCOUNT_LOCKED x1
    for _ in range(5):
        assert client.post("/api/auth/login", json={
            "username": "evt_user",
            "password": "WrongPassword123!",
        }).status_code == 401

    # 5. 6th attempt -> LOGIN_BLOCKED
    assert client.post("/api/auth/login", json={
        "username": "evt_user",
        "password": pwd,
    }).status_code == 403

    recorded_types = [e["event_type"] for e in get_recent_security_events()]
    assert EVENT_USER_REGISTERED in recorded_types
    assert EVENT_SESSION_CREATED in recorded_types
    assert EVENT_LOGIN_SUCCESS in recorded_types
    assert EVENT_SESSION_REVOKED in recorded_types
    assert recorded_types.count(EVENT_LOGIN_FAILURE) == 5
    assert EVENT_ACCOUNT_LOCKED in recorded_types
    assert EVENT_LOGIN_BLOCKED in recorded_types


def test_mfa_recovery_and_password_change_emit_shared_events(client, app):
    """Verify MFA, recovery code, and password change routes emit shared event names."""
    pwd1 = "sunset-mountain-camera-coffee"
    pwd2 = "ocean-breeze-guitar-notebook"

    assert client.post("/api/auth/register", json={
        "username": "evt_mfa_user",
        "email": "evt_mfa@example.com",
        "password": pwd1,
    }).status_code == 201

    # Setup MFA
    setup_data = client.post("/api/auth/mfa/setup", json={
        "username": "evt_mfa_user",
        "password": pwd1,
    }).get_json()
    setup_token = setup_data["setup_token"]
    secret = setup_data["secret"]

    # Bad confirmation code -> MFA_FAILURE
    assert client.post("/api/auth/mfa/enable", json={
        "setup_token": setup_token,
        "code": "000000",
    }).status_code == 400

    # Valid confirmation -> MFA_ENABLED
    res_enable = client.post("/api/auth/mfa/enable", json={
        "setup_token": setup_token,
        "code": pyotp.TOTP(secret).now(),
    })
    assert res_enable.status_code == 200
    rec_code = res_enable.get_json()["recovery_codes"][0]

    # Login with MFA -> bad code -> MFA_FAILURE, then recovery -> RECOVERY_CODE_USED + LOGIN_SUCCESS
    mfa_token = client.post("/api/auth/login", json={
        "username": "evt_mfa_user",
        "password": pwd1,
    }).get_json()["mfa_token"]

    assert client.post("/api/auth/verify-mfa", json={
        "mfa_token": mfa_token,
        "code": "000000",
    }).status_code == 401

    res_rec = client.post("/api/auth/recovery", json={
        "mfa_token": mfa_token,
        "recovery_code": rec_code,
    })
    assert res_rec.status_code == 200
    tok = res_rec.get_json()["session_token"]

    # Create secondary session then change password -> PASSWORD_CHANGED + SESSION_REVOKED
    with app.app_context():
        u = User.query.filter_by(username="evt_mfa_user").first()
        create_session(u.id, ip_address="127.0.0.2", user_agent="ExtraDevice")

    assert client.post(
        "/api/auth/change-password",
        json={"username": "evt_mfa_user", "current_password": pwd1, "new_password": pwd2},
        headers={"Authorization": f"Bearer {tok}"},
    ).status_code == 200

    recorded_types = [e["event_type"] for e in get_recent_security_events()]
    assert EVENT_MFA_FAILURE in recorded_types
    assert EVENT_MFA_ENABLED in recorded_types
    assert EVENT_RECOVERY_CODE_USED in recorded_types
    assert EVENT_PASSWORD_CHANGED in recorded_types
    assert EVENT_SESSION_REVOKED in recorded_types


def test_rate_limit_handler_emits_rate_limited_event(app):
    """Confirm HTTP 429 error handler emits RATE_LIMITED event."""
    with app.test_request_context("/api/auth/login", method="POST"):
        handler = app.error_handler_spec[None][429][list(app.error_handler_spec[None][429].keys())[0]]
        resp, status = handler(None)
        assert status == 429

    events = get_recent_security_events(EVENT_RATE_LIMITED)
    assert len(events) == 1
    assert events[0]["details"]["path"] == "/api/auth/login"


def test_codebase_uses_only_shared_event_constants():
    """Step 3.1 Check: Audit backend/app to verify no route emits raw ad-hoc event strings."""
    app_dir = Path(__file__).resolve().parent.parent / "app"
    pattern = re.compile(r"record_security_event\(\s*[\"']")

    offenders = []
    for py_file in app_dir.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        if pattern.search(content):
            offenders.append(str(py_file))

    assert offenders == [], f"Found raw event string literals instead of shared constants in: {offenders}"
