import re
import pytest
import pyotp
from app import create_app
from app.extensions import db
from app.models.user import User
from app.auth.password import hash_password
from app.auth.session_manager import create_session
from app.auth.reset import get_dev_email_outbox, clear_dev_email_outbox
from app.detection.event_collector import clear_recent_security_events
from app.detection.event_repository import query_events
from app.detection.event_types import (
    EVENT_USER_REGISTERED,
    EVENT_LOGIN_SUCCESS,
    EVENT_LOGIN_FAILURE,
    EVENT_MFA_SUCCESS,
    EVENT_MFA_FAILURE,
    EVENT_ACCOUNT_LOCKED,
    EVENT_LOGIN_BLOCKED,
    EVENT_PASSWORD_RESET_REQUESTED,
    EVENT_PASSWORD_RESET_COMPLETED,
    EVENT_SESSION_CREATED,
    EVENT_SESSION_REVOKED,
    EVENT_MFA_ENABLED,
    EVENT_MFA_DISABLED,
    EVENT_PASSWORD_CHANGED,
    EVENT_RECOVERY_CODE_USED,
    EVENT_ADMIN_ACTION,
)


@pytest.fixture
def app(tmp_path):
    app = create_app("testing")
    auth_log_file = tmp_path / "auth.log"
    app.config["AUTH_LOG_ENABLED"] = True
    app.config["AUTH_LOG_PATH"] = str(auth_log_file)

    with app.app_context():
        db.create_all()
        clear_dev_email_outbox()
        clear_recent_security_events()
        yield app
        db.session.remove()
        db.drop_all()
        clear_dev_email_outbox()
        clear_recent_security_events()


@pytest.fixture
def client(app):
    return app.test_client()


def test_all_10_step34_actions_persist_db_events_and_fail2ban_log(client, app, tmp_path):
    """
    Step 3.4 Check: Perform every required action (1-10) and verify both
    structured database events AND Fail2Ban-compatible auth.log output.
    """
    pwd1 = "guitar-notebook-winter-coffee"
    pwd2 = "sunset-mountain-camera-coffee"
    pwd3 = "ocean-breeze-guitar-notebook"

    # 1. Registration
    assert client.post("/api/auth/register", json={
        "username": "step34_user",
        "email": "step34@example.com",
        "password": pwd1,
    }).status_code == 201

    # 2. Successful login & 7. Session creation
    res_login = client.post("/api/auth/login", json={
        "username": "step34_user",
        "password": pwd1,
    })
    assert res_login.status_code == 200
    tok1 = res_login.get_json()["session_token"]

    # 9. MFA changes (enable)
    setup_data = client.post("/api/auth/mfa/setup", json={
        "username": "step34_user",
        "password": pwd1,
    }).get_json()
    secret = setup_data["secret"]
    res_enable = client.post("/api/auth/mfa/enable", json={
        "setup_token": setup_data["setup_token"],
        "code": pyotp.TOTP(secret).now(),
    })
    assert res_enable.status_code == 200
    rec_code = res_enable.get_json()["recovery_codes"][0]

    # 4. MFA failure & MFA success
    mfa_tok = client.post("/api/auth/login", json={
        "username": "step34_user",
        "password": pwd1,
    }).get_json()["mfa_token"]
    assert client.post("/api/auth/verify-mfa", json={"mfa_token": mfa_tok, "code": "000000"}).status_code == 401

    # Use valid MFA code at next step (valid_window=1) to avoid replay collision from enable step
    import time
    next_code = pyotp.TOTP(secret).generate_otp(int(time.time() / 30) + 1)
    res_mfa_ok = client.post("/api/auth/verify-mfa", json={"mfa_token": mfa_tok, "code": next_code})
    assert res_mfa_ok.status_code == 200
    tok2 = res_mfa_ok.get_json()["session_token"]

    # Password change + Session revocation
    assert client.post(
        "/api/auth/change-password",
        json={"username": "step34_user", "current_password": pwd1, "new_password": pwd2},
        headers={"Authorization": f"Bearer {tok2}"},
    ).status_code == 200

    # 9. MFA changes (disable via recovery code + re-enable + explicit disable)
    mfa_tok2 = client.post("/api/auth/login", json={
        "username": "step34_user",
        "password": pwd2,
    }).get_json()["mfa_token"]
    res_rec = client.post("/api/auth/recovery", json={
        "mfa_token": mfa_tok2,
        "recovery_code": rec_code,
    })
    assert res_rec.status_code == 200
    tok3 = res_rec.get_json()["session_token"]

    # 8. Session revocation (logout)
    assert client.post("/api/auth/logout", headers={"Authorization": f"Bearer {tok3}"}).status_code == 200

    # 6. Password reset
    assert client.post("/api/auth/forgot-password", json={"email": "step34@example.com"}).status_code == 200
    reset_tok = get_dev_email_outbox()[-1]["token"]
    assert client.post("/api/auth/reset-password", json={
        "token": reset_tok,
        "new_password": pwd3,
    }).status_code == 200

    # 3. Failed login & 5. Account lockout
    for _ in range(5):
        assert client.post("/api/auth/login", json={
            "username": "step34_user",
            "password": "WrongPassword999!",
        }).status_code == 401
    assert client.post("/api/auth/login", json={
        "username": "step34_user",
        "password": pwd3,
    }).status_code == 403

    # 10. Administrative security actions (CLI admin + status update)
    with app.app_context():
        admin = User(
            username="step34_admin",
            email="step34_admin@example.com",
            password_hash=hash_password("purple-sunset-guitar-coffee"),
            password_algorithm="argon2id",
            role="admin",
        )
        db.session.add(admin)
        db.session.commit()
        _, admin_tok = create_session(admin.id, ip_address="127.0.0.1", user_agent="AdminSuite")
        target_u = User.query.filter_by(username="step34_user").first()
        target_id = target_u.id

    admin_client = app.test_client()
    assert admin_client.patch(
        f"/api/users/{target_id}/status",
        headers={"Authorization": f"Bearer {admin_tok}"},
        json={"is_active": True},
    ).status_code == 200

    # Verify all expected event types persisted in security_events DB table
    with app.app_context():
        rows, total = query_events(limit=100)
        persisted_types = {r.event_type for r in rows}

        required_events = {
            EVENT_USER_REGISTERED,
            EVENT_LOGIN_SUCCESS,
            EVENT_LOGIN_FAILURE,
            EVENT_MFA_SUCCESS,
            EVENT_MFA_FAILURE,
            EVENT_ACCOUNT_LOCKED,
            EVENT_LOGIN_BLOCKED,
            EVENT_PASSWORD_RESET_REQUESTED,
            EVENT_PASSWORD_RESET_COMPLETED,
            EVENT_SESSION_CREATED,
            EVENT_SESSION_REVOKED,
            EVENT_MFA_ENABLED,
            EVENT_MFA_DISABLED,
            EVENT_PASSWORD_CHANGED,
            EVENT_RECOVERY_CODE_USED,
            EVENT_ADMIN_ACTION,
        }
        missing = required_events - persisted_types
        assert not missing, f"Missing expected persisted events: {missing}"

    # Verify Fail2Ban-compatible auth.log lines were generated matching docs/Guide.md failregex
    auth_log_file = tmp_path / "auth.log"
    assert auth_log_file.is_file()
    log_lines = auth_log_file.read_text(encoding="utf-8").splitlines()
    assert len(log_lines) >= 6  # 1 MFA failure + 5 login failures + 1 lockout + 1 blocked
    failregex = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} Failed login attempt for user=\S+ from \S+$")
    for line in log_lines:
        assert failregex.match(line), f"Line did not match Fail2Ban failregex: {line}"
