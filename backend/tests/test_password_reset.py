from datetime import datetime, timezone, timedelta
import pytest
import pyotp
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.password_reset_token import PasswordResetToken
from app.auth.password import hash_password, verify_password
from app.auth.mfa import encrypt_totp_secret
from app.auth.session_manager import create_session
from app.auth.reset import (
    hash_reset_token,
    get_dev_email_outbox,
    clear_dev_email_outbox,
    create_password_reset_token,
    send_reset_email_dev_console,
)
from app.detection.events import (
    get_recent_security_events,
    clear_recent_security_events,
    EVENT_PASSWORD_RESET_REQUESTED,
    EVENT_PASSWORD_RESET_COMPLETED,
)


@pytest.fixture
def app():
    app = create_app("testing")
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


def test_forgot_password_generic_response_prevents_enumeration(client, app):
    """Existing and non-existing emails must return the exact same generic response."""
    with app.app_context():
        user = User(
            username="enum_user",
            email="real.user@example.com",
            password_hash=hash_password("sunset-guitar-river-bridge"),
            password_algorithm="argon2id",
        )
        db.session.add(user)
        db.session.commit()

    # 1. Non-existent email
    res_missing = client.post("/api/auth/forgot-password", json={"email": "nobody@example.com"})
    assert res_missing.status_code == 200
    assert res_missing.get_json() == {
        "message": "If an account with that email exists, a password reset link has been sent."
    }
    assert len(get_dev_email_outbox()) == 0

    # 2. Existing email
    res_found = client.post("/api/auth/forgot-password", json={"email": "real.user@example.com"})
    assert res_found.status_code == 200
    assert res_found.get_json() == res_missing.get_json()
    assert "token" not in res_found.get_json()

    # Dev outbox should hold the token link
    outbox = get_dev_email_outbox()
    assert len(outbox) == 1
    assert outbox[0]["to"] == "real.user@example.com"
    assert "token=" in outbox[0]["reset_link"]

    # Security event recorded
    req_events = get_recent_security_events(EVENT_PASSWORD_RESET_REQUESTED)
    assert len(req_events) == 2
    assert req_events[0]["details"]["account_found"] is False
    assert req_events[1]["details"]["account_found"] is True


def test_reset_token_stored_only_as_sha256_hash(client, app):
    """Only the SHA-256 hash of the reset token must be stored in password_reset_tokens."""
    with app.app_context():
        user = User(
            username="hash_reset_user",
            email="hashreset@example.com",
            password_hash=hash_password("sunset-guitar-river-bridge"),
            password_algorithm="argon2id",
        )
        db.session.add(user)
        db.session.commit()
        user_id = user.id

    client.post("/api/auth/forgot-password", json={"email": "hashreset@example.com"})
    raw_token = get_dev_email_outbox()[0]["token"]
    assert len(raw_token) >= 32

    with app.app_context():
        rec = PasswordResetToken.query.filter_by(user_id=user_id).first()
        assert rec is not None
        assert len(rec.token_hash) == 64
        assert rec.token_hash == hash_reset_token(raw_token)
        assert rec.token_hash != raw_token
        assert rec.used is False
        assert rec.is_expired is False


def test_valid_reset_token_revokes_sessions_and_logs_event(client, app):
    """Valid token resets password with Argon2id, revokes all active sessions, and logs event."""
    old_pwd = "old-guitar-winter-coffee"
    new_pwd = "fresh-mountain-river-breeze"

    with app.app_context():
        user = User(
            username="valid_reset_user",
            email="validreset@example.com",
            password_hash=hash_password(old_pwd),
            password_algorithm="argon2id",
        )
        db.session.add(user)
        db.session.commit()
        uid = user.id

        # Create 2 active sessions prior to reset
        _, tok1 = create_session(uid, ip_address="10.0.0.1", user_agent="Browser 1")
        _, tok2 = create_session(uid, ip_address="10.0.0.2", user_agent="Browser 2")

    # Request reset
    client.post("/api/auth/forgot-password", json={"email": "validreset@example.com"})
    raw_token = get_dev_email_outbox()[0]["token"]

    # Complete reset
    res_reset = client.post("/api/auth/reset-password", json={
        "token": raw_token,
        "new_password": new_pwd,
    })
    assert res_reset.status_code == 200
    data = res_reset.get_json()
    assert data["revoked_sessions"] == 2
    assert "session_token" not in data

    # Existing sessions must now be rejected
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok1}"}).status_code == 401
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok2}"}).status_code == 401

    # Verify DB password updated with Argon2id and old password fails
    with app.app_context():
        u = db.session.get(User, uid)
        assert u.password_hash.startswith("$argon2id$v=19$")
        assert u.password_algorithm == "argon2id"
        assert verify_password(new_pwd, u.password_hash) is True
        assert verify_password(old_pwd, u.password_hash) is False

    # Verify security event logged
    completed_events = get_recent_security_events(EVENT_PASSWORD_RESET_COMPLETED)
    assert len(completed_events) == 1
    assert completed_events[0]["username"] == "valid_reset_user"
    assert completed_events[0]["details"]["revoked_sessions"] == 2


def test_reused_expired_and_invalid_reset_tokens(client, app):
    """Step 2.8 Check: Test valid, expired, reused, and invalid reset tokens."""
    with app.app_context():
        user = User(
            username="token_cases_user",
            email="tokencases@example.com",
            password_hash=hash_password("initial-sunset-river-bridge"),
            password_algorithm="argon2id",
        )
        db.session.add(user)
        db.session.commit()
        uid = user.id

    # 1. Invalid token
    res_invalid = client.post("/api/auth/reset-password", json={
        "token": "completely-invalid-random-token-12345",
        "new_password": "second-sunset-river-bridge",
    })
    assert res_invalid.status_code == 400
    assert "Invalid or expired" in res_invalid.get_json()["message"]

    # 2. Expired token
    with app.app_context():
        u = db.session.get(User, uid)
        expired_raw = create_password_reset_token(u, expiry_seconds=900)
        rec = PasswordResetToken.query.filter_by(token_hash=hash_reset_token(expired_raw)).first()
        rec.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
        db.session.commit()

    res_expired = client.post("/api/auth/reset-password", json={
        "token": expired_raw,
        "new_password": "second-sunset-river-bridge",
    })
    assert res_expired.status_code == 400
    assert "expired" in res_expired.get_json()["message"]

    # 3. Valid token followed by reuse attempt
    client.post("/api/auth/forgot-password", json={"email": "tokencases@example.com"})
    valid_raw = get_dev_email_outbox()[-1]["token"]

    res_valid = client.post("/api/auth/reset-password", json={
        "token": valid_raw,
        "new_password": "third-sunset-river-bridge",
    })
    assert res_valid.status_code == 200

    res_reused = client.post("/api/auth/reset-password", json={
        "token": valid_raw,
        "new_password": "fourth-sunset-river-bridge",
    })
    assert res_reused.status_code == 400
    assert "already been used" in res_reused.get_json()["message"]


def test_new_reset_request_invalidates_prior_unused_token(client, app):
    """Requesting a fresh token must invalidate older unused reset tokens."""
    with app.app_context():
        user = User(
            username="supersede_user",
            email="supersede@example.com",
            password_hash=hash_password("initial-camera-coffee-journal"),
            password_algorithm="argon2id",
        )
        db.session.add(user)
        db.session.commit()

    client.post("/api/auth/forgot-password", json={"email": "supersede@example.com"})
    first_token = get_dev_email_outbox()[-1]["token"]

    client.post("/api/auth/forgot-password", json={"email": "supersede@example.com"})
    second_token = get_dev_email_outbox()[-1]["token"]

    assert first_token != second_token

    # First token is now invalidated
    res_first = client.post("/api/auth/reset-password", json={
        "token": first_token,
        "new_password": "updated-camera-coffee-journal",
    })
    assert res_first.status_code == 400

    # Second token works
    res_second = client.post("/api/auth/reset-password", json={
        "token": second_token,
        "new_password": "updated-camera-coffee-journal",
    })
    assert res_second.status_code == 200


def test_weak_password_rejected_without_consuming_token(client, app):
    """Weak new passwords fail Step 2.4 validation while keeping valid token usable."""
    with app.app_context():
        user = User(
            username="weak_reset_user",
            email="weakreset@example.com",
            password_hash=hash_password("strong-initial-passphrase-one"),
            password_algorithm="argon2id",
        )
        db.session.add(user)
        db.session.commit()

    client.post("/api/auth/forgot-password", json={"email": "weakreset@example.com"})
    token = get_dev_email_outbox()[0]["token"]

    # Weak password fails validation
    res_weak = client.post("/api/auth/reset-password", json={
        "token": token,
        "new_password": "password123",
    })
    assert res_weak.status_code == 400
    assert "security requirements" in res_weak.get_json()["message"]

    # Same valid token still works once user picks a strong password
    res_ok = client.post("/api/auth/reset-password", json={
        "token": token,
        "new_password": "strong-updated-passphrase-two",
    })
    assert res_ok.status_code == 200


def test_password_reset_does_not_bypass_mfa(client, app):
    """Requirement 10: A user with MFA enabled must still pass MFA after resetting password."""
    old_pwd = "old-mfa-protected-passphrase"
    new_pwd = "new-mfa-protected-passphrase"
    raw_secret = pyotp.random_base32()

    with app.app_context():
        user = User(
            username="mfa_reset_guard",
            email="mfaguard@example.com",
            password_hash=hash_password(old_pwd),
            password_algorithm="argon2id",
            mfa_enabled=True,
            totp_secret=encrypt_totp_secret(raw_secret),
        )
        db.session.add(user)
        db.session.commit()

    client.post("/api/auth/forgot-password", json={"email": "mfaguard@example.com"})
    reset_token = get_dev_email_outbox()[0]["token"]

    res_reset = client.post("/api/auth/reset-password", json={
        "token": reset_token,
        "new_password": new_pwd,
    })
    assert res_reset.status_code == 200
    assert res_reset.get_json()["mfa_required_on_next_login"] is True
    assert "Set-Cookie" not in res_reset.headers

    # Next login with new password MUST require MFA (no bypass!)
    res_login = client.post("/api/auth/login", json={
        "username": "mfa_reset_guard",
        "password": new_pwd,
    })
    assert res_login.status_code == 200
    login_data = res_login.get_json()
    assert login_data["mfa_required"] is True
    assert "user" not in login_data

    # Complete login with valid TOTP
    code = pyotp.TOTP(raw_secret).now()
    res_mfa = client.post("/api/auth/verify-mfa", json={
        "mfa_token": login_data["mfa_token"],
        "code": code,
    })
    assert res_mfa.status_code == 200
    assert res_mfa.get_json()["authenticated"] is True


def test_production_mode_never_logs_reset_tokens():
    """In production configuration, dev email outbox must stay empty."""
    prod_app = create_app("production")
    clear_dev_email_outbox()
    with prod_app.app_context():
        send_reset_email_dev_console("prod@example.com", "secret-prod-token")
    assert len(get_dev_email_outbox()) == 0
