import time
import pytest
import pyotp
from app import create_app
from app.extensions import db
from app.models.user import User
from app.auth.mfa import (
    generate_totp_secret,
    encrypt_totp_secret,
    decrypt_totp_secret,
    generate_provisioning_uri,
    generate_qr_code_data_uri,
    verify_totp_code,
    generate_pending_mfa_token,
    verify_pending_mfa_token,
)
from app.auth.password import hash_password


@pytest.fixture
def app():
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_totp_secret_encryption_at_rest(app):
    """MFA secrets must be encrypted at rest using Fernet and never stored in plaintext."""
    with app.app_context():
        raw_secret = generate_totp_secret()
        encrypted = encrypt_totp_secret(raw_secret)

        # Encrypted value must differ from plaintext
        assert encrypted != raw_secret
        # Fernet tokens start with base64 'gAAAAA'
        assert encrypted.startswith("gAAAAA")

        # Decryption must recover the original base32 secret
        decrypted = decrypt_totp_secret(encrypted)
        assert decrypted == raw_secret


def test_provisioning_uri_and_qr_code(app):
    """Provisioning URI must match RFC 6238 and QR code must be a valid PNG Data URI."""
    with app.app_context():
        secret = generate_totp_secret()
        uri = generate_provisioning_uri(secret, "alice@authshield.lab")
        assert uri.startswith("otpauth://totp/")
        assert "secret=" in uri
        assert "alice%40authshield.lab" in uri or "alice@authshield.lab" in uri

        qr_data = generate_qr_code_data_uri(uri)
        assert qr_data.startswith("data:image/png;base64,iVBORw0KGgo")


def test_totp_verification_and_drift_window(app):
    """Test TOTP verification with valid codes, invalid codes, and ±30s clock drift."""
    with app.app_context():
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)
        current_step = int(time.time() / 30)

        # 1. Current valid code
        valid_code = totp.now()
        is_ok, matched_step, _ = verify_totp_code(secret, valid_code)
        assert is_ok is True
        assert matched_step == current_step

        # 2. Clock drift: Past step (T - 30s) within valid window 1
        past_code = totp.generate_otp(current_step - 1)
        is_ok_past, _, _ = verify_totp_code(secret, past_code, valid_window=1)
        assert is_ok_past is True

        # 3. Clock drift: Future step (T + 30s) within valid window 1
        future_code = totp.generate_otp(current_step + 1)
        is_ok_future, _, _ = verify_totp_code(secret, future_code, valid_window=1)
        assert is_ok_future is True

        # 4. Out-of-window code (T - 90s, offset -3)
        old_code = totp.generate_otp(current_step - 3)
        is_ok_old, _, _ = verify_totp_code(secret, old_code, valid_window=1)
        assert is_ok_old is False

        # 5. Invalid / non-numeric codes
        assert verify_totp_code(secret, "12345")[0] is False
        assert verify_totp_code(secret, "abcdef")[0] is False
        assert verify_totp_code(secret, "999999")[0] is False


def test_replay_attack_prevention(app):
    """A TOTP code must NOT be accepted more than once in the same time step."""
    with app.app_context():
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)
        current_step = int(time.time() / 30)
        code = totp.now()

        # First verification succeeds
        is_ok, step, _ = verify_totp_code(secret, code, last_step=None)
        assert is_ok is True
        assert step == current_step

        # Second verification with last_step recorded must be rejected as replayed
        is_replayed, _, reason = verify_totp_code(secret, code, last_step=step)
        assert is_replayed is False
        assert "already been used" in reason


def test_mfa_setup_and_enable_flow(client, app):
    """Test full enrollment: setup initiation -> QR generation -> verification -> enable."""
    password = "MySecurePassword#2026!"
    client.post("/api/auth/register", json={
        "username": "mfa_enroll_user",
        "email": "mfa_enroll@example.com",
        "password": password
    })

    # 1. Initiate setup
    res_setup = client.post("/api/auth/mfa/setup", json={
        "username": "mfa_enroll_user",
        "password": password
    })
    assert res_setup.status_code == 200
    data_setup = res_setup.get_json()
    assert "setup_token" in data_setup
    assert "secret" in data_setup
    assert "qr_code" in data_setup

    setup_token = data_setup["setup_token"]
    raw_secret = data_setup["secret"]

    # 2. Confirm with bad code fails
    res_bad = client.post("/api/auth/mfa/enable", json={
        "setup_token": setup_token,
        "code": "000000"
    })
    assert res_bad.status_code == 400

    # 3. Confirm with valid code succeeds
    valid_code = pyotp.TOTP(raw_secret).now()
    res_enable = client.post("/api/auth/mfa/enable", json={
        "setup_token": setup_token,
        "code": valid_code
    })
    assert res_enable.status_code == 200
    assert res_enable.get_json()["mfa_enabled"] is True

    # 4. Confirm in database: secret is encrypted and mfa_enabled is True
    with app.app_context():
        user = User.query.filter_by(username="mfa_enroll_user").first()
        assert user.mfa_enabled is True
        assert user.totp_secret.startswith("gAAAAA")
        assert user.last_totp_step is not None
        assert decrypt_totp_secret(user.totp_secret) == raw_secret


def test_login_pending_mfa_state_and_verification(client, app):
    """
    Test login flow with MFA:
    - Step 1: Password verified -> returns short-lived pending MFA token (no full session).
    - Step 2: verify-mfa with valid code -> returns full session.
    - Bad password -> 401 without revealing MFA status.
    """
    password = "CorrectHorseBatteryStaple!"
    raw_secret = pyotp.random_base32()

    with app.app_context():
        user = User(
            username="mfa_login_user",
            email="mfa_login@example.com",
            password_hash=hash_password(password),
            password_algorithm="argon2id",
            mfa_enabled=True,
            totp_secret=encrypt_totp_secret(raw_secret),
        )
        db.session.add(user)
        db.session.commit()

    # 1. Wrong password does NOT reveal MFA state
    res_wrong = client.post("/api/auth/login", json={
        "username": "mfa_login_user",
        "password": "WrongPassword"
    })
    assert res_wrong.status_code == 401
    assert "Invalid username or password" in res_wrong.get_json()["message"]
    assert "mfa_required" not in res_wrong.get_json()

    # 2. Correct password returns pending MFA state
    res_login = client.post("/api/auth/login", json={
        "username": "mfa_login_user",
        "password": password
    })
    assert res_login.status_code == 200
    login_data = res_login.get_json()
    assert login_data["mfa_required"] is True
    assert "mfa_token" in login_data
    # Full session user dict must NOT be present
    assert "user" not in login_data

    mfa_token = login_data["mfa_token"]

    # 3. verify-mfa with incorrect code fails
    res_bad_mfa = client.post("/api/auth/verify-mfa", json={
        "mfa_token": mfa_token,
        "code": "111111"
    })
    assert res_bad_mfa.status_code == 401

    # 4. verify-mfa with correct code succeeds
    valid_code = pyotp.TOTP(raw_secret).now()
    res_ok_mfa = client.post("/api/auth/verify-mfa", json={
        "mfa_token": mfa_token,
        "code": valid_code
    })
    assert res_ok_mfa.status_code == 200
    mfa_data = res_ok_mfa.get_json()
    assert mfa_data["authenticated"] is True
    assert mfa_data["user"]["username"] == "mfa_login_user"

    # 5. Immediate replay of the same code must fail
    res_replay = client.post("/api/auth/verify-mfa", json={
        "mfa_token": mfa_token,
        "code": valid_code
    })
    assert res_replay.status_code == 401
    assert "already been used" in res_replay.get_json()["message"]


def test_disable_mfa_after_reauthentication(client, app):
    """Disabling MFA requires password reauthentication and valid TOTP code."""
    password = "DisableMfaPassphrase#2026"
    raw_secret = pyotp.random_base32()

    with app.app_context():
        user = User(
            username="disable_user",
            email="disable@example.com",
            password_hash=hash_password(password),
            password_algorithm="argon2id",
            mfa_enabled=True,
            totp_secret=encrypt_totp_secret(raw_secret),
        )
        db.session.add(user)
        db.session.commit()

    # 1. Wrong password fails
    res_bad_pwd = client.post("/api/auth/mfa/disable", json={
        "username": "disable_user",
        "password": "WrongPassword",
        "code": pyotp.TOTP(raw_secret).now()
    })
    assert res_bad_pwd.status_code == 401

    # 2. Wrong code fails
    res_bad_code = client.post("/api/auth/mfa/disable", json={
        "username": "disable_user",
        "password": password,
        "code": "000000"
    })
    assert res_bad_code.status_code == 401

    # 3. Correct password and code succeeds
    res_ok = client.post("/api/auth/mfa/disable", json={
        "username": "disable_user",
        "password": password,
        "code": pyotp.TOTP(raw_secret).now()
    })
    assert res_ok.status_code == 200
    assert res_ok.get_json()["mfa_enabled"] is False

    # 4. Subsequent login no longer requires MFA
    res_relogin = client.post("/api/auth/login", json={
        "username": "disable_user",
        "password": password
    })
    assert res_relogin.status_code == 200
    assert res_relogin.get_json()["mfa_required"] is False
    assert res_relogin.get_json()["user"]["username"] == "disable_user"
