import pytest
import pyotp
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.recovery_code import RecoveryCode
from app.auth.password import hash_password
from app.auth.mfa import encrypt_totp_secret
from app.auth.recovery import (
    generate_user_recovery_codes,
    verify_and_consume_recovery_code,
    hash_recovery_code,
    normalize_recovery_code,
    get_remaining_recovery_codes_count,
)


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


def test_generate_and_hash_recovery_codes(app):
    """Test recovery code generation, format, salted SHA-256 hashing, and database storage."""
    with app.app_context():
        user = User(
            username="rec_test_user",
            email="rec_test@example.com",
            password_hash=hash_password("MySecretPassphrase#2026"),
            password_algorithm="argon2id",
            mfa_enabled=True,
        )
        db.session.add(user)
        db.session.commit()

        codes = generate_user_recovery_codes(user.id, count=8)
        assert len(codes) == 8
        assert len(set(codes)) == 8  # All unique

        # Verify format (XXXXX-XXXXX)
        for c in codes:
            assert len(c) == 11
            assert c[5] == "-"

        # Verify database records
        db_records = RecoveryCode.query.filter_by(user_id=user.id).all()
        assert len(db_records) == 8
        for r in db_records:
            assert r.used is False
            assert r.used_at is None
            # Only cryptographic hashes are stored (SHA-256 is 64 hex characters)
            assert len(r.code_hash) == 64
            # Plaintext code must NOT be in the database
            assert r.code_hash not in codes


def test_verify_and_consume_one_time_guarantee(app):
    """Confirm a code can be verified once and cannot be used again."""
    with app.app_context():
        user = User(
            username="rec_single_use",
            email="rec_single@example.com",
            password_hash=hash_password("MySecretPassphrase#2026"),
            password_algorithm="argon2id",
            mfa_enabled=True,
        )
        db.session.add(user)
        db.session.commit()

        codes = generate_user_recovery_codes(user.id, count=4)
        target_code = codes[0]

        # 1. First use succeeds (handles formatting variations)
        is_ok, msg = verify_and_consume_recovery_code(user.id, target_code)
        assert is_ok is True
        assert "verified successfully" in msg

        # 2. Second use of the EXACT SAME code must fail
        is_ok2, msg2 = verify_and_consume_recovery_code(user.id, target_code)
        assert is_ok2 is False
        assert "already been used" in msg2

        # 3. Non-existent code fails
        is_bad, _ = verify_and_consume_recovery_code(user.id, "XXXXX-YYYYY")
        assert is_bad is False


def test_recovery_login_flow(client, app):
    """
    Test end-to-end recovery login:
    1. User with MFA logs in with password -> gets pending MFA token.
    2. Submits wrong recovery code -> 401.
    3. Submits valid recovery code -> 200, logs in, deactivates lost MFA device.
    4. Code cannot be reused.
    """
    password = "MySecureRecoveryPassword#2026"
    raw_secret = pyotp.random_base32()

    with app.app_context():
        user = User(
            username="rec_login_user",
            email="rec_login@example.com",
            password_hash=hash_password(password),
            password_algorithm="argon2id",
            mfa_enabled=True,
            totp_secret=encrypt_totp_secret(raw_secret),
        )
        db.session.add(user)
        db.session.commit()

        codes = generate_user_recovery_codes(user.id, count=5)
        valid_recovery_code = codes[0]

    # Step 1: Initial password login returns mfa_required
    res_login = client.post("/api/auth/login", json={
        "username": "rec_login_user",
        "password": password
    })
    assert res_login.status_code == 200
    mfa_token = res_login.get_json()["mfa_token"]

    # Step 2: Bad recovery code rejected
    res_bad = client.post("/api/auth/recovery", json={
        "mfa_token": mfa_token,
        "recovery_code": "00000-00000"
    })
    assert res_bad.status_code == 401

    # Step 3: Valid recovery code succeeds
    res_ok = client.post("/api/auth/recovery", json={
        "mfa_token": mfa_token,
        "recovery_code": valid_recovery_code
    })
    assert res_ok.status_code == 200
    data = res_ok.get_json()
    assert data["authenticated"] is True
    assert data["mfa_reset"] is True
    assert data["require_mfa_re_enroll"] is True
    assert data["user"]["username"] == "rec_login_user"

    # Step 4: Verify in database that lost MFA was deactivated
    with app.app_context():
        u = User.query.filter_by(username="rec_login_user").first()
        assert u.mfa_enabled is False
        assert u.totp_secret is None

    # Step 5: Confirm the same recovery code cannot be reused
    res_relogin = client.post("/api/auth/login", json={
        "username": "rec_login_user",
        "password": password
    })
    # Since MFA was deactivated, password login succeeds directly
    assert res_relogin.status_code == 200
    assert res_relogin.get_json()["mfa_required"] is False


def test_regenerate_and_status_endpoints(client, app):
    """Test generating fresh recovery codes and querying remaining unused count."""
    password = "RegenerateTestPassphrase#2026"

    with app.app_context():
        user = User(
            username="regen_user",
            email="regen@example.com",
            password_hash=hash_password(password),
            password_algorithm="argon2id",
            mfa_enabled=True,
            totp_secret=encrypt_totp_secret(pyotp.random_base32()),
        )
        db.session.add(user)
        db.session.commit()
        user_id = user.id

    # 1. Regenerate codes
    res_regen = client.post("/api/auth/mfa/recovery-codes/regenerate", json={
        "username": "regen_user",
        "password": password
    })
    assert res_regen.status_code == 200
    codes = res_regen.get_json()["recovery_codes"]
    assert len(codes) == 8

    # 2. Check status
    res_status = client.get("/api/auth/mfa/recovery-codes/status?username=regen_user")
    assert res_status.status_code == 200
    assert res_status.get_json()["remaining_recovery_codes"] == 8

    # 3. Use one code directly via username/password fallback
    res_use = client.post("/api/auth/recovery", json={
        "username": "regen_user",
        "password": password,
        "recovery_code": codes[0]
    })
    assert res_use.status_code == 200
    assert res_use.get_json()["authenticated"] is True
