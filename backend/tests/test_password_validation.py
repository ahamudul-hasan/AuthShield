import pytest
from app import create_app
from app.extensions import db
from app.models.user import User
from app.auth.validator import validate_password, is_passphrase, calculate_entropy
from app.auth.password import verify_password


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


def test_minimum_length_validation():
    """Passwords shorter than minimum length (default 10) must be rejected with clear message."""
    res = validate_password("Short1!", username="user1", email="user1@example.com")
    assert res["is_valid"] is False
    assert any("at least 10 characters long" in err for err in res["errors"])
    assert res["score"] == 0
    assert res["strength"] == "very_weak"


def test_maximum_length_validation_dos_mitigation():
    """Excessively long passwords (>128 chars) must be rejected to prevent hashing DoS."""
    huge_pwd = "A" * 129
    res = validate_password(huge_pwd)
    assert res["is_valid"] is False
    assert any("maximum length of 128 characters" in err for err in res["errors"])
    assert any("protects system resources" in err for err in res["errors"])


def test_common_and_compromised_passwords():
    """Passwords appearing in the RockYou/common blocklist must be rejected."""
    common_passwords = [
        "1234567890",
        "password123",
        "iloveyou123",
        "football2024",
        "superman123!",
        "dragon12345",
    ]
    for pwd in common_passwords:
        res = validate_password(pwd)
        assert res["is_valid"] is False, f"Expected '{pwd}' to be rejected as common."
        assert any("common" in err or "compromised" in err for err in res["errors"])


def test_passwords_containing_username_or_email():
    """Passwords containing username, reversed username, or email tokens must be rejected."""
    # Username in password
    res_user = validate_password("MyAliceSecret2024!", username="Alice", email="alice@test.com")
    assert res_user["is_valid"] is False
    assert any("cannot contain your username" in err for err in res_user["errors"])

    # Reversed username in password
    res_rev = validate_password("Secret2024ecilA!", username="Alice", email="alice@test.com")
    assert res_rev["is_valid"] is False
    assert any("reversed username" in err for err in res_rev["errors"])

    # Email token in password
    res_email = validate_password("Secret2024JohnDoe!", username="jdoe", email="john.doe@example.com")
    assert res_email["is_valid"] is False
    assert any("parts of your email address" in err or "personal email identifier" in err for err in res_email["errors"])


def test_repetitive_and_sequential_patterns():
    """Passwords with 4+ identical repeated chars or linear sequences must be rejected."""
    # Repeated characters
    res_rep = validate_password("aaaaBC123456!", username="test", email="test@test.com")
    assert res_rep["is_valid"] is False
    assert any("repeated characters" in err for err in res_rep["errors"])

    # Sequential keyboard characters
    res_seq = validate_password("qwertyuiop12345!", username="test", email="test@test.com")
    assert res_seq["is_valid"] is False
    assert any("predictable sequential pattern" in err for err in res_seq["errors"])


def test_passphrase_recognition_and_scoring():
    """Multi-word passphrases should be recognized and rewarded with top strength score."""
    passphrase = "correct horse battery staple"
    assert is_passphrase(passphrase) is True

    res = validate_password(passphrase)
    assert res["is_valid"] is True
    assert res["is_passphrase"] is True
    assert res["score"] == 4
    assert res["strength"] == "strong"
    assert len(res["errors"]) == 0

    # Hyphenated passphrase
    hyphen_passphrase = "mountain-river-sunset-coffee"
    assert is_passphrase(hyphen_passphrase) is True
    res2 = validate_password(hyphen_passphrase)
    assert res2["is_valid"] is True
    assert res2["score"] == 4


def test_register_enforces_password_strength(client):
    """POST /api/auth/register must reject weak passwords and accept strong ones."""
    # 1. Attempt registering with weak common password
    res_weak = client.post("/api/auth/register", json={
        "username": "weakuser",
        "email": "weakuser@example.com",
        "password": "password123"
    })
    assert res_weak.status_code == 400
    data_weak = res_weak.get_json()
    assert "Password does not meet security requirements" in data_weak["message"]
    assert "details" in data_weak
    assert data_weak["details"]["is_valid"] is False
    assert len(data_weak["details"]["errors"]) > 0

    # 2. Attempt registering with password containing username
    res_user = client.post("/api/auth/register", json={
        "username": "charlie",
        "email": "charlie@example.com",
        "password": "CharliePassword2024!"
    })
    assert res_user.status_code == 400
    assert any("username" in err for err in res_user.get_json()["details"]["errors"])

    # 3. Register with strong multi-word passphrase
    res_strong = client.post("/api/auth/register", json={
        "username": "stronguser",
        "email": "stronguser@example.com",
        "password": "sunset-guitar-river-bridge"
    })
    assert res_strong.status_code == 201
    assert res_strong.get_json()["message"] == "User registered successfully."


def test_validate_password_endpoint(client):
    """POST /api/auth/validate-password provides real-time scoring and feedback."""
    res = client.post("/api/auth/validate-password", json={
        "password": "short",
        "username": "test",
        "email": "test@test.com"
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["is_valid"] is False
    assert data["score"] == 0
    assert data["strength"] == "very_weak"
    assert len(data["errors"]) > 0
    assert len(data["suggestions"]) > 0

    # Test strong passphrase
    res_ok = client.post("/api/auth/validate-password", json={
        "password": "vintage-camera-coffee-journal",
        "username": "test",
        "email": "test@test.com"
    })
    assert res_ok.status_code == 200
    data_ok = res_ok.get_json()
    assert data_ok["is_valid"] is True
    assert data_ok["score"] == 4
    assert data_ok["strength"] == "strong"
    assert data_ok["is_passphrase"] is True


def test_change_password_endpoint(client, app):
    """POST /api/auth/change-password validates current password, tests new password quality, and updates hash."""
    old_pwd = "OldOriginalPassword#2024"
    client.post("/api/auth/register", json={
        "username": "changepwd_user",
        "email": "changepwd@example.com",
        "password": old_pwd
    })

    # 1. Wrong current password
    res_bad_curr = client.post("/api/auth/change-password", json={
        "username": "changepwd_user",
        "current_password": "WrongCurrentPassword",
        "new_password": "NewValidSecretPassword#2025"
    })
    assert res_bad_curr.status_code == 401

    # 2. Reusing current password
    res_same = client.post("/api/auth/change-password", json={
        "username": "changepwd_user",
        "current_password": old_pwd,
        "new_password": old_pwd
    })
    assert res_same.status_code == 400
    assert "cannot be the same" in res_same.get_json()["message"]

    # 3. New password too weak (e.g. common password)
    res_weak_new = client.post("/api/auth/change-password", json={
        "username": "changepwd_user",
        "current_password": old_pwd,
        "new_password": "password123"
    })
    assert res_weak_new.status_code == 400
    assert "New password does not meet security requirements" in res_weak_new.get_json()["message"]

    # 4. Successful change with strong passphrase
    new_strong_pwd = "guitar-notebook-winter-coffee"
    res_ok = client.post("/api/auth/change-password", json={
        "username": "changepwd_user",
        "current_password": old_pwd,
        "new_password": new_strong_pwd
    })
    assert res_ok.status_code == 200
    assert res_ok.get_json()["message"] == "Password changed successfully."

    # 5. Verify old password no longer works for login
    res_login_old = client.post("/api/auth/login", json={
        "username": "changepwd_user",
        "password": old_pwd
    })
    assert res_login_old.status_code == 401

    # 6. Verify new password succeeds for login
    res_login_new = client.post("/api/auth/login", json={
        "username": "changepwd_user",
        "password": new_strong_pwd
    })
    assert res_login_new.status_code == 200
