import pytest
import bcrypt
from argon2 import PasswordHasher
from app import create_app
from app.extensions import db
from app.models.user import User
from app.auth.password import hash_password, verify_password, needs_rehash, benchmark_argon2


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


def test_argon2_hash_and_verify():
    """Verify Argon2id produces valid encoded format and verifies correctly."""
    pwd = "TestSecretPassword#2026"
    h = hash_password(pwd)
    assert h.startswith("$argon2id$v=19$")
    assert verify_password(pwd, h) is True
    assert verify_password("WrongPassword", h) is False
    assert verify_password("", h) is False


def test_register_creates_argon2_user(client, app):
    """Test user registration hashes password with Argon2id and stores it."""
    payload = {
        "username": "testuser",
        "email": "testuser@example.com",
        "password": "CorrectPassword123!"
    }
    res = client.post("/api/auth/register", json=payload)
    assert res.status_code == 201
    data = res.get_json()
    assert data["message"] == "User registered successfully."
    assert data["password_algorithm"] == "argon2id"
    assert data["user"]["username"] == "testuser"

    with app.app_context():
        user = User.query.filter_by(username="testuser").first()
        assert user is not None
        assert user.password_hash.startswith("$argon2id$v=19$")
        assert user.password_algorithm == "argon2id"
        assert verify_password("CorrectPassword123!", user.password_hash) is True


def test_login_correct_and_wrong_password(client):
    """Test login success and failure responses."""
    client.post("/api/auth/register", json={
        "username": "loginuser",
        "email": "loginuser@example.com",
        "password": "MySecretPassword123"
    })

    # Correct login
    res_ok = client.post("/api/auth/login", json={
        "username": "loginuser",
        "password": "MySecretPassword123"
    })
    assert res_ok.status_code == 200
    assert res_ok.get_json()["message"] == "Login successful."
    assert res_ok.get_json()["user"]["username"] == "loginuser"

    # Wrong password
    res_err = client.post("/api/auth/login", json={
        "username": "loginuser",
        "password": "IncorrectPassword"
    })
    assert res_err.status_code == 401
    assert "Invalid username or password" in res_err.get_json()["message"]
    assert res_err.get_json()["attempts_remaining"] == 4


def test_account_lockout_after_max_failures(client, app):
    """Test account is locked after 5 consecutive failed attempts."""
    client.post("/api/auth/register", json={
        "username": "lockoutvictim",
        "email": "lockout@example.com",
        "password": "CorrectPassword123"
    })

    # Fail 5 times
    for i in range(5):
        res = client.post("/api/auth/login", json={
            "username": "lockoutvictim",
            "password": "WrongPassword"
        })
        assert res.status_code == 401

    # 6th attempt should be blocked with 403 Forbidden
    res_locked = client.post("/api/auth/login", json={
        "username": "lockoutvictim",
        "password": "CorrectPassword123"
    })
    assert res_locked.status_code == 403
    assert "temporarily locked" in res_locked.get_json()["message"]


def test_rehash_and_upgrade_on_login(client, app):
    """Test that an older or bcrypt hash is automatically upgraded to Argon2id on successful login."""
    # Seed a user with a legacy bcrypt hash
    raw_pwd = "OldBcryptPassword"
    bcrypt_hash = bcrypt.hashpw(raw_pwd.encode(), bcrypt.gensalt(rounds=10)).decode()

    with app.app_context():
        legacy_user = User(
            username="migrateduser",
            email="migrated@example.com",
            password_hash=bcrypt_hash,
            password_algorithm="bcrypt"
        )
        db.session.add(legacy_user)
        db.session.commit()

    # Log in with the legacy password
    res = client.post("/api/auth/login", json={
        "username": "migrateduser",
        "password": raw_pwd
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["hash_upgraded"] is True
    assert data["password_algorithm"] == "argon2id"

    # Verify database now stores Argon2id
    with app.app_context():
        updated_user = User.query.filter_by(username="migrateduser").first()
        assert updated_user.password_hash.startswith("$argon2id$v=19$")
        assert updated_user.password_algorithm == "argon2id"
        assert verify_password(raw_pwd, updated_user.password_hash) is True


def test_argon2_benchmark_endpoint(client):
    """Test the benchmark endpoint returns timing and memory metrics."""
    res = client.get("/api/auth/benchmark?iterations=2")
    assert res.status_code == 200
    data = res.get_json()
    assert data["algorithm"] == "argon2id"
    assert data["iterations"] == 2
    assert "avg_duration_ms" in data
    assert "memory_cost_kib" in data
    assert data["avg_duration_ms"] > 0
