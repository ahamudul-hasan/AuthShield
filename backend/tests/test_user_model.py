import pytest
from datetime import datetime, timedelta, timezone
from sqlalchemy.exc import IntegrityError
from app import create_app
from app.extensions import db
from app.models.user import User


@pytest.fixture
def app():
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def test_create_user_defaults(app):
    """Test user creation with default fields and timestamps."""
    user = User(
        username="alice",
        email="alice@example.com",
        password_hash="argon2_fake_hash_value",
        password_algorithm="argon2id"
    )
    db.session.add(user)
    db.session.commit()

    saved = User.query.filter_by(username="alice").first()
    assert saved is not None
    assert saved.id is not None
    assert saved.role == "user"
    assert saved.mfa_enabled is False
    assert saved.failed_attempts == 0
    assert saved.is_active is True
    assert saved.is_locked is False
    assert saved.created_at is not None
    assert saved.updated_at is not None


def test_user_lockout_property(app):
    """Test is_locked property against future and past timestamps."""
    user = User(
        username="bob",
        email="bob@example.com",
        password_hash="hash",
        lockout_until=datetime.now(timezone.utc) + timedelta(minutes=15)
    )
    assert user.is_locked is True

    user.lockout_until = datetime.now(timezone.utc) - timedelta(minutes=1)
    assert user.is_locked is False

    user.lockout_until = None
    assert user.is_locked is False


def test_user_to_dict_security(app):
    """Ensure sensitive credentials are never leaked in to_dict()."""
    user = User(
        username="charlie",
        email="charlie@example.com",
        password_hash="secret_hash_value",
        totp_secret="secret_mfa_token",
        role="user"
    )
    safe_data = user.to_dict()
    assert "password_hash" not in safe_data
    assert "totp_secret" not in safe_data
    assert safe_data["username"] == "charlie"
    assert safe_data["email"] == "charlie@example.com"

    admin_data = user.to_dict(include_admin_fields=True)
    assert "password_hash" not in admin_data
    assert "totp_secret" not in admin_data
    assert "failed_attempts" in admin_data
    assert "is_locked" in admin_data


def test_unique_constraints(app):
    """Ensure duplicate usernames and emails are rejected."""
    u1 = User(username="dave", email="dave@example.com", password_hash="h1")
    db.session.add(u1)
    db.session.commit()

    # Duplicate username
    u2 = User(username="dave", email="dave2@example.com", password_hash="h2")
    db.session.add(u2)
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    # Duplicate email
    u3 = User(username="dave3", email="dave@example.com", password_hash="h3")
    db.session.add(u3)
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()
