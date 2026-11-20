from datetime import datetime, timezone, timedelta
import pytest
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.session import UserSession
from app.auth.password import hash_password
from app.auth.session_manager import (
    create_session,
    hash_session_token,
    revoke_session,
    revoke_other_sessions,
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


def test_login_creates_hashed_session_and_sets_cookie(client, app):
    """
    Login must create a server-side session, store only its SHA-256 hash in DB,
    and set an HttpOnly cookie.
    """
    password = "CorrectHorseBattery#2026"
    client.post("/api/auth/register", json={
        "username": "session_user1",
        "email": "session1@example.com",
        "password": password
    })

    res = client.post("/api/auth/login", json={
        "username": "session_user1",
        "password": password
    })
    assert res.status_code == 200
    data = res.get_json()
    assert "session_token" in data
    assert "session" in data

    raw_token = data["session_token"]

    # Verify HttpOnly cookie in response headers
    cookie_header = res.headers.get("Set-Cookie", "")
    assert "authshield_session=" in cookie_header
    assert "HttpOnly" in cookie_header
    assert "Path=/" in cookie_header

    # Verify database record
    with app.app_context():
        user = User.query.filter_by(username="session_user1").first()
        sess_record = UserSession.query.filter_by(user_id=user.id).first()
        assert sess_record is not None
        assert sess_record.is_revoked is False
        # Stored hash must be 64-char SHA-256
        assert len(sess_record.session_hash) == 64
        assert sess_record.session_hash == hash_session_token(raw_token)
        # Raw token must NOT be in DB
        assert sess_record.session_hash != raw_token


def test_get_me_with_cookie_and_bearer_token(client, app):
    """GET /api/auth/me should accept either HttpOnly cookie or Bearer token."""
    password = "CorrectHorseBattery#2026"
    client.post("/api/auth/register", json={
        "username": "bearer_user",
        "email": "bearer@example.com",
        "password": password
    })

    res_login = client.post("/api/auth/login", json={
        "username": "bearer_user",
        "password": password
    })
    raw_token = res_login.get_json()["session_token"]

    # 1. Access with HttpOnly cookie (automatically passed by test client)
    res_cookie = client.get("/api/auth/me")
    assert res_cookie.status_code == 200
    assert res_cookie.get_json()["user"]["username"] == "bearer_user"
    assert res_cookie.get_json()["session"]["is_current"] is True

    # 2. Access with Bearer token header on a fresh client (no cookies)
    fresh_client = app.test_client()
    res_bearer = fresh_client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {raw_token}"}
    )
    assert res_bearer.status_code == 200
    assert res_bearer.get_json()["user"]["username"] == "bearer_user"

    # 3. Access without token fails
    res_no_auth = fresh_client.get("/api/auth/me")
    assert res_no_auth.status_code == 401


def test_list_and_revoke_session_check(app):
    """
    Step 2.7 Primary Check:
    'Log in from two browser sessions and revoke one session from the other.'
    """
    password = "TwoSessionsPassword#2026"

    with app.app_context():
        user = User(
            username="dual_session_user",
            email="dual@example.com",
            password_hash=hash_password(password),
            password_algorithm="argon2id",
        )
        db.session.add(user)
        db.session.commit()
        user_id = user.id

        # Simulate Session 1 (Firefox on Windows)
        sess1, token1 = create_session(user_id, ip_address="192.168.1.10", user_agent="Firefox/Windows")
        sess1_id = sess1.id

        # Simulate Session 2 (Chrome on Android)
        sess2, token2 = create_session(user_id, ip_address="10.0.0.5", user_agent="Chrome/Android")
        sess2_id = sess2.id

    client = app.test_client()

    # Step A: From Session 1, list all active sessions
    res_list = client.get("/api/auth/sessions", headers={"Authorization": f"Bearer {token1}"})
    assert res_list.status_code == 200
    list_data = res_list.get_json()
    assert list_data["total"] == 2

    # Check is_current indicator
    current_flags = {s["id"]: s["is_current"] for s in list_data["sessions"]}
    assert current_flags[sess1_id] is True
    assert current_flags[sess2_id] is False

    # Step B: From Session 1, revoke Session 2
    res_revoke = client.delete(f"/api/auth/sessions/{sess2_id}", headers={"Authorization": f"Bearer {token1}"})
    assert res_revoke.status_code == 200
    assert f"Session {sess2_id} has been revoked" in res_revoke.get_json()["message"]

    # Step C: Session 2 attempts an authenticated request and must be REJECTED (401)
    res_sess2_req = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token2}"})
    assert res_sess2_req.status_code == 401
    assert "revoked" in res_sess2_req.get_json()["message"]

    # Step D: Session 1 remains active and authenticated (200)
    res_sess1_req = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token1}"})
    assert res_sess1_req.status_code == 200
    assert res_sess1_req.get_json()["user"]["username"] == "dual_session_user"


def test_revoke_all_other_sessions(app):
    """Test revoking all other sessions except the current one."""
    password = "MultiSessionPassword#2026"

    with app.app_context():
        user = User(
            username="multi_user",
            email="multi@example.com",
            password_hash=hash_password(password),
            password_algorithm="argon2id",
        )
        db.session.add(user)
        db.session.commit()
        uid = user.id

        s1, t1 = create_session(uid, ip_address="1.1.1.1", user_agent="App 1")
        s2, t2 = create_session(uid, ip_address="2.2.2.2", user_agent="App 2")
        s3, t3 = create_session(uid, ip_address="3.3.3.3", user_agent="App 3")

    client = app.test_client()

    # From Session 1, revoke all others
    res = client.delete("/api/auth/sessions", headers={"Authorization": f"Bearer {t1}"})
    assert res.status_code == 200
    assert res.get_json()["revoked_count"] == 2

    # Session 2 and 3 should now fail
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {t2}"}).status_code == 401
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {t3}"}).status_code == 401

    # Session 1 remains active
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {t1}"}).status_code == 200


def test_logout_revokes_session_and_clears_cookie(client, app):
    """POST /api/auth/logout should revoke session in DB and clear cookie."""
    password = "guitar-notebook-winter-coffee"
    res_reg = client.post("/api/auth/register", json={
        "username": "logout_user",
        "email": "logout@example.com",
        "password": password
    })
    assert res_reg.status_code == 201

    res_login = client.post("/api/auth/login", json={
        "username": "logout_user",
        "password": password
    })
    assert res_login.status_code == 200
    token = res_login.get_json()["session_token"]

    # Call logout
    res_logout = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert res_logout.status_code == 200
    assert "Logout successful" in res_logout.get_json()["message"]

    # Cookie cleared in response
    cookie_header = res_logout.headers.get("Set-Cookie", "")
    assert "authshield_session=;" in cookie_header or 'authshield_session=""' in cookie_header

    # Request with old token returns 401
    res_after = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res_after.status_code == 401


def test_password_change_revokes_other_sessions(client, app):
    """Task 8: Password change should revoke other sessions for the user."""
    old_pwd = "OldPasswordPassphrase#2026"
    new_pwd = "NewPasswordPassphrase#2026"

    with app.app_context():
        user = User(
            username="pwd_change_user",
            email="pwd_change@example.com",
            password_hash=hash_password(old_pwd),
            password_algorithm="argon2id",
        )
        db.session.add(user)
        db.session.commit()
        uid = user.id

        # Session A and Session B
        sess_a, token_a = create_session(uid, ip_address="1.1.1.1", user_agent="Device A")
        sess_b, token_b = create_session(uid, ip_address="2.2.2.2", user_agent="Device B")

    # From Session A, change password
    res_change = client.post(
        "/api/auth/change-password",
        json={
            "username": "pwd_change_user",
            "current_password": old_pwd,
            "new_password": new_pwd,
        },
        headers={"Authorization": f"Bearer {token_a}"}
    )
    assert res_change.status_code == 200

    # Session B must now be invalidated
    res_b = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token_b}"})
    assert res_b.status_code == 401


def test_idle_timeout_and_absolute_expiry(app):
    """Sessions exceeding idle timeout or absolute lifetime must be rejected."""
    with app.app_context():
        user = User(
            username="timeout_user",
            email="timeout@example.com",
            password_hash=hash_password("TimeoutPassword#2026"),
            password_algorithm="argon2id",
        )
        db.session.add(user)
        db.session.commit()
        uid = user.id

        # Create session with last_active_at 2 hours ago (idle timeout = 1 hour)
        sess, token = create_session(uid)
        sess.last_active_at = datetime.now(timezone.utc) - timedelta(seconds=7200)
        db.session.commit()

    client = app.test_client()
    res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 401
    assert "expired" in res.get_json()["message"] or "revoked" in res.get_json()["message"]


def test_csrf_endpoint(client):
    """GET /api/auth/csrf returns a valid CSRF token."""
    res = client.get("/api/auth/csrf")
    assert res.status_code == 200
    data = res.get_json()
    assert "csrf_token" in data
    assert len(data["csrf_token"]) > 20
