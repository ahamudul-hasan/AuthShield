import pytest
from app import create_app
from app.extensions import db
from app.models.user import User
from app.auth.password import hash_password
from app.auth.session_manager import create_session
from app.detection.events import get_recent_security_events, clear_recent_security_events, EVENT_ADMIN_ACTION


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


def test_unauthenticated_requests_rejected_401(client):
    """Protected endpoints must reject unauthenticated callers with 401 Unauthorized."""
    endpoints = [
        ("GET", "/api/alerts"),
        ("GET", "/api/dashboard/stats"),
        ("GET", "/api/dashboard/summary"),
        ("GET", "/api/users"),
        ("GET", "/api/events"),
        ("PATCH", "/api/users/1/role"),
        ("PATCH", "/api/users/1/status"),
    ]
    for method, path in endpoints:
        res = client.open(path, method=method)
        assert res.status_code == 401, f"{method} {path} returned {res.status_code} instead of 401"


def test_normal_user_forbidden_from_admin_endpoints_403(client, app):
    """Step 2.9 Check: Confirm that a normal user receives 403 Forbidden on admin-only APIs."""
    pwd = "guitar-notebook-winter-coffee"
    res_reg = client.post("/api/auth/register", json={
        "username": "ordinary_user",
        "email": "ordinary@example.com",
        "password": pwd,
    })
    assert res_reg.status_code == 201
    assert res_reg.get_json()["user"]["role"] == "user"

    res_login = client.post("/api/auth/login", json={
        "username": "ordinary_user",
        "password": pwd,
    })
    token = res_login.get_json()["session_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Attempt to access admin-only endpoints as a normal user
    for method, path, payload in [
        ("GET", "/api/alerts", None),
        ("GET", "/api/dashboard/stats", None),
        ("GET", "/api/dashboard/summary", None),
        ("GET", "/api/users", None),
        ("GET", "/api/events", None),
        ("PATCH", "/api/users/1/role", {"role": "admin"}),
        ("PATCH", "/api/users/1/status", {"is_active": False}),
    ]:
        res = client.open(path, method=method, headers=headers, json=payload)
        assert res.status_code == 403, f"Expected 403 on {method} {path}, got {res.status_code}"
        assert res.get_json()["error"] == "Forbidden"

    # Normal user CAN manage their own account and sessions
    assert client.get("/api/auth/me", headers=headers).status_code == 200
    assert client.get("/api/auth/sessions", headers=headers).status_code == 200

    # Verify authorization denial events were recorded
    admin_events = get_recent_security_events(EVENT_ADMIN_ACTION)
    assert any(e["details"].get("action") == "rbac_access_denied" for e in admin_events)


def test_registration_never_accepts_role(client, app):
    """Public registration must reject attempts to pass a role value."""
    res_escalate = client.post("/api/auth/register", json={
        "username": "evil_admin",
        "email": "evil@example.com",
        "password": "guitar-notebook-winter-coffee",
        "role": "admin",
    })
    assert res_escalate.status_code == 403
    assert "not allowed" in res_escalate.get_json()["message"]

    with app.app_context():
        assert User.query.filter_by(username="evil_admin").first() is None


def test_admin_access_and_user_management(client, app):
    """Administrators can view alerts, stats, users, events, and manage roles/statuses."""
    with app.app_context():
        admin = User(
            username="sec_admin",
            email="sec_admin@example.com",
            password_hash=hash_password("sunset-mountain-camera-coffee"),
            password_algorithm="argon2id",
            role="admin",
        )
        member = User(
            username="normal_member",
            email="member@example.com",
            password_hash=hash_password("ocean-breeze-camera-coffee"),
            password_algorithm="argon2id",
            role="user",
        )
        db.session.add_all([admin, member])
        db.session.commit()
        admin_id = admin.id
        member_id = member.id

        _, admin_token = create_session(admin_id, ip_address="127.0.0.1", user_agent="AdminConsole")
        _, member_token = create_session(member_id, ip_address="127.0.0.2", user_agent="MemberBrowser")

    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    member_headers = {"Authorization": f"Bearer {member_token}"}

    # 1. Admin accesses protected endpoints
    assert client.get("/api/alerts", headers=admin_headers).status_code == 200
    res_stats = client.get("/api/dashboard/summary", headers=admin_headers)
    assert res_stats.status_code == 200
    assert res_stats.get_json()["total_users"] == 2

    res_users = client.get("/api/users", headers=admin_headers)
    assert res_users.status_code == 200
    users_payload = res_users.get_json()["users"]
    assert len(users_payload) == 2
    for u in users_payload:
        assert "password_hash" not in u
        assert "totp_secret" not in u

    # 2. Admin cannot demote themselves
    res_self_demote = client.patch(
        f"/api/users/{admin_id}/role",
        headers=admin_headers,
        json={"role": "user"},
    )
    assert res_self_demote.status_code == 400

    # 3. Admin promotes normal_member to admin -> revokes member's old session
    res_promote = client.patch(
        f"/api/users/{member_id}/role",
        headers=admin_headers,
        json={"role": "admin"},
    )
    assert res_promote.status_code == 200
    assert res_promote.get_json()["user"]["role"] == "admin"

    # Old session was revoked on privilege change
    assert client.get("/api/auth/me", headers=member_headers).status_code == 401

    # 4. Admin deactivates user account
    res_deactivate = client.patch(
        f"/api/users/{member_id}/status",
        headers=admin_headers,
        json={"is_active": False},
    )
    assert res_deactivate.status_code == 200
    assert res_deactivate.get_json()["user"]["is_active"] is False

    # Events endpoint reflects recorded admin actions
    res_events = client.get("/api/events", headers=admin_headers)
    assert res_events.status_code == 200
    assert res_events.get_json()["total"] >= 2


def test_cli_create_admin_command(app):
    """flask create-admin CLI command creates an admin account securely."""
    runner = app.test_cli_runner()

    # 1. Weak password rejected
    res_weak = runner.invoke(
        args=[
            "create-admin",
            "--username", "cli_admin",
            "--email", "cli_admin@example.com",
            "--password", "password123",
        ]
    )
    assert res_weak.exit_code != 0
    assert "Password rejected" in res_weak.output

    # 2. Strong passphrase succeeds
    res_ok = runner.invoke(
        args=[
            "create-admin",
            "--username", "cli_admin",
            "--email", "cli_admin@example.com",
            "--password", "sunset-guitar-winter-coffee",
        ]
    )
    assert res_ok.exit_code == 0
    assert "created successfully" in res_ok.output

    with app.app_context():
        admin = User.query.filter_by(username="cli_admin").first()
        assert admin is not None
        assert admin.role == "admin"
        assert admin.password_hash.startswith("$argon2id$v=19$")

    # 3. Duplicate username fails cleanly
    res_dup = runner.invoke(
        args=[
            "create-admin",
            "--username", "cli_admin",
            "--email", "other_admin@example.com",
            "--password", "sunset-guitar-winter-coffee",
        ]
    )
    assert res_dup.exit_code != 0
    assert "already registered" in res_dup.output
