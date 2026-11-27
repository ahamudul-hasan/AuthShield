from datetime import datetime, timezone, timedelta
import pytest
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.security_event import SecurityEvent, hash_attempted_identifier
from app.detection.event_types import (
    EVENT_LOGIN_FAILURE,
    EVENT_LOGIN_SUCCESS,
    EVENT_USER_REGISTERED,
)
from app.detection.event_collector import (
    record_security_event,
    sanitize_details,
    sanitize_string,
    clear_recent_security_events,
)
from app.detection.event_repository import (
    query_events,
    count_events,
    count_total_events,
    purge_expired_events,
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


def test_collector_persists_events_and_redacts_secrets(app):
    """Collector must redact passwords, TOTP codes, tokens, cookies, and sanitize control chars."""
    with app.app_context():
        payload = record_security_event(
            EVENT_LOGIN_FAILURE,
            source_ip="198.51.100.77",
            user_agent="EvilAgent\r\nInjectedHeader: value\x00",
            raw_identifier="SomeTypedUser",
            success=False,
            details={
                "password": "MyPlaintextPassword!",
                "totp_code": "123456",
                "session_token": "raw-cookie-secret",
                "reset_token": "raw-reset-token",
                "recovery_code": "K9W2P-R4M7T",
                "nested": {"cookie": "abc=123", "reason": "bad_creds\nforged_line"},
            },
        )

        assert payload["id"] is not None
        assert payload["details"]["password"] == "[REDACTED]"
        assert payload["details"]["totp_code"] == "[REDACTED]"
        assert payload["details"]["session_token"] == "[REDACTED]"
        assert payload["details"]["reset_token"] == "[REDACTED]"
        assert payload["details"]["recovery_code"] == "[REDACTED]"
        assert payload["details"]["nested"]["cookie"] == "[REDACTED]"
        assert "\n" not in payload["details"]["nested"]["reason"]
        assert "\r" not in payload["user_agent"]
        assert "\n" not in payload["user_agent"]

        row = db.session.get(SecurityEvent, payload["id"])
        assert row is not None
        assert row.details["password"] == "[REDACTED]"
        assert row.details["totp_code"] == "[REDACTED]"
        assert row.attempted_identifier == hash_attempted_identifier("sometypeduser")
        assert "SomeTypedUser" not in str(row.to_dict())


def test_untrusted_proxy_headers_ignored_and_trusted_proxy_respected(app):
    """X-Forwarded-For must be ignored unless peer IP is explicitly configured in TRUSTED_PROXIES."""
    # 1. Untrusted peer tries spoofing X-Forwarded-For
    with app.test_request_context(
        "/api/auth/login",
        method="POST",
        environ_base={"REMOTE_ADDR": "203.0.113.10"},
        headers={"X-Forwarded-For": "8.8.8.8"},
    ):
        ev_untrusted = record_security_event(EVENT_LOGIN_FAILURE, success=False)
        assert ev_untrusted["source_ip"] == "203.0.113.10"

    # 2. Trusted reverse proxy resolves real client IP
    app.config["TRUSTED_PROXIES"] = ["127.0.0.1"]
    with app.test_request_context(
        "/api/auth/login",
        method="POST",
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
        headers={"X-Forwarded-For": "198.51.100.42, 127.0.0.1"},
    ):
        ev_trusted = record_security_event(EVENT_LOGIN_FAILURE, success=False)
        assert ev_trusted["source_ip"] == "198.51.100.42"


def test_repository_query_count_and_retention_purge(app):
    """Repository must filter, count, paginate, and purge events older than retention policy."""
    with app.app_context():
        now = datetime.now(timezone.utc)
        old_ev = SecurityEvent(
            event_type=EVENT_LOGIN_FAILURE,
            source_ip="192.0.2.1",
            success=False,
            timestamp=now - timedelta(days=120),
            details={"age": "expired"},
        )
        recent_ev1 = SecurityEvent(
            event_type=EVENT_LOGIN_FAILURE,
            source_ip="192.0.2.2",
            success=False,
            timestamp=now - timedelta(days=5),
            details={"age": "recent"},
        )
        recent_ev2 = SecurityEvent(
            event_type=EVENT_LOGIN_SUCCESS,
            source_ip="192.0.2.2",
            success=True,
            timestamp=now - timedelta(minutes=10),
            details={"age": "fresh"},
        )
        db.session.add_all([old_ev, recent_ev1, recent_ev2])
        db.session.commit()

        assert count_total_events() == 3
        assert count_events(source_ip="192.0.2.2", success=False) == 1

        events, total = query_events(source_ip="192.0.2.2", limit=1, offset=0)
        assert total == 2
        assert len(events) == 1
        assert events[0].event_type == EVENT_LOGIN_SUCCESS  # ordered newest first

        # Apply 90-day retention policy -> deletes old_ev only
        purged = purge_expired_events(retention_days=90)
        assert purged == 1
        assert count_total_events() == 2


def test_end_to_end_actions_persist_structured_events_to_db(client, app):
    """Step 3.3 Check: Trigger several test actions and verify safe structured DB events."""
    pwd = "guitar-notebook-winter-coffee"

    # 1. Register user
    assert client.post("/api/auth/register", json={
        "username": "collector_user",
        "email": "collector@example.com",
        "password": pwd,
    }).status_code == 201

    # 2. Failed login on unknown account -> stores HMAC attempted_identifier, user_id=None
    assert client.post("/api/auth/login", json={
        "username": "ghost_account",
        "password": "WrongPassword123!",
    }).status_code == 401

    # 3. Failed login on existing account -> stores user_id and HMAC identifier
    assert client.post("/api/auth/login", json={
        "username": "collector_user",
        "password": "WrongPassword123!",
    }).status_code == 401

    # 4. Successful login -> stores LOGIN_SUCCESS + SESSION_CREATED
    assert client.post("/api/auth/login", json={
        "username": "collector_user",
        "password": pwd,
    }).status_code == 200

    with app.app_context():
        all_rows, total = query_events(limit=50)
        assert total >= 5
        event_types = {row.event_type for row in all_rows}
        assert {EVENT_USER_REGISTERED, EVENT_LOGIN_FAILURE, EVENT_LOGIN_SUCCESS}.issubset(event_types)

        # Confirm unknown user failure has HMAC attempted_identifier and no plaintext username
        ghost_hmac = hash_attempted_identifier("ghost_account")
        ghost_count = count_events(event_type=EVENT_LOGIN_FAILURE, attempted_identifier=ghost_hmac)
        assert ghost_count == 1
        for row in all_rows:
            serialized = str(row.to_dict())
            assert pwd not in serialized
            assert "WrongPassword123!" not in serialized
            assert "ghost_account" not in serialized
