import pytest
from sqlalchemy import inspect
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.security_event import SecurityEvent, hash_attempted_identifier
from app.auth.password import hash_password
from app.detection.event_types import EVENT_LOGIN_FAILURE, EVENT_LOGIN_SUCCESS


@pytest.fixture
def app():
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def test_security_event_model_columns_and_indexes(app):
    """Verify required columns, indexes, and absence of reserved 'metadata' column."""
    table = SecurityEvent.__table__
    col_names = set(table.columns.keys())
    expected_cols = {
        "id",
        "event_type",
        "user_id",
        "source_ip",
        "user_agent",
        "timestamp",
        "success",
        "attempted_identifier",
        "details",
    }
    assert expected_cols.issubset(col_names)
    assert "metadata" not in col_names

    with app.app_context():
        inspector = inspect(db.engine)
        indexes = inspector.get_indexes("security_events")
        indexed_cols = {col for idx in indexes for col in idx["column_names"]}
        assert {"event_type", "user_id", "source_ip", "timestamp", "attempted_identifier"}.issubset(indexed_cols)


def test_hmac_attempted_identifier_consistency_and_privacy(app):
    """HMAC attempted_identifier must normalize input, match across retries, and never store raw text."""
    with app.app_context():
        h1 = hash_attempted_identifier("  Alice.Smith ")
        h2 = hash_attempted_identifier("alice.smith")
        h3 = hash_attempted_identifier("bob.jones")

        assert h1 is not None
        assert len(h1) == 64
        assert h1 == h2
        assert h1 != h3
        assert "alice" not in h1
        assert hash_attempted_identifier("") is None
        assert hash_attempted_identifier(None) is None


def test_insert_and_query_security_event(app):
    """Verify inserting and retrieving both known-user and unknown-user SecurityEvents."""
    with app.app_context():
        user = User(
            username="sec_event_user",
            email="sec_event@example.com",
            password_hash=hash_password("sunset-guitar-winter-coffee"),
            password_algorithm="argon2id",
        )
        db.session.add(user)
        db.session.commit()
        uid = user.id

        ev_success = SecurityEvent(
            event_type=EVENT_LOGIN_SUCCESS,
            user_id=uid,
            source_ip="192.168.1.50",
            user_agent="Mozilla/5.0 TestBrowser",
            success=True,
            attempted_identifier=hash_attempted_identifier("sec_event_user"),
            details={"mfa_used": False, "method": "password"},
        )
        ev_unknown_fail = SecurityEvent(
            event_type=EVENT_LOGIN_FAILURE,
            user_id=None,
            source_ip="203.0.113.42",
            user_agent="curl/8.5",
            success=False,
            attempted_identifier=hash_attempted_identifier("nonexistent_admin"),
            details={"reason": "account_not_found"},
        )
        db.session.add_all([ev_success, ev_unknown_fail])
        db.session.commit()

        fetched_success = SecurityEvent.query.filter_by(user_id=uid).first()
        assert fetched_success is not None
        assert fetched_success.event_type == EVENT_LOGIN_SUCCESS
        assert fetched_success.details["method"] == "password"
        assert fetched_success.timestamp is not None

        fetched_fail = SecurityEvent.query.filter_by(
            attempted_identifier=hash_attempted_identifier("NONEXISTENT_ADMIN")
        ).first()
        assert fetched_fail is not None
        assert fetched_fail.user_id is None
        assert fetched_fail.success is False
        assert fetched_fail.source_ip == "203.0.113.42"
        assert fetched_fail.to_dict()["event_type"] == EVENT_LOGIN_FAILURE
