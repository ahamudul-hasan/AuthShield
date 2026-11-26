import hashlib
import hmac
import os
from datetime import datetime, timezone
from typing import Optional
from flask import current_app
from sqlalchemy.dialects.postgresql import JSONB
from app.extensions import db


def hash_attempted_identifier(identifier: Optional[str]) -> Optional[str]:
    """
    Compute a keyed HMAC-SHA256 digest of a normalized login identifier.
    Allows counting attempts against non-existent accounts without storing
    the raw typed username (which may accidentally contain a password).
    """
    if not identifier or not isinstance(identifier, str):
        return None
    normalized = identifier.strip().lower()
    if not normalized:
        return None

    try:
        key = current_app.config.get("EVENT_HMAC_KEY") or current_app.config.get("SECRET_KEY", "dev-hmac-key")
    except RuntimeError:
        key = os.environ.get("EVENT_HMAC_KEY") or os.environ.get("SECRET_KEY", "dev-hmac-key")

    return hmac.new(key.encode("utf-8"), normalized.encode("utf-8"), hashlib.sha256).hexdigest()


class SecurityEvent(db.Model):
    """
    Structured authentication and security activity record (Step 3.2).
    Uses JSONB on PostgreSQL and JSON on SQLite for `details`.
    """
    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(64), nullable=False, index=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    source_ip = db.Column(db.String(45), nullable=True, index=True)
    user_agent = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    success = db.Column(db.Boolean, nullable=True)
    attempted_identifier = db.Column(db.String(64), nullable=True, index=True)
    details = db.Column(
        db.JSON().with_variant(JSONB(), "postgresql"),
        nullable=False,
        default=dict,
    )

    user = db.relationship(
        "User",
        backref=db.backref("security_events", lazy="dynamic", passive_deletes=True),
    )

    def to_dict(self) -> dict:
        """Return JSON-safe representation of the security event."""
        return {
            "id": self.id,
            "event_type": self.event_type,
            "user_id": self.user_id,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "success": self.success,
            "attempted_identifier": self.attempted_identifier,
            "details": self.details or {},
        }
