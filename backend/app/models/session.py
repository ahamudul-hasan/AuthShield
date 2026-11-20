from datetime import datetime, timezone
from typing import Optional
from app.extensions import db


class UserSession(db.Model):
    """
    Server-side user session model.
    Stores cryptographic SHA-256 hash of the random opaque session token.
    Supports individual and bulk session revocation, idle timeouts, and IP/UA auditing.
    """
    __tablename__ = "user_sessions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    session_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    last_active_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    expires_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False
    )
    is_revoked = db.Column(db.Boolean, nullable=False, default=False)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True)

    user = db.relationship(
        "User",
        backref=db.backref("sessions", lazy="dynamic", cascade="all, delete-orphan")
    )

    @property
    def is_expired(self) -> bool:
        """Return True if session has reached its absolute expiration time."""
        now = datetime.now(timezone.utc)
        if self.expires_at.tzinfo is not None:
            return now > self.expires_at
        return now.replace(tzinfo=None) > self.expires_at

    def is_idle_timeout(self, timeout_seconds: int = 3600) -> bool:
        """Return True if session has been inactive longer than idle timeout."""
        now = datetime.now(timezone.utc)
        active_time = self.last_active_at
        if active_time.tzinfo is not None:
            diff = (now - active_time).total_seconds()
        else:
            diff = (now.replace(tzinfo=None) - active_time).total_seconds()
        return diff > timeout_seconds

    @property
    def is_valid(self) -> bool:
        """Return True if session is not revoked and not expired."""
        return not self.is_revoked and not self.is_expired

    def to_dict(self, is_current: bool = False) -> dict:
        """Return safe representation for session list and revocation views."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_active_at": self.last_active_at.isoformat() if self.last_active_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_current": is_current,
            "is_active": self.is_valid,
        }
