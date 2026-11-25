from datetime import datetime, timezone
from app.extensions import db


class PasswordResetToken(db.Model):
    """
    Expiring, single-use password reset token model.
    Stores only the SHA-256 hash of the random reset token.
    """
    __tablename__ = "password_reset_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    used = db.Column(db.Boolean, nullable=False, default=False)
    used_at = db.Column(db.DateTime(timezone=True), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    user = db.relationship(
        "User",
        backref=db.backref("password_reset_tokens", lazy="dynamic", cascade="all, delete-orphan"),
    )

    @property
    def is_expired(self) -> bool:
        """Return True if the reset token has passed its expiration timestamp."""
        now = datetime.now(timezone.utc)
        if self.expires_at.tzinfo is not None:
            return now > self.expires_at
        return now.replace(tzinfo=None) > self.expires_at

    @property
    def is_valid(self) -> bool:
        """Return True only if the token has not been used and is not expired."""
        return not self.used and not self.is_expired

    def to_dict(self) -> dict:
        """Return safe representation excluding token_hash."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "used": self.used,
            "used_at": self.used_at.isoformat() if self.used_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
