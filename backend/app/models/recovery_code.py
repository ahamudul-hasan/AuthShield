from datetime import datetime, timezone
from app.extensions import db


class RecoveryCode(db.Model):
    """
    Hashed, one-time recovery codes for account recovery when a TOTP device is lost.
    Only cryptographic hashes of codes are stored at rest.
    """
    __tablename__ = "recovery_codes"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    code_hash = db.Column(db.String(255), nullable=False, index=True)
    used = db.Column(db.Boolean, nullable=False, default=False)
    used_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    user = db.relationship(
        "User",
        backref=db.backref("recovery_codes", lazy="dynamic", cascade="all, delete-orphan")
    )

    def to_dict(self) -> dict:
        """Return safe dictionary for administration and status views."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "used": self.used,
            "used_at": self.used_at.isoformat() if self.used_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
