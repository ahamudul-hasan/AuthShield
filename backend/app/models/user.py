from datetime import datetime, timezone
from app.extensions import db


class User(db.Model):
    """User account model supporting Argon2id, bcrypt migration, RBAC, and TOTP MFA."""
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    password_algorithm = db.Column(db.String(32), nullable=False, default="argon2id")
    role = db.Column(db.String(32), nullable=False, default="user")
    totp_secret = db.Column(db.String(255), nullable=True)
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    failed_attempts = db.Column(db.Integer, nullable=False, default=0)
    lockout_until = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    last_login_at = db.Column(db.DateTime(timezone=True), nullable=True)
    password_changed_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True,
        default=lambda: datetime.now(timezone.utc)
    )

    @property
    def is_locked(self) -> bool:
        """Return True if account has an active temporary lockout."""
        if not self.lockout_until:
            return False
        if self.lockout_until.tzinfo is not None:
            return self.lockout_until > datetime.now(timezone.utc)
        return self.lockout_until > datetime.now(timezone.utc).replace(tzinfo=None)

    def to_dict(self, include_admin_fields: bool = False) -> dict:
        """Return safe user dictionary excluding sensitive credentials."""
        data = {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "mfa_enabled": self.mfa_enabled,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
        }
        if include_admin_fields:
            data.update({
                "password_algorithm": self.password_algorithm,
                "failed_attempts": self.failed_attempts,
                "lockout_until": self.lockout_until.isoformat() if self.lockout_until else None,
                "is_locked": self.is_locked,
                "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            })
        return data

    def __repr__(self) -> str:
        return f"<User id={self.id} username='{self.username}' role='{self.role}'>"
