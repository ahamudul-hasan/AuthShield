import os
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple, List, Dict, Any
from flask import current_app
from app.extensions import db
from app.models.user import User
from app.models.password_reset_token import PasswordResetToken

# Development-only email outbox (never populated in production)
_DEV_EMAIL_OUTBOX: List[Dict[str, Any]] = []


def generate_reset_token() -> str:
    """Generate a cryptographically random URL-safe reset token (256 bits)."""
    return secrets.token_urlsafe(32)


def hash_reset_token(raw_token: str) -> str:
    """Compute SHA-256 hex digest of a raw password reset token."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def create_password_reset_token(
    user: User,
    ip_address: Optional[str] = None,
    expiry_seconds: Optional[int] = None,
) -> str:
    """
    Create a short-lived, single-use reset token for the given user.
    Invalidates any prior unused reset tokens for the same user.
    Stores ONLY the cryptographic hash in password_reset_tokens; returns the raw token.
    """
    if expiry_seconds is None:
        try:
            expiry_seconds = current_app.config.get("PASSWORD_RESET_TOKEN_EXPIRY_SECONDS", 900)
        except RuntimeError:
            expiry_seconds = 900

    now = datetime.now(timezone.utc)

    # Invalidate any previously issued unused tokens for this user
    prior_tokens = PasswordResetToken.query.filter_by(user_id=user.id, used=False).all()
    for pt in prior_tokens:
        pt.used = True
        pt.used_at = now

    raw_token = generate_reset_token()
    token_hash = hash_reset_token(raw_token)
    expires_at = now + timedelta(seconds=expiry_seconds)

    token_record = PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at,
        used=False,
        ip_address=ip_address,
        created_at=now,
    )
    db.session.add(token_record)
    db.session.commit()

    return raw_token


def build_reset_link(raw_token: str) -> str:
    """Build the frontend reset-password URL containing the reset token."""
    try:
        base_url = current_app.config.get("FRONTEND_URL", "http://localhost:5173").rstrip("/")
    except RuntimeError:
        base_url = "http://localhost:5173"
    return f"{base_url}/reset-password?token={raw_token}"


def send_reset_email_dev_console(
    recipient_email: str,
    raw_token: str,
    expiry_seconds: Optional[int] = None,
) -> None:
    """
    Display password reset links in the development email console ONLY.
    Never logs or stores raw reset tokens in production.
    """
    try:
        is_prod = (
            os.environ.get("FLASK_ENV", "").lower() == "production"
            or (not current_app.debug and not current_app.testing)
        )
        if expiry_seconds is None:
            expiry_seconds = current_app.config.get("PASSWORD_RESET_TOKEN_EXPIRY_SECONDS", 900)
        is_testing = current_app.testing
    except RuntimeError:
        is_prod = True
        is_testing = False
        expiry_seconds = expiry_seconds or 900

    if is_prod:
        # Never log reset tokens in production environments
        return

    reset_link = build_reset_link(raw_token)
    email_entry = {
        "to": recipient_email,
        "subject": "AuthShield 2.0 — Password Reset Request",
        "reset_link": reset_link,
        "token": raw_token,
        "expires_in_minutes": max(1, expiry_seconds // 60),
        "sent_at": datetime.now(timezone.utc).isoformat(),
    }

    _DEV_EMAIL_OUTBOX.append(email_entry)
    if len(_DEV_EMAIL_OUTBOX) > 100:
        _DEV_EMAIL_OUTBOX.pop(0)

    if not is_testing:
        print("\n" + "=" * 68)
        print(" [DEV EMAIL CONSOLE] Password Reset Notification")
        print(f" To:      {recipient_email}")
        print(f" Subject: {email_entry['subject']}")
        print(f" Link:    {reset_link}")
        print(f" Expires: {email_entry['expires_in_minutes']} minute(s)")
        print("=" * 68 + "\n")


def get_dev_email_outbox() -> List[Dict[str, Any]]:
    """Return development outbox messages (empty unless running in debug/testing)."""
    return list(_DEV_EMAIL_OUTBOX)


def clear_dev_email_outbox() -> None:
    """Clear the development email outbox (useful for tests)."""
    _DEV_EMAIL_OUTBOX.clear()


def verify_reset_token(raw_token: str) -> Tuple[Optional[PasswordResetToken], str]:
    """
    Validate a submitted reset token.
    Returns (PasswordResetToken, message) if valid, or (None, reason) if invalid/used/expired.
    """
    if not raw_token or not isinstance(raw_token, str):
        return None, "Invalid or expired password reset token."

    token_hash = hash_reset_token(raw_token.strip())
    record = PasswordResetToken.query.filter_by(token_hash=token_hash).first()

    if not record:
        return None, "Invalid or expired password reset token."

    if record.used:
        return None, "This password reset token has already been used."

    if record.is_expired:
        return None, "This password reset token has expired. Please request a new one."

    return record, "Reset token is valid."


def consume_reset_token(record: PasswordResetToken) -> None:
    """Mark a password reset token as used so it cannot be reused."""
    record.used = True
    record.used_at = datetime.now(timezone.utc)
