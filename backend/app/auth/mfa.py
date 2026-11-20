import os
import io
import time
import base64
import hashlib
import hmac
from typing import Optional, Tuple, Dict, Any
from flask import current_app
from cryptography.fernet import Fernet, InvalidToken
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import pyotp
import qrcode


def _get_encryption_key() -> bytes:
    """
    Retrieve or derive a 32-byte URL-safe base64-encoded key for Fernet encryption.
    If MFA_ENCRYPTION_KEY is not configured, deterministically derive from SECRET_KEY.
    """
    try:
        raw_key = current_app.config.get("MFA_ENCRYPTION_KEY")
    except RuntimeError:
        raw_key = os.environ.get("MFA_ENCRYPTION_KEY")

    if raw_key:
        if isinstance(raw_key, str):
            raw_key_bytes = raw_key.encode("utf-8")
        else:
            raw_key_bytes = raw_key
        # Verify valid Fernet key length (32 bytes base64-encoded = 44 bytes)
        try:
            Fernet(raw_key_bytes)
            return raw_key_bytes
        except Exception:
            pass

    # Derive from SECRET_KEY using SHA-256
    try:
        secret = current_app.config.get("SECRET_KEY", "fallback-secret-key")
    except RuntimeError:
        secret = os.environ.get("SECRET_KEY", "fallback-secret-key")

    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def get_mfa_cipher() -> Fernet:
    """Return a Fernet cipher instance for encrypting/decrypting MFA secrets at rest."""
    return Fernet(_get_encryption_key())


def encrypt_totp_secret(plain_secret: str) -> str:
    """
    Encrypt a plain base32 TOTP secret at rest.
    Returns the encrypted token as a string.
    """
    if not plain_secret:
        return ""
    cipher = get_mfa_cipher()
    token = cipher.encrypt(plain_secret.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_totp_secret(stored_secret: str) -> str:
    """
    Decrypt an encrypted TOTP secret from storage.
    If the secret is unencrypted legacy base32, handles gracefully without error.
    """
    if not stored_secret:
        return ""
    cipher = get_mfa_cipher()
    try:
        decrypted = cipher.decrypt(stored_secret.encode("utf-8"))
        return decrypted.decode("utf-8")
    except (InvalidToken, Exception):
        # Fallback: stored secret may be raw base32 from legacy records
        return stored_secret


def generate_totp_secret() -> str:
    """Generate a random 32-character base32 TOTP secret."""
    return pyotp.random_base32()


def generate_provisioning_uri(
    secret: str,
    username: str,
    issuer_name: Optional[str] = None
) -> str:
    """
    Generate standard OTPAuth URI for authenticator app enrollment.
    otpauth://totp/Issuer:username?secret=...&issuer=Issuer
    """
    if not issuer_name:
        try:
            issuer_name = current_app.config.get("MFA_ISSUER_NAME", "AuthShield 2.0")
        except RuntimeError:
            issuer_name = "AuthShield 2.0"

    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer_name)


def generate_qr_code_data_uri(provisioning_uri: str) -> str:
    """
    Generate a base64-encoded PNG Data URI for the provisioning QR code.
    Suitable for embedding directly into <img src="data:image/png;base64,...">.
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=3,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    b64_img = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{b64_img}"


def verify_totp_code(
    secret: str,
    code: str,
    last_step: Optional[int] = None,
    valid_window: int = 1
) -> Tuple[bool, Optional[int], Optional[str]]:
    """
    Verify a 6-digit TOTP code against a secret with clock-drift tolerance and replay prevention.

    Args:
        secret: Plain or encrypted TOTP base32 secret.
        code: The 6-digit code supplied by user.
        last_step: The last accepted time step recorded for this user.
        valid_window: Clock-skew window (1 = ±30s, allowing previous, current, next step).

    Returns:
        tuple (is_valid: bool, matched_step: Optional[int], reason: Optional[str])
    """
    if not secret or not code:
        return False, None, "Code and secret are required."

    clean_code = str(code).strip()
    if len(clean_code) != 6 or not clean_code.isdigit():
        return False, None, "MFA code must be exactly 6 numeric digits."

    plain_secret = decrypt_totp_secret(secret)
    totp = pyotp.TOTP(plain_secret)

    current_step = int(time.time() / 30)
    # Check current step first, then adjacent steps within drift window
    steps_to_check = [current_step]
    for offset in range(1, valid_window + 1):
        steps_to_check.append(current_step - offset)
        steps_to_check.append(current_step + offset)

    for step in steps_to_check:
        expected = totp.generate_otp(step)
        if hmac.compare_digest(clean_code, expected):
            # Code matches! Now check for replay attack
            if last_step is not None and step <= last_step:
                return False, None, "This MFA code has already been used. Please wait for the next code."
            return True, step, None

    return False, None, "Invalid or expired MFA code."


def _get_serializer(salt: str) -> URLSafeTimedSerializer:
    try:
        secret = current_app.config.get("SECRET_KEY", "fallback-secret-key")
    except RuntimeError:
        secret = os.environ.get("SECRET_KEY", "fallback-secret-key")
    return URLSafeTimedSerializer(secret, salt=salt)


def generate_pending_mfa_token(user_id: int) -> str:
    """
    Generate a short-lived token representing 'pending MFA' state after password verification.
    Valid for 300 seconds (5 minutes). Does NOT grant a full session.
    """
    s = _get_serializer("mfa-login-pending")
    return s.dumps({"user_id": user_id, "action": "mfa_pending", "iat": int(time.time())})


def verify_pending_mfa_token(token: str, max_age: Optional[int] = None) -> Optional[int]:
    """
    Verify a pending MFA token. Returns user_id if valid, or None if expired/corrupted.
    """
    if not token:
        return None
    if max_age is None:
        try:
            max_age = current_app.config.get("MFA_TOKEN_EXPIRY_SECONDS", 300)
        except RuntimeError:
            max_age = 300

    s = _get_serializer("mfa-login-pending")
    try:
        data = s.loads(token, max_age=max_age)
        if data.get("action") == "mfa_pending":
            return data.get("user_id")
    except (BadSignature, SignatureExpired):
        return None
    return None


def generate_mfa_setup_token(user_id: int, pending_secret: str) -> str:
    """
    Generate a signed setup token for MFA enrollment containing the unconfirmed secret.
    Stateless and valid for 600 seconds (10 minutes).
    """
    s = _get_serializer("mfa-setup-pending")
    return s.dumps({
        "user_id": user_id,
        "secret": pending_secret,
        "action": "mfa_setup",
        "iat": int(time.time()),
    })


def verify_mfa_setup_token(token: str, max_age: int = 600) -> Optional[Dict[str, Any]]:
    """
    Verify an MFA setup token. Returns payload dict with user_id and secret if valid.
    """
    if not token:
        return None
    s = _get_serializer("mfa-setup-pending")
    try:
        data = s.loads(token, max_age=max_age)
        if data.get("action") == "mfa_setup":
            return data
    except (BadSignature, SignatureExpired):
        return None
    return None
