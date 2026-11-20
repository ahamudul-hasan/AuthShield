import secrets
import hashlib
from datetime import datetime, timezone
from typing import List, Tuple, Optional
from flask import current_app
from app.extensions import db
from app.models.recovery_code import RecoveryCode

# Crockford Base32-inspired charset excluding ambiguous characters (0, O, 1, I, L)
_CHARSET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"


def normalize_recovery_code(code: str) -> str:
    """Normalize recovery code by stripping whitespace and dashes and converting to uppercase."""
    if not code:
        return ""
    return str(code).strip().replace("-", "").replace(" ", "").upper()


def generate_single_code() -> str:
    """Generate a single formatted recovery code (e.g. 'K9W2P-R4M7T')."""
    part1 = "".join(secrets.choice(_CHARSET) for _ in range(5))
    part2 = "".join(secrets.choice(_CHARSET) for _ in range(5))
    return f"{part1}-{part2}"


def hash_recovery_code(code: str, user_id: int) -> str:
    """
    Hash a normalized recovery code using salted SHA-256.
    Salted with user_id to prevent rainbow table or cross-account attacks.
    """
    normalized = normalize_recovery_code(code)
    salt_prefix = f"authshield:recovery:{user_id}:"
    return hashlib.sha256(f"{salt_prefix}{normalized}".encode("utf-8")).hexdigest()


def generate_user_recovery_codes(
    user_id: int,
    count: Optional[int] = None,
    invalidate_existing: bool = True
) -> List[str]:
    """
    Generate a set of one-time recovery codes for a user.
    Stores only salted cryptographic hashes in the database.
    Returns the list of plaintext codes to be displayed to the user ONCE.
    """
    if count is None:
        try:
            count = current_app.config.get("RECOVERY_CODE_COUNT", 8)
        except RuntimeError:
            count = 8

    if invalidate_existing:
        # Delete any previous unused or used recovery codes for this user
        RecoveryCode.query.filter_by(user_id=user_id).delete()

    plain_codes: List[str] = []
    seen_normalized = set()

    while len(plain_codes) < count:
        code = generate_single_code()
        norm = normalize_recovery_code(code)
        if norm not in seen_normalized:
            seen_normalized.add(norm)
            plain_codes.append(code)

            code_hash = hash_recovery_code(code, user_id)
            rec_obj = RecoveryCode(
                user_id=user_id,
                code_hash=code_hash,
                used=False,
                created_at=datetime.now(timezone.utc),
            )
            db.session.add(rec_obj)

    db.session.commit()
    return plain_codes


def verify_and_consume_recovery_code(
    user_id: int,
    code: str
) -> Tuple[bool, str]:
    """
    Verify a supplied recovery code against stored hashes and mark it as consumed.

    Returns:
        tuple (success: bool, message: str)
    """
    if not code:
        return False, "Recovery code is required."

    target_hash = hash_recovery_code(code, user_id)

    # Look up matching record for this user
    rec = RecoveryCode.query.filter_by(user_id=user_id, code_hash=target_hash).first()

    if not rec:
        return False, "Invalid recovery code."

    if rec.used:
        return False, "This recovery code has already been used."

    # Mark as used (one-time use guarantee)
    rec.used = True
    rec.used_at = datetime.now(timezone.utc)
    db.session.commit()

    return True, "Recovery code verified successfully."


def get_remaining_recovery_codes_count(user_id: int) -> int:
    """Return count of remaining unused recovery codes for a user."""
    return RecoveryCode.query.filter_by(user_id=user_id, used=False).count()
