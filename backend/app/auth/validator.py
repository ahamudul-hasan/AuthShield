import os
import re
import math
from pathlib import Path
from typing import Optional, Dict, Any, List, Set
from flask import current_app

# Path to common passwords file
DATA_DIR = Path(__file__).resolve().parent / "data"
COMMON_PASSWORDS_FILE = DATA_DIR / "common_passwords.txt"

# In-memory cached set of common/compromised passwords
_COMMON_PASSWORDS: Optional[Set[str]] = None

# Built-in essential fallback blocklist (used if file is unavailable)
_FALLBACK_COMMON_PASSWORDS: Set[str] = {
    "password", "123456", "12345678", "123456789", "12345", "1234", "qwerty",
    "dragon", "pussy", "baseball", "football", "letmein", "master", "monkey",
    "shadow", "superman", "trustno1", "admin", "admin123", "password123",
    "iloveyou", "princess", "starwars", "welcome", "welcome1", "computer",
    "security", "authshield", "login", "root", "secret", "pass1234"
}

# Known keyboard and numeric walk sequences
_SEQUENCES: List[str] = [
    "0123456789012345",
    "9876543210987654",
    "abcdefghijklmnopqrstuvwxyz",
    "zyxwvutsrqponmlkjihgfedcba",
    "qwertyuiopasdfghjklzxcvbnm",
]


def load_common_passwords() -> Set[str]:
    """
    Load the list of common/compromised passwords into an in-memory set.
    Caches the set after the first load for sub-millisecond lookups.
    """
    global _COMMON_PASSWORDS
    if _COMMON_PASSWORDS is not None:
        return _COMMON_PASSWORDS

    passwords: Set[str] = set(_FALLBACK_COMMON_PASSWORDS)

    if COMMON_PASSWORDS_FILE.is_file():
        try:
            with open(COMMON_PASSWORDS_FILE, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    w = line.strip().lower()
                    if w:
                        passwords.add(w)
        except Exception:
            pass

    _COMMON_PASSWORDS = passwords
    return _COMMON_PASSWORDS


def is_passphrase(password: str) -> bool:
    """
    Detect if the input is a passphrase (e.g. 3 or more distinct words separated
    by spaces, hyphens, or underscores with substantial length).
    NIST SP 800-63B explicitly encourages long passphrases.
    """
    if len(password) < 14:
        return False

    tokens = re.split(r"[\s\-_]+", password.strip())
    # Require at least 3 distinct word tokens of at least 3 characters each
    valid_tokens = [t for t in tokens if len(t) >= 3 and t.isalpha()]
    return len(valid_tokens) >= 3 and len(set(valid_tokens)) >= 3


def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy of the password in bits."""
    if not password:
        return 0.0
    length = len(password)
    freq: Dict[str, int] = {}
    for c in password:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy * length


def validate_password(
    password: str,
    username: Optional[str] = None,
    email: Optional[str] = None,
    min_length: Optional[int] = None,
    max_length: Optional[int] = None,
    min_score: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Validate password strength against NIST SP 800-63B and OWASP standards:
    1. Minimum length (default 10)
    2. Maximum length (default 128, preventing ReDoS / hashing DoS)
    3. Blocklist of common/compromised passwords (RockYou top 10k)
    4. Prohibits username and email identifiers in the password
    5. Detects repetitive or sequential patterns
    6. Rewards passphrases and entropy without forcing arbitrary composition rules

    Returns a dict with:
        is_valid (bool)
        score (int, 0 to 4)
        strength (str)
        errors (list of str)
        suggestions (list of str)
    """
    try:
        cfg = current_app.config
        min_len = min_length or cfg.get("PASSWORD_MIN_LENGTH", 10)
        max_len = max_length or cfg.get("PASSWORD_MAX_LENGTH", 128)
        required_score = min_score or cfg.get("PASSWORD_MIN_SCORE", 2)
    except RuntimeError:
        min_len = min_length or 10
        max_len = max_length or 128
        required_score = min_score or 2

    errors: List[str] = []
    suggestions: List[str] = []

    # 1. Null / Empty Check
    if not password:
        return {
            "is_valid": False,
            "score": 0,
            "strength": "very_weak",
            "errors": ["Password is required."],
            "suggestions": ["Please enter a strong password or passphrase."],
            "is_passphrase": False,
        }

    # 2. Maximum Length Check (Excessively long input handling / DoS mitigation)
    if len(password) > max_len:
        return {
            "is_valid": False,
            "score": 0,
            "strength": "very_weak",
            "errors": [
                f"Password exceeds maximum length of {max_len} characters. "
                "This limit protects system resources against excessive processing."
            ],
            "suggestions": [f"Keep your password under {max_len} characters."],
            "is_passphrase": False,
        }

    # 3. Minimum Length Check
    if len(password) < min_len:
        errors.append(f"Password must be at least {min_len} characters long.")

    lower_pwd = password.lower()

    # 4. Context-Specific Personal Identifiers (Username & Email)
    if username and len(username.strip()) >= 3:
        clean_user = username.strip().lower()
        if clean_user in lower_pwd:
            errors.append("Password cannot contain your username.")
        elif clean_user[::-1] in lower_pwd:
            errors.append("Password cannot contain your reversed username.")

    if email and "@" in email:
        local_part = email.strip().split("@")[0].lower()
        if len(local_part) >= 3 and local_part in lower_pwd:
            errors.append("Password cannot contain parts of your email address.")
        else:
            # Check sub-tokens of email (e.g. john or doe from john.doe)
            subparts = [p for p in re.split(r"[\._\-+]", local_part) if len(p) >= 3]
            for part in subparts:
                if part in lower_pwd:
                    errors.append(f"Password cannot contain personal email identifier '{part}'.")
                    break

    # 5. Common or Known-Compromised Passwords Check
    common_set = load_common_passwords()

    # Direct match against common compromised passwords
    if lower_pwd in common_set:
        errors.append(
            "This password is very common and appears in lists of known compromised passwords. "
            "Please choose a more unique password."
        )

    # Base match: e.g. "password123!", "admin2024"
    stripped_suffix = re.sub(r"[\d!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]+$", "", lower_pwd)
    if len(stripped_suffix) >= 4 and stripped_suffix in common_set and stripped_suffix != lower_pwd:
        errors.append(
            f"This password is based on a common compromised word ('{stripped_suffix}') "
            "with simple numbers or symbols added."
        )

    # 6. Repetitive and Sequential Patterns
    # 4 or more identical consecutive characters (e.g. aaaa, 1111)
    if re.search(r"(.)\1{3,}", password):
        errors.append("Password contains too many consecutive repeated characters.")

    # Extremely low character diversity (e.g. "ababababab")
    if len(password) >= min_len and len(set(password)) <= 3:
        errors.append("Password lacks character diversity (too few unique characters).")

    # Predictable keyboard or numeric sequences of length >= 5
    for seq in _SEQUENCES:
        for i in range(len(seq) - 4):
            sub = seq[i : i + 5]
            if sub in lower_pwd:
                errors.append(f"Password contains a predictable sequential pattern ('{sub}').")
                break
        if errors and "predictable sequential pattern" in errors[-1]:
            break

    # 7. Passphrase Detection & Strength Scoring (0 to 4)
    passphrase_detected = is_passphrase(password)

    # Character class counts
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9\s]", password))
    char_classes = sum([has_lower, has_upper, has_digit, has_symbol])

    score = 0
    if not errors:
        if passphrase_detected:
            # Long multi-word passphrases achieve top strength score
            score = 4
        else:
            # Length bonuses
            if len(password) >= min_len:
                score += 1
            if len(password) >= 14:
                score += 1
            if len(password) >= 18:
                score += 1

            # Diversity bonus
            if char_classes >= 3 and len(password) >= 12:
                score += 1
            if char_classes >= 4 and len(password) >= 14:
                score += 1

            # Cap at 4
            score = min(score, 4)

    # Score-based strength labels
    strength_labels = {
        0: "very_weak",
        1: "weak",
        2: "fair",
        3: "good",
        4: "strong",
    }
    strength = strength_labels.get(score, "weak")

    # If score is lower than required threshold, append error
    if not errors and score < required_score:
        errors.append(
            f"Password is too predictable or lacks sufficient complexity. "
            f"Increase length or combine multiple random words."
        )

    # 8. User-Friendly Suggestions & Guidance
    if len(password) < 14 and not passphrase_detected:
        suggestions.append(
            "Use at least 14 characters or a multi-word passphrase for enhanced security."
        )
    if not passphrase_detected:
        suggestions.append(
            "Tip: You can use spaces or hyphens to create a passphrase (e.g. 'purple tiger dances slowly'). "
            "Passphrases are easy to remember and extremely difficult to crack."
        )
    if char_classes < 2 and not passphrase_detected:
        suggestions.append("Combine letters with numbers or symbols to increase complexity.")

    is_valid = len(errors) == 0

    return {
        "is_valid": is_valid,
        "score": score,
        "strength": strength,
        "errors": errors,
        "suggestions": suggestions,
        "is_passphrase": passphrase_detected,
    }
