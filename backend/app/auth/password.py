import time
import bcrypt
from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from flask import current_app


def get_argon2_hasher() -> PasswordHasher:
    """Return an Argon2id PasswordHasher configured with application settings."""
    try:
        config = current_app.config
        time_cost = config.get("ARGON2_TIME_COST", 2)
        memory_cost = config.get("ARGON2_MEMORY_COST", 19456)
        parallelism = config.get("ARGON2_PARALLELISM", 1)
        hash_len = config.get("ARGON2_HASH_LEN", 32)
        salt_len = config.get("ARGON2_SALT_LEN", 16)
    except RuntimeError:
        # Fallback defaults when outside Flask application context
        time_cost = 2
        memory_cost = 19456
        parallelism = 1
        hash_len = 32
        salt_len = 16

    return PasswordHasher(
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=hash_len,
        salt_len=salt_len,
        type=Type.ID
    )


def identify_algorithm(stored_hash: str) -> str:
    """Identify the hashing algorithm from the stored hash string prefix."""
    if not stored_hash:
        return "unknown"
    if stored_hash.startswith("$argon2"):
        return "argon2id"
    if stored_hash.startswith(("$2a$", "$2b$", "$2y$")):
        return "bcrypt"
    if len(stored_hash) == 32 and all(c in "0123456789abcdefABCDEF" for c in stored_hash):
        return "md5"
    return "unknown"


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password using Argon2id encoded format."""
    if not plain_password:
        raise ValueError("Password cannot be empty.")
    hasher = get_argon2_hasher()
    return hasher.hash(plain_password)


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """
    Verify a plaintext password against an encoded hash.
    Supports both Argon2id and legacy bcrypt hashes.
    """
    if not plain_password or not stored_hash:
        return False

    algo = identify_algorithm(stored_hash)

    if algo == "argon2id":
        hasher = get_argon2_hasher()
        try:
            return hasher.verify(stored_hash, plain_password)
        except (VerifyMismatchError, InvalidHashError):
            return False

    if algo == "bcrypt":
        try:
            return bcrypt.checkpw(plain_password.encode("utf-8"), stored_hash.encode("utf-8"))
        except (ValueError, TypeError):
            return False

    return False


def needs_rehash(stored_hash: str) -> bool:
    """
    Check if a stored hash needs to be upgraded to current Argon2id parameters.
    Returns True if the hash is bcrypt or uses older Argon2 parameters.
    """
    if not stored_hash:
        return True

    algo = identify_algorithm(stored_hash)
    if algo != "argon2id":
        return True

    hasher = get_argon2_hasher()
    try:
        return hasher.check_needs_rehash(stored_hash)
    except Exception:
        return True


def benchmark_argon2(iterations: int = 5) -> dict:
    """
    Benchmark Argon2id performance on the current system.
    Returns execution timing in milliseconds and configuration parameters.
    """
    hasher = get_argon2_hasher()
    test_password = "BenchmarkTestPassword!123"

    # Warm-up run
    hasher.hash(test_password)

    start = time.perf_counter()
    for _ in range(iterations):
        hasher.hash(test_password)
    total_time = time.perf_counter() - start

    avg_seconds = total_time / iterations
    avg_ms = avg_seconds * 1000
    hashes_per_sec = 1.0 / avg_seconds if avg_seconds > 0 else 0

    return {
        "algorithm": "argon2id",
        "iterations": iterations,
        "avg_duration_ms": round(avg_ms, 2),
        "hashes_per_second": round(hashes_per_sec, 2),
        "time_cost": hasher.time_cost,
        "memory_cost_kib": hasher.memory_cost,
        "memory_cost_mib": round(hasher.memory_cost / 1024, 2),
        "parallelism": hasher.parallelism,
    }
