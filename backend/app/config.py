import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///dev.db")
    RATELIMIT_DEFAULT = os.environ.get("RATELIMIT_DEFAULT", "200 per day;50 per hour")
    RATELIMIT_STORAGE_URI = "memory://"

    # Session security
    SESSION_COOKIE_NAME = os.environ.get("SESSION_COOKIE_NAME", "authshield_session")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "False").lower() == "true"
    SESSION_LIFETIME_SECONDS = int(os.environ.get("SESSION_LIFETIME_SECONDS", 86400))
    SESSION_IDLE_TIMEOUT_SECONDS = int(os.environ.get("SESSION_IDLE_TIMEOUT_SECONDS", 3600))
    PERMANENT_SESSION_LIFETIME = SESSION_LIFETIME_SECONDS

    # CSRF protection
    WTF_CSRF_ENABLED = os.environ.get("WTF_CSRF_ENABLED", "False").lower() == "true"
    WTF_CSRF_TIME_LIMIT = None

    # Argon2id Hashing Parameters (OWASP recommended baseline)
    ARGON2_TIME_COST = int(os.environ.get("ARGON2_TIME_COST", 2))
    ARGON2_MEMORY_COST = int(os.environ.get("ARGON2_MEMORY_COST", 19456))  # 19 MiB
    ARGON2_PARALLELISM = int(os.environ.get("ARGON2_PARALLELISM", 1))
    ARGON2_HASH_LEN = int(os.environ.get("ARGON2_HASH_LEN", 32))
    ARGON2_SALT_LEN = int(os.environ.get("ARGON2_SALT_LEN", 16))

    # Account Lockout Policy (5 failed attempts, 15-minute temporary lockout)
    MAX_FAILED_ATTEMPTS = int(os.environ.get("MAX_FAILED_ATTEMPTS", 5))
    LOCKOUT_DURATION_MINUTES = int(os.environ.get("LOCKOUT_DURATION_MINUTES", 15))

    # Password Validation Policy (NIST SP 800-63B compliant)
    PASSWORD_MIN_LENGTH = int(os.environ.get("PASSWORD_MIN_LENGTH", 10))
    PASSWORD_MAX_LENGTH = int(os.environ.get("PASSWORD_MAX_LENGTH", 128))
    PASSWORD_MIN_SCORE = int(os.environ.get("PASSWORD_MIN_SCORE", 2))

    # TOTP MFA & Encryption at Rest Configuration
    MFA_ISSUER_NAME = os.environ.get("MFA_ISSUER_NAME", "AuthShield 2.0")
    MFA_TOKEN_EXPIRY_SECONDS = int(os.environ.get("MFA_TOKEN_EXPIRY_SECONDS", 300))  # 5 minutes
    MFA_ENCRYPTION_KEY = os.environ.get("MFA_ENCRYPTION_KEY", None)
    MFA_VALID_WINDOW = int(os.environ.get("MFA_VALID_WINDOW", 1))  # ±30s clock skew tolerance

    # Recovery Codes Configuration
    RECOVERY_CODE_COUNT = int(os.environ.get("RECOVERY_CODE_COUNT", 8))

    # Password Reset Configuration
    PASSWORD_RESET_TOKEN_EXPIRY_SECONDS = int(os.environ.get("PASSWORD_RESET_TOKEN_EXPIRY_SECONDS", 900))  # 15 minutes
    FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:5173")

    # Security Event Collection & Retention Configuration (Step 3.3 / 3.4)
    EVENT_HMAC_KEY = os.environ.get("EVENT_HMAC_KEY", None)
    EVENT_RETENTION_DAYS = int(os.environ.get("EVENT_RETENTION_DAYS", 90))
    TRUSTED_PROXIES = [
        p.strip() for p in os.environ.get("TRUSTED_PROXIES", "").split(",") if p.strip()
    ]
    AUTH_LOG_ENABLED = os.environ.get("AUTH_LOG_ENABLED", "True").lower() == "true"
    AUTH_LOG_PATH = os.environ.get("AUTH_LOG_PATH", str(BASE_DIR.parent / "logs" / "auth.log"))

    # Threat Detection Engine Configuration (Stage 4)
    DETECTOR_REALTIME_ENABLED = os.environ.get("DETECTOR_REALTIME_ENABLED", "True").lower() == "true"
    DETECTOR_SCHEDULER_ENABLED = os.environ.get("DETECTOR_SCHEDULER_ENABLED", "False").lower() == "true"
    DETECTOR_SWEEP_INTERVAL_SECONDS = int(os.environ.get("DETECTOR_SWEEP_INTERVAL_SECONDS", 60))

    # Step 4.2: Brute-Force Detection Thresholds
    BRUTE_FORCE_THRESHOLD = int(os.environ.get("BRUTE_FORCE_THRESHOLD", 5))
    BRUTE_FORCE_WINDOW_MINUTES = int(os.environ.get("BRUTE_FORCE_WINDOW_MINUTES", 5))
    BRUTE_FORCE_POINTS = int(os.environ.get("BRUTE_FORCE_POINTS", 60))

    # Step 4.3: Credential-Stuffing Detection Thresholds
    CREDENTIAL_STUFFING_THRESHOLD = int(os.environ.get("CREDENTIAL_STUFFING_THRESHOLD", 10))
    CREDENTIAL_STUFFING_WINDOW_MINUTES = int(os.environ.get("CREDENTIAL_STUFFING_WINDOW_MINUTES", 10))
    CREDENTIAL_STUFFING_POINTS = int(os.environ.get("CREDENTIAL_STUFFING_POINTS", 40))

    # Step 4.4: Password-Spraying Detection Thresholds
    PASSWORD_SPRAY_THRESHOLD = int(os.environ.get("PASSWORD_SPRAY_THRESHOLD", 6))
    PASSWORD_SPRAY_WINDOW_MINUTES = int(os.environ.get("PASSWORD_SPRAY_WINDOW_MINUTES", 15))
    PASSWORD_SPRAY_MAX_ATTEMPTS_PER_ACCOUNT = int(
        os.environ.get("PASSWORD_SPRAY_MAX_ATTEMPTS_PER_ACCOUNT", 2)
    )
    PASSWORD_SPRAY_POINTS = int(os.environ.get("PASSWORD_SPRAY_POINTS", 45))


class DevelopmentConfig(Config):
    """Development environment configuration."""
    DEBUG = True
    FLASK_DEBUG = True


class TestingConfig(Config):
    """Testing environment configuration."""
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get("TEST_DATABASE_URL", "sqlite:///:memory:")
    RATELIMIT_ENABLED = False
    WTF_CSRF_ENABLED = False
    AUTH_LOG_ENABLED = False


class ProductionConfig(Config):
    """Production environment configuration."""
    DEBUG = False
    FLASK_DEBUG = False
    SESSION_COOKIE_SECURE = True


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
