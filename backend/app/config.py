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
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "False").lower() == "true"
    PERMANENT_SESSION_LIFETIME = int(os.environ.get("SESSION_LIFETIME_SECONDS", 3600))

    # CSRF protection
    WTF_CSRF_ENABLED = os.environ.get("WTF_CSRF_ENABLED", "False").lower() == "true"
    WTF_CSRF_TIME_LIMIT = None


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
