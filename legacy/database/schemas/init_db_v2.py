import sqlite3
from pathlib import Path

# Resolve path: AuthShield/database/users.db
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "users.db"


def init_db(db_path=DB_PATH):
    """Initialise the hardened v2 SQLite users schema with MFA and lockout fields."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        totp_secret TEXT NOT NULL,
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        lockout_until REAL NOT NULL DEFAULT 0
    )
    """)
    conn.commit()
    conn.close()
    print(f"DB initialised (hardened schema) at {db_path}")


if __name__ == "__main__":
    init_db()

