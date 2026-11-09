import sqlite3
from pathlib import Path

# Resolve path: AuthShield/database/users.db
DB_DIR = Path(__file__).resolve().parent.parent
DB_PATH = DB_DIR / "users.db"

def init_db(db_path=DB_PATH):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()
    print(f"DB initialised (weak schema) at {db_path}")

if __name__ == "__main__":
    init_db()

