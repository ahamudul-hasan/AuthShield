import sqlite3
from pathlib import Path

# Resolve paths relative to project root
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "database" / "users.db"
OUTPUT_PATH = BASE_DIR / "hashes" / "md5_hashes.txt"

def dump_hashes():
    if not DB_PATH.exists():
        raise FileNotFoundError(f"Database not found at {DB_PATH}")

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    rows = conn.execute("SELECT username, password_hash FROM users").fetchall()
    conn.close()

    with open(OUTPUT_PATH, "w") as f:
        for username, h in rows:
            f.write(f"{username}:{h}\n")
    print(f"Wrote {OUTPUT_PATH}")

if __name__ == "__main__":
    dump_hashes()

