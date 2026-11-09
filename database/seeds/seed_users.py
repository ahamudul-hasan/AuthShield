import sqlite3, hashlib
from pathlib import Path

# Resolve path: AuthShield/database/users.db
DB_DIR = Path(__file__).resolve().parent.parent
DB_PATH = DB_DIR / "users.db"

def seed(db_path=DB_PATH):
    users = [
        # Original dummy victims from lab guide
        ("alice", "password123"),
        ("bob", "letmein"),
        ("carol", "dragon123"),
        ("dave", "qwerty1"),
        # Additional diverse dictionary victims (all present in rockyou.txt)
        ("eve", "123456"),
        ("frank", "football"),
        ("grace", "monkey"),
        ("heidi", "princess"),
        ("ivan", "shadow"),
        ("judy", "trustno1"),
        ("mallory", "starwars"),
        ("oscar", "superman"),
        ("trent", "iloveyou"),
        ("walter", "admin123"),
    ]

    conn = sqlite3.connect(str(db_path))
    for u, p in users:
        h = hashlib.md5(p.encode()).hexdigest()
        conn.execute("INSERT OR IGNORE INTO users (username, password_hash) VALUES (?,?)", (u, h))
    conn.commit()
    conn.close()
    print(f"Seeded {len(users)} users into {db_path}.")

if __name__ == "__main__":
    seed()
