import os
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
import pyotp

# Add backend directory to sys.path so app modules import cleanly
ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from dotenv import load_dotenv
load_dotenv(BACKEND_DIR / ".env")

from app import create_app
from app.extensions import db
from app.models.user import User
from app.auth.password import hash_password
from app.auth.mfa import encrypt_totp_secret

def seed_neon_database():
    print("================================================================")
    print("           SEEDING NEON CLOUD POSTGRESQL DATABASE                ")
    print("================================================================")
    
    app = create_app("development")
    
    with app.app_context():
        # Display target database
        db_url = app.config.get("SQLALCHEMY_DATABASE_URI", "")
        # Mask credentials for logging
        masked_url = db_url.split("@")[-1] if "@" in db_url else db_url
        print(f"Target Database Host: {masked_url}\n")
        
        # Define seed user specifications
        users_to_seed = [
            # 1. Administrator Account (Argon2id + MFA enabled)
            {
                "username": "admin",
                "email": "admin@authshield.lab",
                "plain_pwd": "AdminShield#Secure2026!",
                "algorithm": "argon2id",
                "role": "admin",
                "mfa_enabled": True,
                "totp_secret": pyotp.random_base32(),
                "failed_attempts": 0,
                "lockout_until": None,
                "is_active": True,
            },
            # 2. Security Analyst Account (Argon2id + MFA enabled)
            {
                "username": "sec_analyst",
                "email": "analyst@authshield.lab",
                "plain_pwd": "Analyst-Monitor-2026-Secure",
                "algorithm": "argon2id",
                "role": "analyst",
                "mfa_enabled": True,
                "totp_secret": pyotp.random_base32(),
                "failed_attempts": 0,
                "lockout_until": None,
                "is_active": True,
            },
            # 3. Standard User - Alice (Argon2id passphrase)
            {
                "username": "alice",
                "email": "alice@authshield.lab",
                "plain_pwd": "guitar-notebook-winter-coffee",
                "algorithm": "argon2id",
                "role": "user",
                "mfa_enabled": False,
                "totp_secret": None,
                "failed_attempts": 0,
                "lockout_until": None,
                "is_active": True,
            },
            # 4. Standard User - Bob (Argon2id + MFA enabled)
            {
                "username": "bob",
                "email": "bob@authshield.lab",
                "plain_pwd": "correct horse battery staple",
                "algorithm": "argon2id",
                "role": "user",
                "mfa_enabled": True,
                "totp_secret": pyotp.random_base32(),
                "failed_attempts": 0,
                "lockout_until": None,
                "is_active": True,
            },
            # 5. Legacy Bcrypt User (Coursework P11 - rounds=12)
            {
                "username": "testvictim",
                "email": "testvictim@coursework.local",
                "plain_pwd": "password123",
                "stored_hash": "$2b$12$SEwxkOJD1Zwe7oJfaWyC2.ygEPT3dQoYdz3dxlIfVvNlIGYqlp1R.",
                "algorithm": "bcrypt",
                "role": "user",
                "mfa_enabled": False,
                "totp_secret": None,
                "failed_attempts": 0,
                "lockout_until": None,
                "is_active": True,
            },
            # 6. Legacy Bcrypt User (Coursework P11 - rounds=10)
            {
                "username": "victim_r10",
                "email": "victim_r10@coursework.local",
                "plain_pwd": "password123",
                "stored_hash": "$2b$10$CE5kWeuN4ulTOPCK4uj64.nNRTcfjJtB5pCRymesKe/NFKuMt/Mmq",
                "algorithm": "bcrypt",
                "role": "user",
                "mfa_enabled": False,
                "totp_secret": None,
                "failed_attempts": 0,
                "lockout_until": None,
                "is_active": True,
            },
            # 7. Locked Account (Simulated brute-force lockout)
            {
                "username": "brute_victim",
                "email": "locked_target@authshield.lab",
                "plain_pwd": "TargetUserSecret#2026!",
                "algorithm": "argon2id",
                "role": "user",
                "mfa_enabled": False,
                "totp_secret": None,
                "failed_attempts": 5,
                "lockout_until": datetime.now(timezone.utc) + timedelta(minutes=15),
                "is_active": True,
            },
            # 8. Deactivated / Suspended Account
            {
                "username": "suspended_user",
                "email": "suspended@authshield.lab",
                "plain_pwd": "SuspendedAccountPwd#2026",
                "algorithm": "argon2id",
                "role": "user",
                "mfa_enabled": False,
                "totp_secret": None,
                "failed_attempts": 0,
                "lockout_until": None,
                "is_active": False,
            },
            # 9. Standard User - Charlie
            {
                "username": "charlie",
                "email": "charlie@authshield.lab",
                "plain_pwd": "sunset-guitar-river-bridge",
                "algorithm": "argon2id",
                "role": "user",
                "mfa_enabled": False,
                "totp_secret": None,
                "failed_attempts": 0,
                "lockout_until": None,
                "is_active": True,
            },
            # 10. Standard User - David
            {
                "username": "david",
                "email": "david@authshield.lab",
                "plain_pwd": "ocean-breeze-camera-coffee",
                "algorithm": "argon2id",
                "role": "user",
                "mfa_enabled": False,
                "totp_secret": None,
                "failed_attempts": 0,
                "lockout_until": None,
                "is_active": True,
            },
        ]
        
        seeded_count = 0
        updated_count = 0
        
        print(f"{'Username':<16} {'Role':<10} {'Algorithm':<10} {'MFA':<6} {'Active':<8} {'Status'}")
        print("-" * 65)
        
        for item in users_to_seed:
            uname = item["username"]
            existing = User.query.filter_by(username=uname).first()
            
            # Compute hash if not pre-set
            if "stored_hash" in item:
                pwd_hash = item["stored_hash"]
            else:
                pwd_hash = hash_password(item["plain_pwd"])
            
            # Encrypt TOTP secret at rest if present
            stored_totp = encrypt_totp_secret(item["totp_secret"]) if item.get("totp_secret") else None

            if existing:
                # Update existing record
                existing.email = item["email"]
                existing.password_hash = pwd_hash
                existing.password_algorithm = item["algorithm"]
                existing.role = item["role"]
                existing.mfa_enabled = item["mfa_enabled"]
                existing.totp_secret = stored_totp
                existing.failed_attempts = item["failed_attempts"]
                existing.lockout_until = item["lockout_until"]
                existing.is_active = item["is_active"]
                existing.updated_at = datetime.now(timezone.utc)
                action = "Updated"
                updated_count += 1
            else:
                # Insert new record
                new_user = User(
                    username=uname,
                    email=item["email"],
                    password_hash=pwd_hash,
                    password_algorithm=item["algorithm"],
                    role=item["role"],
                    mfa_enabled=item["mfa_enabled"],
                    totp_secret=stored_totp,
                    failed_attempts=item["failed_attempts"],
                    lockout_until=item["lockout_until"],
                    is_active=item["is_active"],
                )
                db.session.add(new_user)
                action = "Inserted"
                seeded_count += 1
                
            print(f"{uname:<16} {item['role']:<10} {item['algorithm']:<10} {str(item['mfa_enabled']):<6} {str(item['is_active']):<8} {action}")
        
        db.session.commit()
        
        total_rows = User.query.count()
        print("-" * 65)
        print(f"\n[+] Database operation complete:")
        print(f"    - New rows inserted: {seeded_count}")
        print(f"    - Rows updated:       {updated_count}")
        print(f"    - Total users in Neon: {total_rows}")
        print("\nCredential Reference for Testing:")
        print(f"{'Username':<16} {'Password':<32} {'Role':<10} {'Notes'}")
        print("-" * 75)
        for u in users_to_seed:
            notes = []
            if u["role"] != "user":
                notes.append(u["role"])
            if u["mfa_enabled"]:
                notes.append("MFA Enabled")
            if u["algorithm"] == "bcrypt":
                notes.append("Legacy Bcrypt")
            if u["lockout_until"]:
                notes.append("Temporarily Locked")
            if not u["is_active"]:
                notes.append("Disabled")
            note_str = ", ".join(notes) if notes else "Standard Argon2id"
            print(f"{u['username']:<16} {u['plain_pwd']:<32} {u['role']:<10} {note_str}")

if __name__ == "__main__":
    seed_neon_database()
