import base64
import html
import io
import os
import re
import sqlite3
import time
from pathlib import Path

import bcrypt
import pyotp
import qrcode
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from flask import Flask, redirect, render_template_string, request, session

app = Flask(__name__)
app.secret_key = os.environ.get("AUTHSHIELD_SECRET_KEY", "dev-secret-change-me")

BASE_DIR = Path(__file__).resolve().parent.parent
DB = str(BASE_DIR / "database" / "users.db")
AUTH_LOG = BASE_DIR / "logs" / "auth.log"

HASH_ALGO = os.environ.get("HASH_ALGO", "bcrypt").strip().lower()
BCRYPT_ROUNDS = int(os.environ.get("BCRYPT_ROUNDS", "12"))
ARGON2_HASHER = PasswordHasher(
    time_cost=int(os.environ.get("ARGON2_TIME_COST", "2")),
    memory_cost=int(os.environ.get("ARGON2_MEMORY_COST", "19456")),
    parallelism=int(os.environ.get("ARGON2_PARALLELISM", "1")),
)

MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 15 * 60
MIN_PASSWORD_LENGTH = 8


def ensure_auth_log():
    """Ensure logs/auth.log exists before Fail2Ban starts monitoring it."""
    AUTH_LOG.parent.mkdir(parents=True, exist_ok=True)
    AUTH_LOG.touch(exist_ok=True)


ensure_auth_log()

REGISTER_FORM = """
<h2>Register (Hardened)</h2>
<form method="post">
  Username: <input name="username"><br>
  Password (min 8 chars): <input name="password" type="password"><br>
  Hash Algorithm:
  <select name="algo">
    <option value="bcrypt" {{ 'selected' if default_algo == 'bcrypt' else '' }}>bcrypt (salted)</option>
    <option value="argon2" {{ 'selected' if default_algo == 'argon2' else '' }}>Argon2id (memory-hard + salted)</option>
  </select><br>
  <button type="submit">Register</button>
</form>
<a href="/login">Already registered? Login</a>
"""

LOGIN_FORM = """
<h2>Login (Hardened)</h2>
<form method="post">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <button type="submit">Login</button>
</form>
<a href="/register">Create account</a>
"""

MFA_FORM = """
<h2>Enter 6-digit code from your authenticator app</h2>
<form method="post">
  Code: <input name="code"><br>
  <button type="submit">Verify</button>
</form>
"""


def get_db():
    """Open a SQLite connection configured with row access by column name."""
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password, algo=HASH_ALGO):
    """Hash a password with salted bcrypt or Argon2id."""
    selected = (algo or HASH_ALGO).strip().lower()
    if selected == "argon2":
        return ARGON2_HASHER.hash(password)
    if selected == "bcrypt":
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode()
    raise ValueError(f"Unsupported hash algorithm: {selected}")


def verify_password(password, stored_hash):
    """Verify a password against either an Argon2id or bcrypt hash string."""
    if not stored_hash:
        return False
    if stored_hash.startswith("$argon2"):
        try:
            return ARGON2_HASHER.verify(stored_hash, password)
        except (VerifyMismatchError, InvalidHashError):
            return False
    try:
        return bcrypt.checkpw(password.encode(), stored_hash.encode())
    except ValueError:
        return False


def log_failed_attempt(username, ip):
    """Append a Fail2Ban-compatible failed auth line with sanitized username."""
    ensure_auth_log()
    safe_user = re.sub(r"[^A-Za-z0-9_.-]", "_", username or "unknown")[:64]
    with open(AUTH_LOG, "a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} Failed login attempt for user={safe_user} from {ip}\n")


def is_locked(user):
    """Return True when the user record is currently inside an active lockout window."""
    return bool(user and user["lockout_until"] > time.time())


def record_failure(conn, user, username, ip):
    """Increment failed_attempts, apply account lockout at threshold, and log for Fail2Ban."""
    locked_now = False
    if user:
        attempts = user["failed_attempts"] + 1
        lockout = time.time() + LOCKOUT_SECONDS if attempts >= MAX_ATTEMPTS else 0
        locked_now = lockout > 0
        conn.execute(
            "UPDATE users SET failed_attempts=?, lockout_until=? WHERE username=?",
            (attempts, lockout, username),
        )
        conn.commit()
    log_failed_attempt(username, ip)
    return locked_now


def clear_failures(conn, username):
    """Reset failed attempt counters and lockout timer after successful verification."""
    conn.execute(
        "UPDATE users SET failed_attempts=0, lockout_until=0 WHERE username=?",
        (username,),
    )
    conn.commit()


@app.route("/")
def index():
    """Redirect authenticated users to /dashboard and others to /login."""
    if session.get("user"):
        return redirect("/dashboard")
    return redirect("/login")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register a user with salted bcrypt/Argon2id hash and enroll a TOTP MFA secret."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        algo = request.form.get("algo", HASH_ALGO).strip().lower()
        if not username or len(password) < MIN_PASSWORD_LENGTH:
            return f"Username required and password must be at least {MIN_PASSWORD_LENGTH} characters", 400
        if algo not in {"bcrypt", "argon2"}:
            return "Unsupported hash algorithm", 400

        pw_hash = hash_password(password, algo=algo)
        secret = pyotp.random_base32()
        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, totp_secret) VALUES (?,?,?)",
                (username, pw_hash, secret),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username already taken", 400
        finally:
            conn.close()

        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="P11AuthShield")
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()
        return f"""
        <h2>Scan this with Google Authenticator / Authy / FreeOTP, then log in</h2>
        <p>Algorithm used: <strong>{html.escape(algo)}</strong></p>
        <img src="data:image/png;base64,{qr_b64}"><br>
        Secret (manual entry): <code>{html.escape(secret)}</code><br>
        <a href="/login">Go to login</a>
        """
    return render_template_string(REGISTER_FORM, default_algo=HASH_ALGO)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Authenticate password with lockout tracking before advancing to TOTP MFA."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip = request.remote_addr or "0.0.0.0"

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if is_locked(user):
            conn.close()
            return "account temporarily locked due to too many failed attempts", 403

        if user and verify_password(password, user["password_hash"]):
            clear_failures(conn, username)
            conn.close()
            session["pending_mfa_user"] = username
            return redirect("/verify-mfa")

        locked_now = record_failure(conn, user, username, ip)
        conn.close()
        if locked_now:
            return "account temporarily locked due to too many failed attempts", 403
        # Return HTTP 200 on invalid web-form login so form testers evaluate the body
        # until account lockout (403) and Fail2Ban take effect.
        return "incorrect username or password", 200
    return render_template_string(LOGIN_FORM)


@app.route("/verify-mfa", methods=["GET", "POST"])
def verify_mfa():
    """Verify the 6-digit TOTP code with identical 5-attempt lockout protection."""
    username = session.get("pending_mfa_user")
    if not username:
        return redirect("/login")

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        ip = request.remote_addr or "0.0.0.0"

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if is_locked(user):
            conn.close()
            session.pop("pending_mfa_user", None)
            return "account temporarily locked due to too many failed attempts", 403

        if user and pyotp.TOTP(user["totp_secret"]).verify(code, valid_window=1):
            clear_failures(conn, username)
            conn.close()
            session.pop("pending_mfa_user", None)
            session["user"] = username
            return redirect("/dashboard")

        locked_now = record_failure(conn, user, username, ip)
        conn.close()
        if locked_now:
            session.pop("pending_mfa_user", None)
            return "account temporarily locked due to too many failed attempts", 403
        return "incorrect MFA code", 200
    return render_template_string(MFA_FORM)


@app.route("/dashboard")
def dashboard():
    """Protected route requiring completed password + TOTP MFA authentication."""
    username = session.get("user")
    if not username:
        return redirect("/login")
    safe_user = html.escape(username)
    return f"""
    <h2>Welcome {safe_user}</h2>
    <p>Login successful! Welcome {safe_user} (password + MFA verified)</p>
    <a href="/logout">Logout</a>
    """


@app.route("/logout")
def logout():
    """Clear the authenticated session."""
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

