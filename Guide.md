# P11 — Authentication & Password Security

### Step-by-step project guide (WSL/Ubuntu · Python + Flask + SQLite)

> **Scope reminder (important):** Every attack in this project (John, Hashcat, Hydra) is run **only** against your own local Flask app, on your own machine, inside your own WSL instance. Never point these tools at a system you don't own or don't have written permission to test. That's not just an ethics footnote — it's literally what your threat model section in the report should state.

---

## 0. What you're building

A single Flask + SQLite login app that you deliberately build **weak first**, break it, then **harden it**, and break it again (and fail) to prove the defenses work.

| Milestone (from [Topic.md](Topic.md))             | What it maps to below |
| ------------------------------------------------- | --------------------- |
| 1. Crack weak hashes & brute-force the login      | Phase 1 + Phase 2     |
| 2. Add salted slow hashing, lockout, MFA          | Phase 3               |
| 3. Re-run and tabulate crack-time vs. work factor | Phase 4               |

| Rubric criterion ([Evalution_metric.pdf](Evalution_metric.pdf)) | Where it's produced      |
| --------------------------------------------------------------- | ------------------------ |
| Problem definition & threat model (2)                           | Phase 5, Step 21         |
| Methodology & lab setup (3)                                     | Phase 0, Phase 5         |
| Attack implementation & results (3)                             | Phase 2, Phase 4         |
| Defense / mitigation & evaluation (3)                           | Phase 3, Phase 4         |
| Analysis & discussion (2) *(incl. limits, false positives, risk)* | Phase 5 + Phase 6 (viva) |
| Report quality & reproducibility (2)                            | Phase 5                  |
| Live demo & viva (15, individual)                               | Phase 6                  |

---

## Phase 0 — Environment setup

### Step 1: Confirm WSL Ubuntu is ready

> 🎯 **What this step does:** Checks that you have Ubuntu running inside Windows using WSL 2.
> 💡 **Why we do it:** The security tools we need (like John the Ripper, Hashcat, and fail2ban) are made for Linux and do not work well directly on Windows.
> 🌟 **Why it matters:** You get a fast, safe Linux environment to run security tools without needing a second computer or a slow virtual machine.

In PowerShell (Windows side), check your distro:

```powershell
wsl -l -v
```

You want an **Ubuntu** entry on **version 2**. If you don't have one: `wsl --install -d Ubuntu`.

---

### Step 2: Enable systemd (needed later for fail2ban)

> 🎯 **What this step does:** Turns on `systemd` inside WSL and restarts it.
> 💡 **Why we do it:** `systemd` manages background services in Linux. Our defensive shield tool (`fail2ban`) needs it to run continuously in the background.
> 🌟 **Why it matters:** Without this, `fail2ban` cannot run in the background to detect attacks and block attackers automatically.

Inside Ubuntu (WSL):

```bash
sudo nano /etc/wsl.conf
```

Add:

```ini
[boot]
systemd=true
```

Save, then from PowerShell:

```powershell
wsl --shutdown
```

Reopen Ubuntu. Verify:

```bash
ps --no-headers -o comm 1   # should print "systemd"
```

---

### Step 3: Update system & install the security tools

> 🎯 **What this step does:** Installs Python, the attack tools (`john`, `hashcat`, `hydra`), and defense tools (`fail2ban`, `iptables`).
> 💡 **Why we do it:** Sets up everything you need in one go: the target website, the security testing tools, and the firewall/intrusion-prevention tools to defend it.
> 🌟 **Why it matters:** You have all required software ready upfront, preventing "command not found" errors during your project and demo.

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-venv python3-pip sqlite3 \
    john hashcat hydra fail2ban iptables net-tools curl git
```

---

### Step 4: Check the attack tools run

> 🎯 **What this step does:** Runs quick test commands to make sure `john`, `hashcat`, and `hydra` are installed and ready.
> 💡 **Why we do it:** Checks that the tools open properly on your computer before you rely on them.
> 🌟 **Why it matters:** Avoids stressful troubleshooting or surprises right before your lab demo.

```bash
john --list=formats | grep -i md5
hashcat -I          # lists compute devices (GPU or CPU OpenCL)
hydra -h | head -5
```

If `hashcat -I` errors about OpenCL, install `pocl-opencl-icd` or plan to run Hashcat in CPU/benchmark mode — that's enough for this project.

---

### Step 5: Single-purpose project folders + virtual environment

> 🎯 **What this step does:** Creates clean single-purpose folders and an isolated Python workspace (`.venv`) with Flask, bcrypt, Argon2, and TOTP MFA libraries.
> 💡 **Why we do it:** Keeping every directory limited to one role (code vs. databases vs. hash dumps vs. cracked outputs vs. audit logs) prevents mixed-type clutter and keeps scripts reproducible from the project root.
> 🌟 **Why it matters:** Anyone can clone your repository, run `pip install -r requirements.txt`, and reproduce every test cleanly.

```bash
mkdir -p ~/p11-auth-project/{app,database/{schemas,seeds,backups},hashes,logs,results,scripts,Terminal_crack_result,wordlists}
cd ~/p11-auth-project
python3 -m venv .venv
source .venv/bin/activate
pip install flask bcrypt argon2-cffi pyotp "qrcode[pil]"
pip freeze > requirements.txt
```

Directory layout:

- `app/` — Flask web applications (`app_v1_weak.py`, `app_v2_hardened.py`)
- `database/` — Active SQLite DB (`users.db`), `schemas/`, `seeds/`, `backups/`
- `scripts/` — CLI utilities (`dump_hashes.py`, `benchmark_hashing.py`)
- `hashes/` — Extracted hash dumps (inputs for offline cracking)
- `results/` — Machine-readable tool outputs (`cracked_*.txt`, `benchmark_hashing.txt`)
- `Terminal_crack_result/` — Annotated terminal audit logs and evidence tables
- `logs/` — Runtime and Fail2Ban logs (`auth.log`)
- `wordlists/` — Dictionary files (`rockyou.txt`)

---

### Step 6: Get a wordlist

> 🎯 **What this step does:** Downloads `rockyou.txt`, a famous list of real leaked passwords.
> 💡 **Why we do it:** Attackers rarely guess random characters — they start with real passwords people actually reuse.
> 🌟 **Why it matters:** Lets you test realistic password attacks and proves why weak, common passwords get broken fast.

Standard Ubuntu doesn't ship `rockyou.txt` (that's a Kali default). Save it directly as `rockyou.txt` (this release file is already uncompressed plain text):

```bash
cd ~/p11-auth-project/wordlists
curl -L -o rockyou.txt \
  https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
# If that mirror is unavailable, pull from SecLists (Passwords/Leaked-Databases/rockyou.txt.tar.gz)
# and extract it so wordlists/rockyou.txt exists as a plain text file.
```

A 1,000–5,000 line subset works fine too if the full ~14.3M-line file is slow on your CPU — note that choice in your report's methodology section.

---

### Step 7: Find your WSL interface IP (you'll need this later)

> 🎯 **What this step does:** Finds your WSL Linux IP address (e.g. `172.x.x.x`).
> 💡 **Why we do it:** If you attack `127.0.0.1` (localhost), firewalls usually ignore loopback traffic. Attacking your WSL `eth0` IP mimics a real external client connecting over a network interface.
> 🌟 **Why it matters:** Lets `fail2ban` see incoming network traffic and ban the attacker's IP with `iptables`.

```bash
ip addr show eth0 | grep "inet "
```

Note this IP (e.g. `172.x.x.x`), and **never commit your private machine IP into public report logs** — replace it with `<TARGET_IP>` when archiving logs. **Use this `eth0` IP, not `127.0.0.1`,** when Hydra targets the app later.

---

## Phase 1 — Build the intentionally weak app (pre-Milestone 1)

### Step 8: Database schema (weak version)

> 🎯 **What this step does:** Creates a simple `users` table with only `username` and `password_hash`.
> 💡 **Why we do it:** This represents a poorly designed legacy website: no per-user salt, no failed-attempt counter, no lockout timestamp, and no MFA secret.
> 🌟 **Why it matters:** Gives you a weak "Before" baseline so you can demonstrate why insecure storage and unlimited login attempts fail.

`database/schemas/init_db_v1.py`:

```python
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "users.db"

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
```

---

### Step 9: The vulnerable Flask app

> 🎯 **What this step does:** Builds a minimal Flask website that hashes passwords with unsalted MD5 and allows unlimited login guesses.
> 💡 **Why we do it:** MD5 is extremely fast and unsalted (trivial to crack offline), and the login form has zero rate limiting, lockout, or MFA.
> 🌟 **Why it matters:** Gives you an intentionally vulnerable target to measure both offline cracking (John/Hashcat) and online brute-forcing (Hydra).

`app/app_v1_weak.py`:

```python
from flask import Flask, request, render_template_string, redirect
import sqlite3, hashlib
from pathlib import Path

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent.parent
DB = str(BASE_DIR / "database" / "users.db")

LOGIN_FORM = """
<h2>Login</h2>
<form method="post">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <button type="submit">Login</button>
</form>
"""
REGISTER_FORM = """
<h2>Register</h2>
<form method="post">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <button type="submit">Register</button>
</form>
"""

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/")
def index():
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        # INTENTIONALLY WEAK — unsalted MD5. This is the vulnerability for Milestone 1.
        pw_hash = hashlib.md5(password.encode()).hexdigest()
        conn = get_db()
        try:
            conn.execute("INSERT INTO users (username, password_hash) VALUES (?,?)",
                         (username, pw_hash))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username already taken", 400
        finally:
            conn.close()
        return redirect("/login")
    return render_template_string(REGISTER_FORM)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        pw_hash = hashlib.md5(password.encode()).hexdigest()
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()
        if user and user["password_hash"] == pw_hash:
            return "Login successful! Welcome " + username
        # Return HTTP 200 (not 401) so Hydra's http-post-form inspects the HTML body
        # for "incorrect" instead of aborting with an HTTP Basic Auth 401 error.
        return "incorrect username or password", 200
    return render_template_string(LOGIN_FORM)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
```

> **Why HTTP `200` on failed form login instead of `401`?** Hydra's `http-post-form` module treats HTTP `401 Unauthorized` as HTTP Basic/Digest authentication (`use module "http-get" instead`) and aborts. Real web login forms typically re-render the form page with HTTP `200` and an error message, which allows `F=incorrect` to match cleanly.

---

### Step 10: Seed victim accounts with weak dictionary passwords

> 🎯 **What this step does:** Inserts seeded dummy users (`alice`, `bob`, etc.) with common passwords from `rockyou.txt`, then saves a database backup.
> 💡 **Why we do it:** Gives your offline crackers and Hydra predictable, known test accounts to verify every attack cleanly.
> 🌟 **Why it matters:** Preserves a clean snapshot of the Phase 1 weak database in `database/backups/` before you upgrade the schema in Phase 3.

`database/seeds/seed_users.py`:

```python
import sqlite3, hashlib
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "users.db"

def seed(db_path=DB_PATH):
    users = [
        ("alice", "password123"),
        ("bob", "letmein"),
        ("carol", "dragon123"),
        ("dave", "qwerty1"),
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
```

Run from the project root (`~/p11-auth-project`):

```bash
cd ~/p11-auth-project
python3 database/schemas/init_db_v1.py
python3 database/seeds/seed_users.py
cp database/users.db database/backups/users_phase1_weak.db.bak
python3 app/app_v1_weak.py
```

Confirm it loads at `http://<your-eth0-ip>:5000/login`.

---

## Phase 2 — Attack the weak app (Milestone 1)

### Step 11: Export the hashes for offline cracking

> 🎯 **What this step does:** Dumps usernames and password hashes from `database/users.db` into `hashes/md5_hashes.txt`.
> 💡 **Why we do it:** Simulates a database leak/SQLi breach where an attacker obtains the hash file and attacks it offline without touching the login page.
> 🌟 **Why it matters:** Proves that rate limits and firewalls cannot protect stolen hashes — only strong salted slow hashing can.

`scripts/dump_hashes.py`:

```python
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "database" / "users.db"
OUTPUT_PATH = BASE_DIR / "hashes" / "md5_hashes.txt"

def dump_hashes(output_path=OUTPUT_PATH):
    if not DB_PATH.exists():
        raise FileNotFoundError(f"Database not found at {DB_PATH}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    rows = conn.execute("SELECT username, password_hash FROM users").fetchall()
    conn.close()

    with open(output_path, "w") as f:
        for username, h in rows:
            f.write(f"{username}:{h}\n")
    print(f"Wrote {output_path}")

if __name__ == "__main__":
    dump_hashes()
```

Run from the project root:

```bash
cd ~/p11-auth-project
python3 scripts/dump_hashes.py
```

---

### Step 12: Crack with John the Ripper

> 🎯 **What this step does:** Uses John the Ripper to crack `hashes/md5_hashes.txt` with `wordlists/rockyou.txt`.
> 💡 **Why we do it:** Measures CPU dictionary cracking speed against unsalted MD5.
> 🌟 **Why it matters:** Gives you baseline CPU timing and cracked plaintext evidence for `results/cracked_john.txt` and `Terminal_crack_result/john_the_ripper.txt`.

```bash
cd ~/p11-auth-project
john --format=Raw-MD5 --wordlist=wordlists/rockyou.txt hashes/md5_hashes.txt
john --show --format=Raw-MD5 hashes/md5_hashes.txt > results/cracked_john.txt
```

Record the wall-clock time (`time john ...`) and guesses/sec reported by John.

---

### Step 13: Crack the same hashes with Hashcat (for GPU/speed comparison)

> 🎯 **What this step does:** Strips usernames into `hashes/md5_only.txt` and cracks the raw MD5 digests with Hashcat.
> 💡 **Why we do it:** Hashcat exposes exact `H/s` throughput on your GPU/CPU, showing why fast hashes collapse at millions/billions of guesses per second.
> 🌟 **Why it matters:** Establishes your `-m 0` baseline speed to contrast against `-m 3200` (bcrypt) in Phase 4.

```bash
cd ~/p11-auth-project
cut -d: -f2 hashes/md5_hashes.txt > hashes/md5_only.txt
time hashcat -m 0 -a 0 -o results/cracked_hashcat.txt hashes/md5_only.txt wordlists/rockyou.txt
cat results/cracked_hashcat.txt
```

Note the exact `Speed` (`H/s`) reported by Hashcat and save the terminal output in `Terminal_crack_result/hashcat.txt`.

---

### Step 14: Brute-force the live login with Hydra

> 🎯 **What this step does:** Runs Hydra against the live `/login` form on `app/app_v1_weak.py`.
> 💡 **Why we do it:** Demonstrates an online dictionary brute-force attack when there is no rate limit, lockout, IP ban, or MFA.
> 🌟 **Why it matters:** Provides "Before" online brute-force proof to compare against Phase 4's blocked Hydra run.

With `app/app_v1_weak.py` running on `0.0.0.0:5000`, run from a separate WSL terminal:

```bash
cd ~/p11-auth-project
hydra -l alice -P wordlists/rockyou.txt <your-eth0-ip> -s 5000 \
  http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"
```

- `-l alice` — single known username (or `-L userlist.txt` for multiple accounts)
- `F=incorrect` — string matching failed login responses (`HTTP 200` body from `app_v1_weak.py`)

Save the recovered credential in `results/cracked_hydra_weak.txt` and the anonymized log (with `<TARGET_IP>` replacing your WSL IP) in `Terminal_crack_result/hydra_weak.txt`.

> **Checkpoint — Milestone 1 done:** You have offline cracked hashes (`John` + `Hashcat`) and a successful online brute-force (`Hydra`) against the weak app.

---

## Phase 3 — Add the defenses (Milestone 2)

### Step 15: New schema with lockout + MFA fields

> 🎯 **What this step does:** Creates a hardened `users` table with per-user salted bcrypt hashes, `totp_secret`, `failed_attempts`, and `lockout_until`.
> 💡 **Why we do it:** Persists failed-login tracking and MFA state per account so the app enforces lockouts across both password and MFA steps.
> 🌟 **Why it matters:** Provides the storage foundation for salted slow hashing, account lockout, and 2FA.

`database/schemas/init_db_v2.py`:

```python
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "users.db"

def init_db(db_path=DB_PATH):
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
```

Verify you backed up the Phase 1 database to `database/backups/users_phase1_weak.db.bak`, then reset and create the v2 schema:

```bash
cd ~/p11-auth-project
rm -f database/users.db
python3 database/schemas/init_db_v2.py
```

---

### Step 16: Hardened app — bcrypt + lockout + TOTP + protected dashboard

> 🎯 **What this step does:** Builds `app/app_v2_hardened.py` with four coordinated defenses:
>
> 1. **Salted slow hashing (`bcrypt`, configurable rounds):** Adds a unique 128-bit random salt per user and tunable cost (`BCRYPT_ROUNDS`, default `12`, configurable via environment variable for Phase 4 tests).
> 2. **Account lockout across BOTH `/login` and `/verify-mfa`:** Tracks `failed_attempts` and locks the account for 15 minutes after 5 failed password **or** 5 failed TOTP attempts.
> 3. **Two-Factor Authentication (TOTP MFA) + session routes:** Enrolls each user with a QR code (`pyotp`) and gates `/dashboard` behind both password and TOTP verification.
> 4. **Safe Fail2Ban logging:** Sanitizes logged usernames before writing `logs/auth.log` (prevents log/regex injection) and creates `logs/auth.log` at startup so `fail2ban` always starts cleanly.
>
> 💡 **Why we do it:** Fixes the MFA brute-force hole, path fragility, HTTP `401` Hydra mismatch, and log-creation trap present in naive examples.
> 🌟 **Why it matters:** Stops offline cracking, online guessing, and credential-stuffing attacks while keeping legitimate authentication intact.

`app/app_v2_hardened.py`:

```python
from flask import Flask, request, render_template_string, redirect, session
from pathlib import Path
import os, re, sqlite3, time, bcrypt, pyotp, qrcode, io, base64

app = Flask(__name__)
app.secret_key = os.environ.get("AUTHSHIELD_SECRET_KEY", "dev-secret-change-me")

BASE_DIR = Path(__file__).resolve().parent.parent
DB = str(BASE_DIR / "database" / "users.db")
AUTH_LOG = BASE_DIR / "logs" / "auth.log"

BCRYPT_ROUNDS = int(os.environ.get("BCRYPT_ROUNDS", "12"))  # vary via env var in Phase 4
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 15 * 60
MIN_PASSWORD_LENGTH = 8

# Ensure logs/auth.log exists before fail2ban starts watching it
AUTH_LOG.parent.mkdir(parents=True, exist_ok=True)
AUTH_LOG.touch(exist_ok=True)

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def log_failed_attempt(username, ip):
    # Sanitize username so spaces/newlines cannot inject fake log lines or break failregex
    safe_user = re.sub(r"[^A-Za-z0-9_.-]", "_", username or "unknown")[:64]
    with open(AUTH_LOG, "a") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} Failed login attempt for user={safe_user} from {ip}\n")

def is_locked(user):
    return bool(user and user["lockout_until"] > time.time())

def record_failure(conn, user, username, ip):
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

REGISTER_FORM = """
<h2>Register</h2>
<form method="post">
  Username: <input name="username"><br>
  Password (min 8 chars): <input name="password" type="password"><br>
  <button type="submit">Register</button>
</form>
"""
LOGIN_FORM = """
<h2>Login</h2>
<form method="post">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <button type="submit">Login</button>
</form>
"""
MFA_FORM = """
<h2>Enter 6-digit code from your authenticator app</h2>
<form method="post">
  Code: <input name="code"><br>
  <button type="submit">Verify</button>
</form>
"""

@app.route("/")
def index():
    if session.get("user"):
        return redirect("/dashboard")
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        if not username or len(password) < MIN_PASSWORD_LENGTH:
            return f"Username required and password must be at least {MIN_PASSWORD_LENGTH} characters", 400

        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode()
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
        <img src="data:image/png;base64,{qr_b64}"><br>
        Secret (manual entry): {secret}<br>
        <a href="/login">Go to login</a>
        """
    return render_template_string(REGISTER_FORM)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        ip = request.remote_addr
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

        if is_locked(user):
            conn.close()
            return "account temporarily locked due to too many failed attempts", 403

        if user and bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
            conn.execute("UPDATE users SET failed_attempts=0, lockout_until=0 WHERE username=?", (username,))
            conn.commit()
            conn.close()
            session["pending_mfa_user"] = username
            return redirect("/verify-mfa")

        locked_now = record_failure(conn, user, username, ip)
        conn.close()
        if locked_now:
            return "account temporarily locked due to too many failed attempts", 403
        # Keep status 200 on standard form mismatch so Hydra can attempt multiple guesses
        # until lockout (403) and Fail2Ban IP ban actually trigger.
        return "incorrect username or password", 200
    return render_template_string(LOGIN_FORM)

@app.route("/verify-mfa", methods=["GET", "POST"])
def verify_mfa():
    username = session.get("pending_mfa_user")
    if not username:
        return redirect("/login")
    if request.method == "POST":
        code = request.form["code"].strip()
        ip = request.remote_addr
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

        if is_locked(user):
            conn.close()
            session.pop("pending_mfa_user", None)
            return "account temporarily locked due to too many failed attempts", 403

        if user and pyotp.TOTP(user["totp_secret"]).verify(code, valid_window=1):
            conn.execute("UPDATE users SET failed_attempts=0, lockout_until=0 WHERE username=?", (username,))
            conn.commit()
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
    username = session.get("user")
    if not username:
        return redirect("/login")
    return f"""
    <h2>Welcome {username}</h2>
    <p>Login successful! Welcome {username} (password + MFA verified)</p>
    <a href="/logout">Logout</a>
    """

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
```

Start the hardened app and register **two** accounts before testing attacks (one victim account e.g. `testvictim` for Hydra/lockout testing, and one personal demo account e.g. `legituser` whose QR code you scan into your authenticator app so your demo login isn't blocked by `lockout_until`!):

```bash
cd ~/p11-auth-project
python3 app/app_v2_hardened.py
```

> **Note:** Register at least one test user with a `>= 8` char dictionary password from `rockyou.txt` (such as `password123`) if you want Step 20 to compare real Hashcat/John cracking against `bcrypt` using `rockyou.txt`.

---

### Step 17: fail2ban — network-layer lockout on top of app-level lockout

> 🎯 **What this step does:** Configures `fail2ban` to monitor `logs/auth.log` and dynamically block attacking IPs via `iptables` on port `5000`.
> 💡 **Why we do it:** App-level lockouts protect the user account, but the Python server still processes incoming HTTP traffic unless a firewall drops abusive IPs at the network layer.
> 🌟 **Why it matters:** Creates defense-in-depth: application lockout protects accounts across distributed IPs, while Fail2Ban protects server resources from single-source floods.

Ensure `logs/auth.log` exists (already touched by `app_v2_hardened.py`, or run `touch ~/p11-auth-project/logs/auth.log`):

Create `/etc/fail2ban/filter.d/flaskapp.conf`:

```ini
[Definition]
failregex = Failed login attempt for user=\S+ from <HOST>
ignoreregex =
```

Create `/etc/fail2ban/jail.d/flaskapp.local` (replace `<you>` with your WSL Linux username):

```ini
[flaskapp]
enabled  = true
port     = 5000
filter   = flaskapp
logpath  = /home/<you>/p11-auth-project/logs/auth.log
maxretry = 5
findtime = 600
bantime  = 900
action   = iptables-multiport[name=flaskapp, port="5000", protocol=tcp]
```

Start Fail2Ban and verify both the jail and `iptables` backend:

```bash
sudo systemctl restart fail2ban
sudo fail2ban-client status flaskapp
sudo iptables -L f2b-flaskapp -n
```

> **WSL2 `iptables` tip:** If `iptables` rules fail or don't drop traffic in WSL2, switch from `nft` to legacy mode (`sudo update-alternatives --set iptables /usr/sbin/iptables-legacy` and restart `fail2ban`).

**Report insight:** Fail2Ban bans by source IP and only applies to online network attacks (Hydra); it provides zero defense if an attacker steals `database/users.db` directly for offline cracking (John/Hashcat).

---

## Phase 4 — Re-attack the hardened app & tabulate work factors (Milestone 3)

### Step 18: Re-run Hydra against the hardened login

> 🎯 **What this step does:** Targets the hardened app with Hydra to verify account lockout, MFA protection, and Fail2Ban firewall banning.
> 💡 **Why we do it:** Proves experimentally that the exact same attack path from Phase 2 is stopped.
> 🌟 **Why it matters:** Produces the "After" captures required for the *Defense / mitigation & evaluation* rubric section.

Use `S=/verify-mfa` (matching Flask's redirect to `/verify-mfa` on a valid password instead of `F=incorrect`) so Hydra will **never** misinterpret `"account temporarily locked"` (`403`) as a cracked password:

```bash
cd ~/p11-auth-project
hydra -l testvictim -P wordlists/rockyou.txt <your-eth0-ip> -s 5000 \
  http-post-form "/login:username=^USER^&password=^PASS^:S=/verify-mfa"
```

What to expect and capture:
1. After `5` wrong attempts (`MAX_ATTEMPTS = 5`), `app_v2_hardened.py` locks `testvictim` (`403 account temporarily locked...`).
2. After `maxretry = 5` log entries in `logs/auth.log`, `fail2ban` bans `<your-eth0-ip>` on port `5000`, blocking subsequent connections.
3. Also verify directly with `curl -i -X POST -d "username=testvictim&password=wrong" http://<your-eth0-ip>:5000/login` (after unbanning IP) to show the `HTTP/1.1 403 FORBIDDEN` lockout body, and save evidence:

```bash
sudo fail2ban-client status flaskapp
tail -20 logs/auth.log
```

Save the anonymized terminal output in `Terminal_crack_result/hydra_hardened.txt` (remember to replace your private IP with `<TARGET_IP>`).

---

### Step 19: Benchmark hashing speed & crack time vs. work factor

> 🎯 **What this step does:** Runs `scripts/benchmark_hashing.py` to measure per-hash cost and projected `rockyou.txt` crack times across MD5, multiple bcrypt rounds (`10`, `12`, `14`), and Argon2id profiles.
> 💡 **Why we do it:** Quantifies the asymmetric defense of key-stretching work factors in real CPU milliseconds vs. billions of attempts.
> 🌟 **Why it matters:** Fulfills Milestone 3's crack-time vs. work-factor table and proves why Argon2id / high-round bcrypt resist offline cracking.

`scripts/benchmark_hashing.py`:

```python
import hashlib, time
from pathlib import Path
import bcrypt
from argon2 import PasswordHasher

BASE_DIR = Path(__file__).resolve().parent.parent
OUT_FILE = BASE_DIR / "results" / "benchmark_hashing.txt"
WORDLIST_SIZE = 14_344_391  # full rockyou.txt line count

def format_duration(seconds):
    if seconds < 60:
        return f"{seconds:.2f} sec"
    if seconds < 3600:
        return f"{seconds / 60:.2f} min"
    if seconds < 86400:
        return f"{seconds / 3600:.2f} hours"
    if seconds < 31_536_000:
        return f"{seconds / 86400:.2f} days"
    return f"{seconds / 31_536_000:.2f} years"

def time_fn(fn, n=20):
    start = time.perf_counter()
    for _ in range(n):
        fn()
    return (time.perf_counter() - start) / n

lines = []
header = f"{'Algorithm':<18}{'Work Factor':<22}{'Time/Hash (ms)':<18}{'Hashes/sec':<14}{'Est. Full rockyou.txt'}"
lines.append(header)
lines.append("-" * len(header))

def record(name, params, sec_per_hash):
    rate = 1.0 / sec_per_hash
    est = format_duration(sec_per_hash * WORDLIST_SIZE)
    lines.append(f"{name:<18}{params:<22}{sec_per_hash * 1000:<18.4f}{rate:<14.1f}{est}")

md5_t = time_fn(lambda: hashlib.md5(b"testpassword123").hexdigest(), n=2000)
record("MD5 (unsalted)", "-", md5_t)

for rounds in [10, 12, 14]:
    t = time_fn(lambda r=rounds: bcrypt.hashpw(b"testpassword123", bcrypt.gensalt(rounds=r)), n=5)
    record("bcrypt", f"rounds={rounds}", t)

for label, t_cost, m_cost, p_cost in [
    ("t=2, m=19MB, p=1", 2, 19456, 1),
    ("t=3, m=64MB, p=1", 3, 65536, 1),
]:
    ph = PasswordHasher(time_cost=t_cost, memory_cost=m_cost, parallelism=p_cost)
    t = time_fn(lambda p=ph: p.hash("testpassword123"), n=5)
    record("Argon2id", label, t)

OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
report = "\n".join(lines)
print(report)
OUT_FILE.write_text(report + "\n")
print(f"\nSaved to {OUT_FILE}")
```

Run it from project root:

```bash
cd ~/p11-auth-project
python3 scripts/benchmark_hashing.py
```

> **Important methodological note for your report & viva:** Python's single-threaded `hashlib.md5()` loop measures **Python interpreter overhead**, so it reports far fewer MD5 hashes/sec than real C/CUDA cracking tools. Combine this table with your **actual Step 13 Hashcat MD5 throughput** (tens of millions of hashes/sec on GPU) and **Step 20 Hashcat bcrypt throughput**!

---

### Step 20: Re-run John / Hashcat across actual bcrypt work factors (required for Milestone 3)

> 🎯 **What this step does:** Dumps real bcrypt hashes at multiple work factors (e.g., `rounds=10` and `rounds=12`) from your database and tests Hashcat (`-m 3200`) / John (`--format=bcrypt`) against them.
> 💡 **Why we do it:** Proves *with the actual cracking tools* (not only a Python loop) how doubling the cost factor slashes `H/s` and defeats GPU cracking, directly satisfying Milestone 3 (*"Re-run and tabulate crack-time vs. work factor"*).
> 🌟 **Why it matters:** Gives you side-by-side empirical Hashcat `H/s` numbers comparing MD5 (`-m 0`), `bcrypt rounds=10`, and `bcrypt rounds=12` (and optionally Argon2id `-m 34000` if supported by your Hashcat version).

Register two test users (e.g., one while running `BCRYPT_ROUNDS=10 python3 app/app_v2_hardened.py` and one while running `BCRYPT_ROUNDS=12 python3 app/app_v2_hardened.py`), then export each work factor separately so Hashcat measures them cleanly without overwriting `hashes/md5_hashes.txt`:

```bash
cd ~/p11-auth-project
sqlite3 database/users.db "SELECT username || ':' || password_hash FROM users;" > hashes/bcrypt_hashes.txt
grep '$2b$10$' hashes/bcrypt_hashes.txt | cut -d: -f2 > hashes/bcrypt_r10_only.txt
grep '$2b$12$' hashes/bcrypt_hashes.txt | cut -d: -f2 > hashes/bcrypt_r12_only.txt

# Run briefly (a minute or two) and press 's' for status / 'q' to quit, recording H/s speed:
hashcat -m 3200 -a 0 hashes/bcrypt_r10_only.txt wordlists/rockyou.txt
hashcat -m 3200 -a 0 hashes/bcrypt_r12_only.txt wordlists/rockyou.txt
john --format=bcrypt --wordlist=wordlists/rockyou.txt hashes/bcrypt_hashes.txt
```

Tabulate the real Hashcat / John measurements alongside Step 13 (`MD5 -m 0`) and Step 19:

| Algorithm & Work Factor | Hashcat Mode | Measured Speed (`H/s`) | Per-Hash Cost (Step 19) | Projected Full `rockyou.txt` Time |
| ----------------------- | ------------ | ---------------------- | ----------------------- | --------------------------------- |
| MD5 (unsalted)          | `-m 0`       | *(from Step 13)*       | *(from Step 19)*        | Seconds                           |
| bcrypt (`rounds=10`)    | `-m 3200`    | *(from Step 20)*       | *(from Step 19)*        | Hours / Days                      |
| bcrypt (`rounds=12`)    | `-m 3200`    | *(from Step 20)*       | *(from Step 19)*        | Days / Months                     |
| bcrypt (`rounds=14`)    | `-m 3200`    | *(est. `1/4` of r=12)* | *(from Step 19)*        | Years                             |
| Argon2id (`t=2,m=19MB`) | `-m 34000`   | *(CPU/GPU bound)*      | *(from Step 19)*        | Memory-hard resistance            |

> **Checkpoint — Milestone 3 done:** You have real tool crack-rate comparisons across algorithms and work factors, plus an end-to-end "attack now blocked" demonstration.

---

## Phase 5 — Writing the report (15 marks)

### Step 21: Suggested structure (mapped directly to [Evalution_metric.pdf](Evalution_metric.pdf))

> 🎯 **What this step does:** Maps your 6–10 page team report directly to the 6 criteria in the rubric.
> 💡 **Why we do it:** Matching the examiner's exact rubric keywords ensures every graded element (`false positives`, `reproducibility`, `threat model`, `before/after comparison`) is explicitly answered.
> 🌟 **Why it matters:** Maximizes report marks without missing easy points.

Target length: **6–10 pages** (recommended by [Evalution_metric.pdf](Evalution_metric.pdf)):

1. **Problem definition & threat model (2 marks)** — Assets protected (`database/users.db` credentials and user sessions), attacker capabilities (online network brute-force vs. offline attacker holding stolen hash dumps), scope/ethics boundary (local WSL lab only), and impact of weak unsalted MD5 + missing lockout/MFA.
2. **Methodology & lab setup (3 marks)** — WSL2 Ubuntu version, exact tool versions (`john`, `hashcat`, `hydra`, `fail2ban-client --version`, Python/Flask packages), network setup (`eth0` IP `<TARGET_IP>:5000`), directory layout, and reproducible setup commands.
3. **Attack implementation & results (3 marks)** — Phase 2 evidence from `results/` and `Terminal_crack_result/`: John & Hashcat MD5 crack rates, Hydra online credential recovery (`alice`), and annotated terminal logs/screenshots.
4. **Defense / mitigation & evaluation (3 marks)** — Phase 3 design (`bcrypt` work factors, dual `/login` + `/verify-mfa` lockout, TOTP MFA, Fail2Ban + `iptables`) and Phase 4 re-runs proving Hydra stops and bcrypt slows cracking by orders of magnitude, with side-by-side before/after tables.
5. **Analysis & discussion (2 marks)** —
   - *Why the defenses work:* random salts prevent rainbow tables; key-stretching (`2^rounds` in bcrypt, memory-hardness in Argon2id) shifts offline attacks from seconds to months/years; lockout + Fail2Ban stop online guessing; TOTP stops credential-only theft.
   - *Limits & false positives (explicitly graded!):* **Account-lockout DoS** (attacker intentionally locking out a known user), **Fail2Ban false positives** (banning a shared NAT/university Wi-Fi IP blocks *all* legitimate users behind that router; rapid typos by a real user lock them out), **TOTP false positives** (device clock skew rejecting valid codes without `valid_window=1`).
   - *Residual risks:* no TLS (`HTTP` plaintext credentials on the wire), `AUTHSHIELD_SECRET_KEY` env fallback, username enumeration via `403` lockout status difference.
6. **Report quality & reproducibility (2 marks)** — Clean `README.md`, `requirements.txt`, `scripts/`, `database/`, `hashes/`, `results/`, `Terminal_crack_result/`, and citations for wordlists/tools/libraries.

---

### Step 22: Evidence checklist to actually include

- [ ] Annotated log / screenshot: `john --show` cracked MD5 output ([john_the_ripper.txt](Terminal_crack_result/john_the_ripper.txt) & [cracked_john.txt](results/cracked_john.txt))
- [ ] Annotated log / screenshot: Hashcat `-m 0` cracked output + `H/s` speed ([hashcat.txt](Terminal_crack_result/hashcat.txt) & [cracked_hashcat.txt](results/cracked_hashcat.txt))
- [ ] Annotated log / screenshot: Hydra run breaking `app_v1_weak.py` ([hydra_weak.txt](Terminal_crack_result/hydra_weak.txt) & [cracked_hydra_weak.txt](results/cracked_hydra_weak.txt), private IP sanitized)
- [ ] Screenshot: TOTP QR code enrollment + successful login reaching `/dashboard`
- [ ] Annotated log / screenshot: Hydra stopped against `app_v2_hardened.py` + `403` lockout output
- [ ] Screenshot: `sudo fail2ban-client status flaskapp`, `sudo iptables -L f2b-flaskapp -n`, and `tail -20 logs/auth.log` showing banned IP
- [ ] Filled crack-time vs. work-factor comparison table (`Step 19` + `Step 20` real Hashcat `-m 0` vs. `-m 3200`)
- [ ] Reproducible repo files (`requirements.txt`, `README.md`, `scripts/`, `database/`, `app/`)

---

## Phase 6 — Demo & viva prep (15 marks, individual)

### Step 23: Live demo order (avoiding the self-lockout trap)

> 🎯 **What this step does:** Gives a clean 7-step demo sequence where Step 5's lockout/IP ban does **not** break Step 6's legitimate login demo.
> 💡 **Why we do it:** Locking a user lasts 15 minutes in SQLite and banning your IP blocks port `5000` in `iptables` — testing on a separate victim account and unbanning between steps keeps the demo smooth.
> 🌟 **Why it matters:** Keeps you calm and prevents live hiccups (worth 10 individual demo marks).

1. Start `app/app_v1_weak.py`; show `/login` and seeded weak accounts in `database/users.db`.
2. Run Hydra live against `alice` on the weak app and show instant password recovery.
3. Show John / Hashcat cracking `hashes/md5_hashes.txt` / `hashes/md5_only.txt` (use a small subset or show full-run evidence from `Terminal_crack_result/` if short on time).
4. Stop `v1`, start `app/app_v2_hardened.py`, inspect bcrypt hashes in SQLite (`sqlite3 database/users.db "SELECT username, password_hash FROM users;"`), and enroll **`legituser`** with your authenticator app. Also ensure a separate **`testvictim`** account exists for step 5.
5. Run Hydra against **`testvictim`** -> show 5 failed logins in `logs/auth.log`, account lock (`403`), and `sudo fail2ban-client status flaskapp` showing your IP banned.
6. **Before logging in as `legituser`, unban your IP** (`sudo fail2ban-client set flaskapp unbanip <your-eth0-ip>`). Because Hydra attacked `testvictim` (not `legituser`), `legituser` is **not** locked out in SQLite — log in end-to-end with password -> TOTP 6-digit code -> `/dashboard`.
7. Walk through your work-factor comparison table (`results/benchmark_hashing.txt` + Step 20 Hashcat rates).

---

### Step 24: Likely viva questions — explain the *why*, not just commands

- **Why does salting defeat rainbow-table attacks even if the attacker has `rockyou.txt`?**
  - A unique random salt per user turns `"password123"` into completely different hashes for `alice` and `bob`. Precomputed lookup tables become useless; attackers must test guesses individually per user hash.
- **Why is bcrypt/Argon2 being "slow" a security feature, and what does the cost parameter control?**
  - A ~100–250 ms hash is imperceptible for one legitimate login, but multiplies attacker time across millions of dictionary guesses. In bcrypt, `rounds` executes $2^{\text{rounds}}$ key-setup iterations; Argon2id additionally adds configurable RAM (`memory_cost`) to thwart parallel GPU/ASIC speedups.
- **What is the difference between app-level lockout and Fail2Ban — why use both?**
  - App lockout protects a *specific account* even across distributed attacker IPs, while Fail2Ban drops abusive traffic at the firewall (`iptables`) so floods don't exhaust Python/CPU resources.
- **How does TOTP work mechanically, and why is `/verify-mfa` also locked after 5 tries?**
  - Server and authenticator share a Base32 secret (`pyotp.random_base32()`), combine it with the current 30-second Unix time step via HMAC-SHA1, and extract a 6-digit code. Locking `/verify-mfa` after 5 wrong guesses ensures an attacker with the password still only gets 5 guesses per 15 minutes out of $1{,}000{,}000$ possible codes.
- **Offline stolen DB vs. online web attack — which defense stops which?**
  - Offline: lockouts, MFA, and Fail2Ban do nothing; only salted slow hashing (`bcrypt` / `Argon2id`) protects passwords. Online: lockout, Fail2Ban, and TOTP MFA stop brute-forcing.
- **What are false positives and residual risks in this setup?**
  - False positives: Fail2Ban blocking a shared NAT/campus IP affects all users behind it; device clock drift can reject valid TOTP codes (mitigated slightly by `valid_window=1`). Residual risks: account-lockout DoS against known usernames, `HTTP` without TLS locally, and `403` lockout status leaking valid usernames.

---

## Appendix A — Quick command cheat sheet (from `~/p11-auth-project`)

```bash
# Start weak vs. hardened app
python3 app/app_v1_weak.py
python3 app/app_v2_hardened.py
BCRYPT_ROUNDS=10 python3 app/app_v2_hardened.py

# Dump hashes from database/users.db
python3 scripts/dump_hashes.py

# Crack MD5 offline
john --format=Raw-MD5 --wordlist=wordlists/rockyou.txt hashes/md5_hashes.txt
hashcat -m 0 -a 0 -o results/cracked_hashcat.txt hashes/md5_only.txt wordlists/rockyou.txt

# Online brute force (weak vs. hardened success matching)
hydra -l alice -P wordlists/rockyou.txt <eth0-ip> -s 5000 \
  http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"
hydra -l testvictim -P wordlists/rockyou.txt <eth0-ip> -s 5000 \
  http-post-form "/login:username=^USER^&password=^PASS^:S=/verify-mfa"

# fail2ban controls
sudo systemctl restart fail2ban
sudo fail2ban-client status flaskapp
sudo fail2ban-client set flaskapp unbanip <eth0-ip>
sudo iptables -L f2b-flaskapp -n

# Check WSL eth0 IP
ip addr show eth0 | grep "inet "
```

## Appendix B — WSL-specific troubleshooting

- **`iptables: command not found` or permission errors** — ensure `systemd=true` is in `/etc/wsl.conf` (Step 2) and restart WSL completely via `wsl --shutdown` in PowerShell.
- **`iptables` rules don't block traffic** — switch WSL2 to legacy iptables (`sudo update-alternatives --set iptables /usr/sbin/iptables-legacy`) and restart `fail2ban`.
- **`fail2ban` fails to start** — run `sudo fail2ban-client -x start` to inspect errors and ensure `logs/auth.log` exists (`touch ~/p11-auth-project/logs/auth.log`).
- **Hydra hitting `127.0.0.1` isn't banned cleanly** — always use the `eth0` IP from Step 7 rather than loopback.
- **Hashcat reports missing OpenCL/GPU** — CPU OpenCL (`pocl-opencl-icd`) or `-b` benchmark mode is sufficient for producing comparison speeds.

## Appendix C — Ethics & scope (include in your report)

All testing in this project is performed strictly against a locally hosted Flask application on the student's own machine inside an isolated WSL environment for coursework evaluation. No external systems, networks, or third-party accounts are targeted. All tools (`John the Ripper`, `Hashcat`, `Hydra`, `fail2ban`) are standard security auditing and defensive utilities used solely within an authorized self-contained lab.
