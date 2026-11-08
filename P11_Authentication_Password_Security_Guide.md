# P11 — Authentication & Password Security
### Step-by-step project guide (WSL/Ubuntu · Python + Flask + SQLite)

> **Scope reminder (important):** every attack in this project (John, Hashcat, Hydra) is run **only** against your own local Flask app, on your own machine, inside your own WSL instance. Never point these tools at a system you don't own or don't have written permission to test. That's not just an ethics footnote — it's literally what your threat model section in the report should state.

---

## 0. What you're building

A single Flask + SQLite login app that you deliberately build **weak first**, break it, then **harden it**, and break it again (and fail) to prove the defenses work.

| Milestone (from brief) | What it maps to below |
|---|---|
| 1. Crack weak hashes & brute-force the login | Phase 1 + Phase 2 |
| 2. Add salted slow hashing, lockout, MFA | Phase 3 |
| 3. Re-run and tabulate crack-time vs. work factor | Phase 4 |

| Rubric criterion | Where it's produced |
|---|---|
| Problem definition & threat model (2) | Phase 5, Step 23 |
| Methodology & lab setup (3) | Phase 0, Phase 5 |
| Attack implementation & results (3) | Phase 2, Phase 4 |
| Defense / mitigation & evaluation (3) | Phase 3, Phase 4 |
| Analysis & discussion (2) | Phase 5 + Phase 6 (viva) |
| Report quality & reproducibility (2) | Phase 5 |
| Live demo & viva (15, individual) | Phase 6 |

---

## Phase 0 — Environment setup

### Step 1: Confirm WSL Ubuntu is ready
In PowerShell (Windows side), check your distro:
```powershell
wsl -l -v
```
You want an **Ubuntu** entry on **version 2**. If you don't have one: `wsl --install -d Ubuntu`.

### Step 2: Enable systemd (needed later for fail2ban)
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

### Step 3: Update system & install the security tools
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-venv python3-pip sqlite3 \
    john hashcat hydra fail2ban iptables net-tools curl git
```

### Step 4: Check the attack tools run
```bash
john --list=formats | grep -i md5
hashcat -I          # lists compute devices (CPU is fine, no GPU needed)
hydra -h | head -5
```
If `hashcat -I` errors about OpenCL, install `pocl-opencl-icd` or just plan to run it in CPU/benchmark mode — that's enough for this project.

### Step 5: Project folder + virtual environment
```bash
mkdir -p ~/p11-auth-project/{app,logs,wordlists,results}
cd ~/p11-auth-project
python3 -m venv venv
source venv/bin/activate
pip install flask bcrypt argon2-cffi pyotp qrcode[pil]
pip freeze > requirements.txt
```

### Step 6: Get a wordlist
Standard Ubuntu doesn't ship `rockyou.txt` (that's a Kali default). Pull a copy from SecLists, a standard, widely-used public wordlist repo for authorized security testing:
```bash
cd ~/p11-auth-project/wordlists
curl -L -o rockyou.txt.gz \
  https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
# if that mirror is down, search "SecLists rockyou.txt" and grab it from
# github.com/danielmiessler/SecLists (Passwords/Leaked-Databases/rockyou.txt.tar.gz)
```
A 1,000–5,000 line subset works fine too if the full 14M-line file is slow on your machine — note that choice in your report's methodology section.

### Step 7: Find your WSL interface IP (you'll need this later)
```bash
ip addr show eth0 | grep "inet "
```
Note this IP (e.g. `172.20.x.x`). **Use this IP, not `127.0.0.1`,** when Hydra attacks the app later — fail2ban bans by source IP, and loopback traffic doesn't behave the same way as a real interface hit. Binding to `0.0.0.0` and attacking via the eth0 IP makes the whole attack/defense story actually work.

---

## Phase 1 — Build the intentionally weak app (pre-Milestone 1)

### Step 8: Database schema (weak version)
`app/init_db_v1.py`:
```python
import sqlite3

conn = sqlite3.connect("users.db")
conn.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
)
""")
conn.commit()
conn.close()
print("DB initialised (weak schema)")
```

### Step 9: The vulnerable Flask app
`app/app_v1_weak.py`:
```python
from flask import Flask, request, render_template_string, redirect
import sqlite3, hashlib

app = Flask(__name__)
DB = "users.db"

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
        return "incorrect username or password", 401   # Hydra will match this failure string
    return render_template_string(LOGIN_FORM)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
```

### Step 10: Seed a few "victim" accounts with weak, dictionary passwords
`app/seed_users.py`:
```python
import sqlite3, hashlib

users = [
    ("alice", "password123"),
    ("bob", "letmein"),
    ("carol", "dragon123"),
    ("dave", "qwerty1"),
]

conn = sqlite3.connect("users.db")
for u, p in users:
    h = hashlib.md5(p.encode()).hexdigest()
    conn.execute("INSERT OR IGNORE INTO users (username, password_hash) VALUES (?,?)", (u, h))
conn.commit()
conn.close()
print("Seeded users.")
```
Run both setup scripts, then start the app:
```bash
cd ~/p11-auth-project/app
python init_db_v1.py
python seed_users.py
python app_v1_weak.py
```
Confirm it loads at `http://<your-eth0-ip>:5000/login`.

**Back up this state now** — you need it as "before" evidence:
```bash
cp users.db ../results/users_phase1_weak.db.bak
```

---

## Phase 2 — Attack the weak app (Milestone 1)

### Step 11: Export the hashes for offline cracking
`app/dump_hashes.py`:
```python
import sqlite3

conn = sqlite3.connect("users.db")
rows = conn.execute("SELECT username, password_hash FROM users").fetchall()
with open("../results/md5_hashes.txt", "w") as f:
    for username, h in rows:
        f.write(f"{username}:{h}\n")
print("Wrote results/md5_hashes.txt")
```

### Step 12: Crack with John the Ripper
```bash
cd ~/p11-auth-project/results
john --format=Raw-MD5 --wordlist=../wordlists/rockyou.txt md5_hashes.txt
john --show --format=Raw-MD5 md5_hashes.txt
```
Record the wall-clock time (`time john ...`) and the cracked plaintexts — this is your "attack implementation & results" evidence.

### Step 13: Crack the same hashes with Hashcat (for comparison)
Hashcat wants just the hash column, so strip usernames:
```bash
cut -d: -f2 md5_hashes.txt > md5_only.txt
time hashcat -m 0 -a 0 -o cracked_hashcat.txt md5_only.txt ../wordlists/rockyou.txt
cat cracked_hashcat.txt
```
`-m 0` = MD5. Note hashes/sec reported by Hashcat — you'll reuse this number in Phase 4's comparison table.

### Step 14: Brute-force the live login with Hydra
With the app still running (bound to `0.0.0.0:5000`, hit via your eth0 IP):
```bash
hydra -l alice -P ../wordlists/rockyou.txt <your-eth0-ip> -s 5000 \
  http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"
```
- `-l alice` — single known username (swap to `-L userlist.txt` to attack several at once)
- `F=incorrect` — the string Hydra treats as "login failed" (matches the Flask response text)

Record: how long it took Hydra to find `alice`'s password, and a screenshot/log excerpt of the successful hit. This is your "before" brute-force evidence.

> **Checkpoint — Milestone 1 done:** you have cracked hashes offline (John + Hashcat) and a successful online brute-force (Hydra) against the weak app.

---

## Phase 3 — Add the defenses (Milestone 2)

### Step 15: New schema with lockout + MFA fields
`app/init_db_v2.py`:
```python
import sqlite3

conn = sqlite3.connect("users.db")
conn.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,       -- now a bcrypt hash (salt embedded)
    totp_secret TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    lockout_until REAL NOT NULL DEFAULT 0
)
""")
conn.commit()
conn.close()
print("DB initialised (hardened schema)")
```
Start fresh for Phase 3 (keep the Phase 1 `.bak` file as your "before" evidence; don't overwrite it):
```bash
rm -f users.db
python init_db_v2.py
```

### Step 16: Hardened app — bcrypt + lockout + TOTP
`app/app_v2_hardened.py`:
```python
from flask import Flask, request, render_template_string, redirect, session
import sqlite3, time, bcrypt, pyotp, qrcode, io, base64

app = Flask(__name__)
app.secret_key = "dev-secret-change-me"
DB = "users.db"
BCRYPT_ROUNDS = 12          # work factor — you'll vary this in Phase 4
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 15 * 60

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def log_failed_attempt(username, ip):
    # fail2ban watches this exact format
    with open("../logs/auth.log", "a") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} Failed login attempt for user={username} from {ip}\n")

REGISTER_FORM = """
<h2>Register</h2>
<form method="post">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
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
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode()
        secret = pyotp.random_base32()
        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, totp_secret) VALUES (?,?,?)",
                (username, pw_hash, secret))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username already taken", 400
        finally:
            conn.close()

        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="P11SecureApp")
        img = qrcode.make(uri)
        buf = io.BytesIO(); img.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()
        return f"""
        <h2>Scan this with Google Authenticator / Authy, then log in</h2>
        <img src="data:image/png;base64,{qr_b64}"><br>
        Secret (manual entry): {secret}<br>
        <a href="/login">Go to login</a>
        """
    return render_template_string(REGISTER_FORM)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        ip = request.remote_addr
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

        if user and user["lockout_until"] > time.time():
            conn.close()
            return "account temporarily locked due to too many failed attempts", 403

        if user and bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
            conn.execute("UPDATE users SET failed_attempts=0 WHERE username=?", (username,))
            conn.commit(); conn.close()
            session["pending_mfa_user"] = username
            return redirect("/verify-mfa")

        if user:
            attempts = user["failed_attempts"] + 1
            lockout = time.time() + LOCKOUT_SECONDS if attempts >= MAX_ATTEMPTS else 0
            conn.execute("UPDATE users SET failed_attempts=?, lockout_until=? WHERE username=?",
                         (attempts, lockout, username))
            conn.commit()
        conn.close()
        log_failed_attempt(username, ip)
        return "incorrect username or password", 401
    return render_template_string(LOGIN_FORM)

@app.route("/verify-mfa", methods=["GET", "POST"])
def verify_mfa():
    username = session.get("pending_mfa_user")
    if not username:
        return redirect("/login")
    if request.method == "POST":
        code = request.form["code"]
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()
        if user and pyotp.TOTP(user["totp_secret"]).verify(code):
            session.pop("pending_mfa_user", None)
            session["user"] = username
            return f"Login successful! Welcome {username} (password + MFA verified)"
        log_failed_attempt(username, request.remote_addr)
        return "incorrect MFA code", 401
    return render_template_string(MFA_FORM)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
```

Run it:
```bash
python app_v2_hardened.py
```
Register a user at `/register`, scan the QR code with an authenticator app (Google Authenticator / Authy / FreeOTP — any TOTP app works), then confirm you can log in through both the password step and the MFA step.

### Step 17: fail2ban — network-layer lockout on top of the app-level one
Create the filter, `/etc/fail2ban/filter.d/flaskapp.conf`:
```ini
[Definition]
failregex = Failed login attempt for user=\S+ from <HOST>
ignoreregex =
```
Create the jail, `/etc/fail2ban/jail.d/flaskapp.local` (replace `<you>` with your Linux username):
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
Start it and check status:
```bash
sudo service fail2ban start
sudo fail2ban-client status flaskapp
```
**Note for your report:** fail2ban bans by source IP at the firewall. Because John/Hashcat work offline against exported hashes, fail2ban is only relevant to the Hydra/online path — it's a second, independent layer behind the app-level lockout, not a replacement for it. That distinction is worth a sentence in your defense/mitigation section.

---

## Phase 4 — Re-attack the hardened app & tabulate (Milestone 3)

### Step 18: Re-run Hydra against the hardened login
```bash
hydra -l alice -P ../wordlists/rockyou.txt <your-eth0-ip> -s 5000 \
  http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"
```
Expect: after `MAX_ATTEMPTS` (5) wrong guesses, every further attempt gets `account temporarily locked...` instead of a password check at all — Hydra's brute force effectively stops, and even on a lucky correct guess it still needs the TOTP step, which it cannot brute-force (new 6-digit code every 30 seconds, and the lockout logic covers wrong MFA codes too). Capture:
```bash
sudo fail2ban-client status flaskapp   # shows the banned IP
tail -20 ../logs/auth.log
```
Screenshot all three (Hydra output, fail2ban status, the log) as "after" evidence.

### Step 19: Benchmark the hashing work factor
This gives you the actual numbers for "crack-time vs. work factor" — no GPU required.

`results/benchmark_hashing.py`:
```python
import time, bcrypt, hashlib
from argon2 import PasswordHasher
from argon2.low_level import Type

WORDLIST_SIZE = 14_300_000   # rockyou.txt, adjust if you used a subset

def time_fn(fn, n=20):
    start = time.perf_counter()
    for _ in range(n):
        fn()
    return (time.perf_counter() - start) / n

# Unsalted MD5 (phase 1 baseline)
md5_time = time_fn(lambda: hashlib.md5(b"testpassword123").hexdigest())

print(f"{'Hash':<20}{'Params':<18}{'Time/hash (s)':<16}{'Hashes/sec':<14}{'Est. time full wordlist'}")

def report(name, params, t):
    rate = 1 / t
    total_seconds = t * WORDLIST_SIZE
    print(f"{name:<20}{params:<18}{t:<16.8f}{rate:<14.1f}{total_seconds/3600:.2f} hours")

report("MD5 (unsalted)", "-", md5_time)

for rounds in [10, 12, 14]:
    t = time_fn(lambda r=rounds: bcrypt.hashpw(b"testpassword123", bcrypt.gensalt(rounds=r)), n=5)
    report("bcrypt", f"rounds={rounds}", t)

ph = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)  # argon2id defaults
t = time_fn(lambda: ph.hash("testpassword123"), n=5)
report("argon2id", "t=2,m=19MB,p=1", t)
```
```bash
pip install argon2-cffi
python benchmark_hashing.py
```
Fill the printed numbers into a table like this in your report:

| Hash | Work factor | Time per hash (ms) | Hashes/sec | Est. time to test full wordlist |
|---|---|---|---|---|
| MD5 (unsalted) | — | *(from script)* | *(from script)* | *(from script)* |
| bcrypt | rounds=10 | | | |
| bcrypt | rounds=12 | | | |
| bcrypt | rounds=14 | | | |
| Argon2id | default | | | |

You should see MD5 at hundreds of thousands–millions of hashes/sec, versus bcrypt/argon2 at tens to low-hundreds per second — several orders of magnitude slower, which is exactly the "work factor" story the rubric wants, with your own measured numbers instead of textbook claims.

### Step 20: Try John/Hashcat against the new bcrypt hashes (optional but strong evidence)
Export a couple of bcrypt hashes the same way as Step 11, then:
```bash
john --format=bcrypt --wordlist=../wordlists/rockyou.txt bcrypt_hashes.txt
hashcat -m 3200 -a 0 bcrypt_only.txt ../wordlists/rockyou.txt
```
Let it run for a few minutes and report the dramatically lower attempts/sec Hashcat reports for `-m 3200` versus `-m 0` earlier — direct before/after comparison.

> **Checkpoint — Milestone 3 done:** you have a filled comparison table and a captured "attack now fails" demonstration.

---

## Phase 5 — Writing the report (15 marks)

### Step 21: Suggested structure (mapped directly to the rubric)
1. **Problem definition & threat model (2)** — what's being protected (user credentials in `users.db`), the attacker model (anyone who can reach the login endpoint, or who obtains the hash DB), and what's at risk if passwords are weakly hashed or guessable online.
2. **Methodology & lab setup (3)** — WSL Ubuntu version, tool versions (`john --version`, `hashcat -V`, `hydra -h` header, Python/Flask versions), network topology (single-host WSL, eth0 IP used, port 5000), and exact steps to reproduce (point to your scripts).
3. **Attack implementation & results (3)** — Phase 2 evidence: John/Hashcat cracked plaintexts + timings, Hydra successful brute force + timing, screenshots/log excerpts.
4. **Defense / mitigation & evaluation (3)** — Phase 3 implementation (bcrypt + rounds, lockout logic, TOTP, fail2ban) and Phase 4 re-run showing the same attacks now fail or are drastically slowed, with before/after side by side.
5. **Analysis & discussion (2)** — *why* bcrypt/argon2 resist offline cracking (deliberately slow, tunable work factor, salted so no rainbow tables), *why* lockout + fail2ban stop online brute force, *why* MFA stops credential-only attacks, and limits/residual risk (e.g., lockout can itself be abused for denial-of-service against a legitimate user; fail2ban only sees network-visible attempts; TOTP secret must be delivered to the user securely at enrollment).
6. **Report quality & reproducibility (2)** — include `requirements.txt`, your scripts folder, a short README with exact run commands, and cite any tools/wordlists/libraries you used.

### Step 22: Evidence checklist to actually include
- [ ] Screenshot: `john --show` output with cracked passwords
- [ ] Screenshot: Hashcat cracked output + speed (`H/s`)
- [ ] Screenshot/terminal log: successful Hydra run against weak app
- [ ] Screenshot: QR code enrollment + successful MFA login
- [ ] Screenshot: Hydra run against hardened app showing lockout message
- [ ] Screenshot: `fail2ban-client status flaskapp` showing a banned IP
- [ ] Filled benchmark table from Step 19
- [ ] Your `requirements.txt` and a short README

---

## Phase 6 — Demo & viva prep (15 marks, individual)

### Step 23: Suggested live demo order
1. Show the weak app running; register/show a seeded user.
2. Run Hydra live against it, get a hit.
3. Show John/Hashcat cracking the exported hash live (use a short wordlist subset so it finishes in seconds during the demo — mention in your report that the full-wordlist run was done separately for the real timing numbers).
4. Switch to the hardened app; show bcrypt hash format in the DB (`sqlite3 users.db "SELECT username, password_hash FROM users;"`), register a fresh user with MFA enrollment.
5. Run Hydra again — show it gets locked out after 5 attempts; show `fail2ban-client status flaskapp`.
6. Log in correctly end-to-end (password → MFA code) to prove it still works for a legitimate user.
7. Show your benchmark table.

### Step 24: Likely viva questions — be ready to explain, not just demo
- Why does salting defeat precomputed/rainbow-table attacks, even if the attacker has the wordlist?
- Why is bcrypt/argon2 "slow" a *security feature*? What's the cost parameter actually controlling?
- What's the difference between the app-level lockout and fail2ban — why have both?
- How does TOTP work mechanically (shared secret + current time step → HMAC → 6-digit code), and why can't Hydra brute-force it in practice?
- What happens if an attacker steals `users.db` directly (offline attack) versus attacking over the network (online attack) — which defense stops which?
- What's a realistic weakness of your own setup? (e.g., dev secret key hardcoded, no HTTPS/TLS on the demo app, lockout could be used to lock out a real user — this is a good "limits/residual risk" answer for both the report and viva.)

---

## Appendix A — Command cheat sheet

```bash
# Start the weak app
cd ~/p11-auth-project/app && python app_v1_weak.py

# Start the hardened app
cd ~/p11-auth-project/app && python app_v2_hardened.py

# Crack MD5 offline
john --format=Raw-MD5 --wordlist=../wordlists/rockyou.txt md5_hashes.txt
hashcat -m 0 -a 0 md5_only.txt ../wordlists/rockyou.txt

# Brute force login online
hydra -l alice -P ../wordlists/rockyou.txt <eth0-ip> -s 5000 \
  http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"

# fail2ban
sudo service fail2ban start
sudo fail2ban-client status flaskapp
sudo fail2ban-client unban <ip>   # to reset between demo runs

# Check WSL IP
ip addr show eth0 | grep "inet "
```

## Appendix B — WSL-specific troubleshooting

- **`iptables: command not found` or permission errors** — make sure `systemd=true` is set (Step 2) and you've fully restarted WSL (`wsl --shutdown` from PowerShell, not just closing the terminal).
- **iptables rules don't seem to apply** — WSL2 sometimes defaults to `iptables-legacy` vs `-nft` inconsistently; try `sudo update-alternatives --set iptables /usr/sbin/iptables-legacy` and retry.
- **fail2ban service won't start** — check `sudo fail2ban-client -x start` for verbose errors, and confirm the `logpath` in your jail file is an absolute path that actually exists.
- **Hydra attacking `127.0.0.1` doesn't get banned correctly** — this is expected; always attack via the `eth0` IP from Step 7, not loopback.
- **Hashcat complains about no GPU/OpenCL** — fine for this project; CPU-mode cracking and `-b` benchmarking are enough to produce your comparison numbers.

## Appendix C — Ethics & scope (put a version of this in your report)

All testing in this project is performed against a locally-hosted application on the student's own machine, inside an isolated WSL environment, for the sole purpose of coursework evaluation. No external systems, networks, or third-party accounts are targeted. Tools used (John the Ripper, Hashcat, Hydra, fail2ban) are standard, publicly available security auditing tools taught in security curricula worldwide and are used here strictly in an authorized, self-contained lab.
