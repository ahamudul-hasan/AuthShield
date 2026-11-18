# AuthShield 2.0 — Full Upgrade Roadmap

**Project type:** Authentication security and threat-monitoring
platform\
**Original project:** P11 — Authentication & Password Security\
**Development environment:** WSL2 Ubuntu\
**Frontend:** React + TypeScript + Tailwind CSS\
**Backend:** Python + Flask\
**Database:** PostgreSQL (Neon Serverless Cloud)\
**Main priority:** Security event detection and threat monitoring

------------------------------------------------------------------------

# 1. Project overview

AuthShield 2.0 is the next version of the P11 authentication and
password-security project. The goal is to preserve the original security
experiments and build a complete application around them.

The original P11 project deliberately creates a weak login application,
attacks it in a controlled local lab, adds security defenses, and
repeats the tests to show whether those defenses work.

AuthShield 2.0 will keep that learning approach while adding:

-   A modern React and Tailwind user interface.
-   A Flask REST API.
-   PostgreSQL (hosted on Neon Serverless) for the new application.
-   Strong password hashing with Argon2id.
-   Existing bcrypt password migration support.
-   TOTP multi-factor authentication.
-   Session management and recovery features.
-   Structured security-event collection.
-   A rule-based threat-detection engine.
-   Risk scoring and security alerts.
-   Optional automated response using existing Fail2Ban and firewall
    defenses.
-   Security analytics and an administrator dashboard.
-   Automated testing and deployment documentation.

## The main idea

**AuthShield should not only protect accounts. It should also explain
suspicious authentication activity and help an administrator investigate
it.**

For example, instead of only displaying "Login failed", the system
should be able to identify repeated failed attempts against several
accounts from one source IP, create a brute-force or credential-stuffing
alert, explain the evidence, and show the incident in the dashboard.

## What the finished project should do

1.  Users can register and log in.
2.  Passwords are stored using Argon2id.
3.  Existing bcrypt hashes can still be verified and upgraded after a
    successful login.
4.  Users can enable TOTP MFA.
5.  Users can view and revoke their own sessions.
6.  Authentication activity is recorded as structured security events.
7.  The detection engine analyzes events and identifies suspicious
    patterns.
8.  Security alerts are created with severity, evidence, and
    explanations.
9.  Administrators can investigate and update alert status.
10. The dashboard displays authentication activity and threat trends.
11. Existing P11 attack demonstrations remain available in an isolated
    lab.
12. Automated tests verify authentication, detection, and authorization
    behavior.

------------------------------------------------------------------------

# 2. Stage 0 — Preserve the original P11 project

Do not delete the original project or replace it with AuthShield 2.0.

The original P11 guide contains these important features:

| Existing P11 feature | How AuthShield 2.0 will use it |
| --- | --- |
| Weak MD5 login application | Keep as an isolated vulnerable demonstration |
| John the Ripper | Keep for the controlled offline hash-cracking experiment |
| Hashcat | Keep for GPU/CPU hash-cracking comparisons |
| Hydra | Keep for authorized local online-login testing |
| Hardened bcrypt application | Use as the starting point for the new authentication design |
| Five failed attempts and 15-minute lockout | Preserve as the initial lab policy, then make configurable |
| TOTP MFA | Keep and improve |
| Fail2Ban and iptables | Keep as network-level defenses |
| Hashing benchmarks | Keep the old results and add new Argon2id measurements |
| SQLite | Preserve the old database; use PostgreSQL (Neon Serverless Cloud) for the new application |
| Basic `auth.log` | Keep a compatible log output for Fail2Ban and add structured database events |

## Important safety boundary

All John, Hashcat, and Hydra demonstrations must remain limited to your
own local lab or systems for which you have explicit permission. Never
expose the intentionally vulnerable MD5 application to the public
internet. Run it bound to `127.0.0.1` only, not `0.0.0.0`.

## Step 0.1 — Back up the original project

**What this step does:** Ensures the original P11 coursework, database, and experiment results are safely preserved.

**Status:** The original P11 project is preserved in the dedicated Git branch (`Original_project`) and external repository, so redundant local backup copies are ignored.

**Check:** Confirm the `Original_project` branch exists and is accessible.

## Step 0.2 — Save the original version in Git

**What this step does:** Configures `.gitignore` so local databases, secrets, virtual environments, and large wordlists are kept out of version control.

**Why we do it:** Git tracks changes and lets you return to earlier commits if any new feature causes issues.

**Why it matters:** You can develop AuthShield 2.0 cleanly while keeping sensitive and build artifacts excluded.

From the project root:

``` bash
# Create .gitignore so local databases, secrets, and large files are never committed
cat >> .gitignore << 'EOF'
.env
.venv/
node_modules/
frontend/dist/
__pycache__/
.pytest_cache/
*.pyc
*.log
logs/*.log
*.db
*.db.bak
wordlists/rockyou.txt
EOF

git add .gitignore
git commit -m "Preserve original P11 project"
```

**Check:** Run `git status` and confirm the working tree is clean.

## Step 0.3 — Separate the legacy demonstration from the new application

**What this step does:** Moves the original weak and hardened applications, their SQLite database, and coursework documentation into dedicated directories (`legacy/` and `docs/`), keeping the project root organized for the new Flask backend and React frontend.

**Why we do it:** The old applications and audit logs are coursework demonstrations. The new AuthShield platform needs a modular architecture, production-ready structure, and clear separation of concerns.

**Why it matters:** You can continue demonstrating the original P11 attacks in an isolated lab without mixing vulnerable code or legacy SQLite databases into the new authentication system.

Project directory structure:

``` text
AuthShield/
├── legacy/                       # Isolated P11 Coursework Demonstration Lab
│   ├── app_v1_weak.py            # Phase 1 weak MD5 login app
│   ├── app_v2_hardened.py        # Phase 3 hardened bcrypt/Argon2 + lockout + TOTP app
│   └── database/                 # SQLite coursework database
│       ├── users.db              # Active SQLite DB for legacy lab
│       ├── schemas/              # Schema initializers (init_db_v1.py, init_db_v2.py)
│       ├── seeds/                # Dummy users seed script (seed_users.py)
│       └── backups/              # Baseline snapshot (users_phase1_weak.db.bak)
│
├── backend/                      # AuthShield 2.0 Flask REST API & Threat Engine (Stage 1+)
│   ├── app/
│   │   ├── auth/                 # Argon2id, bcrypt migration, TOTP, session manager
│   │   ├── detection/            # Event collector, detection rules, risk scoring engine
│   │   ├── alerts/               # Alert management endpoints
│   │   ├── dashboard/            # Metrics & security analytics
│   │   └── models/               # PostgreSQL models (User, SecurityEvent, Alert, Session)
│   ├── tests/                    # Automated pytest test suites
│   ├── migrations/               # Alembic database migrations
│   ├── requirements.txt          # Backend dependencies
│   └── run.py                    # Flask development server
│
├── frontend/                     # AuthShield 2.0 React + Vite + Tailwind UI (Stage 4+)
│   ├── src/
│   │   ├── components/           # UI components (charts, alert cards, badges)
│   │   ├── pages/                # Login, Register, MFA, Dashboard, Alerts, Sessions
│   │   └── services/             # API client & WebSocket connections
│   └── package.json
│
├── docs/                         # Coursework specifications, rubrics & guides
│   ├── Guide.md                  # Comprehensive P11 lab guide
│   ├── Note.md                   # Lab notes
│   ├── Topic.md                  # Assignment topic description
│   ├── work_factor_comparison.md # Hashing work-factor comparison analysis
│   ├── Evalution_metric.pdf      # Course evaluation criteria
│   ├── Project_proposal.pdf      # Original project proposal
│   ├── packages.txt              # Apt package dependencies
│   └── setup.txt                 # Tool installation notes
│
├── scripts/                      # Lab utility scripts
│   ├── benchmark_hashing.py      # Multi-algorithm hashing benchmark tool
│   └── dump_hashes.py            # SQLite user hash export utility
│
├── hashes/                       # Exported hash dumps for offline cracking
│   ├── md5_hashes.txt            # Unsalted MD5 user hashes
│   ├── bcrypt_hashes.txt         # Bcrypt hashes for cracking experiments
│   └── bcrypt_r10_only.txt / bcrypt_r12_only.txt
│
├── results/                      # Experiment outcome summaries & benchmark data
│   ├── benchmark_hashing.txt
│   ├── cracked_hashcat.txt
│   ├── cracked_hydra_weak.txt
│   └── cracked_john.txt
│
├── Terminal_crack_result/        # Raw terminal logs from offline/online cracking
│   ├── hashcat.txt
│   ├── hydra_weak.txt
│   └── john_the_ripper.txt
│
├── Terminal_defence_result/      # Raw terminal logs from defense verifications
│   ├── bcrypt_benchmark.txt
│   └── hydra_hardened.txt
│
├── wordlists/                    # Dictionaries for password cracking tests
│   └── rockyou.txt
│
├── logs/                         # Runtime log directory
│   └── auth.log                  # Fail2Ban-monitored authentication log
│
├── .gitignore                    # Environment & artifact exclusions
├── README.md                     # Repository overview & setup guide
├── requirements.txt              # Root legacy virtualenv requirements
└── setup.sh                      # Automated lab setup script
```

Files were moved using `git mv` so Git retains full file histories, and path references in `legacy/app_v1_weak.py`, `legacy/app_v2_hardened.py`, `scripts/dump_hashes.py`, and `setup.sh` were updated to resolve paths accurately.

**Check:** Both legacy applications must remain fully operational in the isolated lab environment.

------------------------------------------------------------------------

# 3. Target architecture

The application will have five main parts.

``` text
                       AUTHSHIELD 2.0

      Browser: React + TypeScript + Tailwind CSS
                         |
          HTTPS REST API  +  Socket.IO (live updates)
                         |
      +------------------+------------------+
      |             Flask backend           |
      |                                     |
      |   Authentication       Detection    |
      |   Argon2id, MFA        Engine       |
      |   Sessions, RBAC       Risk score   |
      |                        Alert manager|
      +---------+------------------+--------+
                |                  |
           PostgreSQL           auth.log
      Users, Events, Alerts,       |
      Sessions, Audit logs     Fail2Ban
                                   |
                               iptables
```

## Component responsibilities

| Component | Responsibility |
| --- | --- |
| React frontend | Displays login pages, dashboard, alerts, and analytics |
| Flask backend | Handles API requests and application logic |
| Authentication module | Verifies passwords, MFA, sessions, and permissions |
| Event collector | Records authentication and security activity |
| Detection engine | Finds suspicious patterns in collected events |
| Alert manager | Creates and updates security alerts |
| PostgreSQL (Neon Cloud) | Stores users, events, alerts, and sessions in serverless cloud |
| Fail2Ban + iptables | Provides network-level blocking when configured |
| Automated tests | Checks that the application and defenses behave correctly |

React never talks to the database directly. It only calls the Flask API, and Fail2Ban reads the
compatible `auth.log` file locally (it does not read PostgreSQL/Neon).

**Important design rule:** The frontend displays security information.
The backend makes authentication, detection, and authorization
decisions. Never rely on React alone to protect an administrator
endpoint.

------------------------------------------------------------------------

# 4. Stage 1 — Build the Flask backend and Neon PostgreSQL foundation

**Stage goal:** Create the backend structure and connect it to a new
Neon Serverless PostgreSQL database.

Estimated effort: 3–5 days.

## Step 1.1 — Create the backend directory

**What this step does:** Creates a separate folder for the new Flask
application.

**Why we do it:** The original P11 code is a small demonstration.
AuthShield has several modules, so keeping them organized makes
development easier.

**Why it matters:** Authentication, detection, alerts, and database code
can be developed and tested separately.

``` bash
# From the project root:
mkdir -p backend/app/{auth,detection,alerts,dashboard,models}
mkdir -p backend/tests backend/migrations
```

Create the initial files:

``` text
backend/
├── app/
│   ├── __init__.py
│   ├── config.py
│   ├── extensions.py
│   ├── auth/
│   ├── detection/
│   ├── alerts/
│   ├── dashboard/
│   └── models/
├── migrations/
├── tests/
├── requirements.txt
└── run.py
```

**Check:** Confirm that the folders and files exist.

## Step 1.2 — Create a new Python virtual environment

**What this step does:** Creates an isolated Python environment for the
new backend.

**Why we do it:** AuthShield will use more packages than the original
P11 application. A separate environment avoids package conflicts.

**Why it matters:** You can install, update, and reproduce backend
dependencies without changing the original setup.

``` bash
cd backend

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
```

Install the initial packages:

``` bash
pip install flask flask-cors flask-sqlalchemy \
    flask-migrate "psycopg[binary]" python-dotenv \
    flask-limiter argon2-cffi bcrypt pyotp \
    "qrcode[pil]" flask-wtf cryptography apscheduler
```

Save dependencies:

``` bash
pip freeze > requirements.txt
```

Install `pytest` for the tests in Stage 7, and install `flask-socketio`
when you reach Step 6.10 for real-time WebSocket updates.

**Check:** Run `pip list` and confirm that the packages are installed.

## Step 1.3 — Create and configure Neon Serverless PostgreSQL

**What this step does:** Creates a free, cloud-hosted serverless PostgreSQL
database using Neon (https://neon.tech).

**Why we do it:** The original P11 project uses SQLite for local coursework.
AuthShield 2.0 uses PostgreSQL for concurrent event ingestion and alerts.
Using Neon provides a fully managed, production-grade PostgreSQL instance in
seconds without needing to install, configure, or maintain local background
services in WSL2.

**Why it matters:** You get a built-in web SQL console, table visualizer,
automated backups, and instant database branching (allowing you to branch the
database for testing without breaking main data), while saving local RAM.

Implementation tasks:

1.  Sign up or log in at **https://neon.tech**.
2.  Click **Create Project** (Project name: `authshield-db`, Postgres version: 16, Region: choose the one closest to you).
3.  Neon immediately generates your database credentials. In the project dashboard under **Connection Details**:
    - Select **Connection string**
    - Copy the generated URI. It will look like:
      ```text
      postgresql://neondb_owner:YOUR_NEON_PASSWORD@ep-xyz.region.aws.neon.tech/neondb?sslmode=require
      ```
4.  Change the driver prefix from `postgresql://` to `postgresql+psycopg://` so SQLAlchemy uses the modern `psycopg` (psycopg3) driver installed in Step 1.2:
    ```text
    postgresql+psycopg://neondb_owner:YOUR_NEON_PASSWORD@ep-xyz.region.aws.neon.tech/neondb?sslmode=require
    ```
5.  *(Optional)* In the Neon Console under **Branches**, create a secondary branch named `test` (e.g. `authshield-test`). Use this connection string for `tests/` so automated test suites never overwrite live development events.

**Check:** Verify connection to Neon from your terminal using Python:

``` bash
python -c "
import psycopg
conn = psycopg.connect('postgresql://neondb_owner:YOUR_NEON_PASSWORD@ep-xyz.region.aws.neon.tech/neondb?sslmode=require')
print('Connected to Neon PostgreSQL version:', conn.execute('SELECT version()').fetchone()[0])
conn.close()
"
```
Confirm that it prints the PostgreSQL version string without errors.

## Step 1.4 — Configure environment variables

**What this step does:** Stores configuration and secrets outside the
source code.

**Why we do it:** Database passwords and Flask secret keys should not be
written directly into Python files.

**Why it matters:** You can change environments without changing
application code, and you reduce the risk of accidentally publishing
secrets.

Create `backend/.env`:

``` env
FLASK_DEBUG=false
SECRET_KEY=generate-a-long-random-secret
DATABASE_URL=postgresql+psycopg://neondb_owner:YOUR_NEON_PASSWORD@ep-xyz.region.aws.neon.tech/neondb?sslmode=require
```

Make sure `.gitignore` contains these entries (most were already added in
Step 0.2; add any that are missing). Also commit a `backend/.env.example`
with fake placeholder values so other people know which variables to set:

``` gitignore
.env
.venv/
__pycache__/
.pytest_cache/
*.pyc
```

Do not commit `.env`. Generate a different secret for each environment.

**Check:** Confirm that the application can load its configuration
without printing secret values.

## Step 1.5 — Create the Flask application factory

**What this step does:** Creates a central function that configures and
starts Flask.

**Why we do it:** A large application should not have all its routes,
database settings, and extensions inside one Python file.

**Why it matters:** A clean application factory makes testing,
configuration, and future changes easier.

Create:

``` text
backend/app/__init__.py
backend/app/config.py
backend/app/extensions.py
backend/run.py
```

The factory should:

1.  Create the Flask application.
2.  Load the selected configuration.
3.  Initialize SQLAlchemy and Flask-Migrate.
4.  Register authentication, alert, and dashboard blueprints.
5.  Register error handlers.
6.  Return the configured application.

Use separate development and testing configurations.

**Check:** Start Flask and confirm that it runs without errors.

## Step 1.6 — Add a health-check API

**What this step does:** Adds a simple endpoint that reports whether the
backend is running.

**Why we do it:** The frontend and deployment tools need a simple way to
check the backend.

**Why it matters:** You can troubleshoot whether a problem is in Flask,
the database, or the frontend.

Suggested endpoint:

``` text
GET /api/health
```

Expected response:

``` json
{
  "status": "ok"
}
```

Also add a database readiness check that verifies the database
connection without revealing credentials or internal errors.

**Check:** Open `/api/health` and confirm that it returns a successful
response.

------------------------------------------------------------------------

# 5. Stage 2 — Upgrade authentication

**Stage goal:** Build a secure authentication system while retaining
compatibility with the old bcrypt application.

Estimated effort: 5–7 days.

## Step 2.1 — Design the new user database model

**What this step does:** Defines the information AuthShield needs to
store for each user.

**Why we do it:** The original P11 user table contains a username,
password hash, MFA secret, failed-attempt count, and lockout
information. The new application needs additional fields for roles and
account status.

**Why it matters:** A well-designed user model supports authentication,
MFA, permissions, and account management.

Suggested user fields:

| Field | Purpose |
| --- | --- |
| `id` | Unique user identifier |
| `username` | User's login name |
| `email` | User's email address |
| `password_hash` | Stored password hash |
| `password_algorithm` | Current hash algorithm or hash-format indicator |
| `role` | User or administrator |
| `totp_secret` | MFA secret, stored with appropriate protection |
| `mfa_enabled` | Whether MFA is enabled |
| `failed_attempts` | Current failed-attempt count |
| `lockout_until` | Temporary lockout expiry |
| `created_at` | Account creation time |
| `updated_at` | Last account change |
| `is_active` | Whether the account is enabled (lets an administrator disable it; shown as "account status" in Step 6.8) |
| `last_login_at` | Time of the last successful login |
| `password_changed_at` | Used to revoke older sessions after a password change |

Do not store plaintext passwords.

**Check:** Create the model and confirm that a database migration
creates the table.

## Step 2.2 — Integrate Argon2id password hashing

**What this step does:** Uses Argon2id to hash new user passwords.

**Why we do it:** Your original project already benchmarks Argon2id, but
the hardened application primarily uses bcrypt. This step puts Argon2id
into the actual authentication process.

**Why it matters:** Argon2id is designed to make password guessing
expensive in both computation and memory. It is a strong choice for
password storage.

Implementation tasks:

1.  Create a password-hashing module.
2.  Configure Argon2id parameters.
3.  Hash passwords during registration.
4.  Verify passwords during login.
5.  Recheck and upgrade outdated parameters when a user logs in.
6.  Benchmark performance on your actual machine.

Use the Argon2id library's encoded hash format because it stores the
salt and parameters needed for verification.

**Check:** Register a test user, inspect the stored hash, and verify
that the correct password succeeds while a wrong password fails.

## Step 2.3 — Support existing bcrypt hashes

**What this step does:** Allows the new application to verify passwords
stored by the original bcrypt implementation.

**Why we do it:** You should not lose compatibility with accounts
created by the earlier hardened P11 application.

**Why it matters:** Existing users can move to the new system without an
immediate password reset.

Migration flow:

1.  Read the user's stored hash.
2.  Identify whether it is bcrypt or Argon2id.
3.  Verify the supplied password using the matching algorithm.
4.  If bcrypt verification succeeds, hash the password with Argon2id.
5.  Update the stored hash.
6.  Do not change the password itself.

**Check:** Create a bcrypt test hash, log in through the new
application, and confirm that the stored hash is upgraded after
successful verification.

## Step 2.4 — Add password-strength validation

**What this step does:** Checks password quality during registration and
password changes.

**Why we do it:** Users often choose common or predictable passwords.

**Why it matters:** Strong password storage does not make a weak
password impossible to guess. Password quality is another important
defense.

Implement checks for:

-   Minimum length.
-   Common or known-compromised passwords using a safe local list or
    suitable service.
-   Passwords containing the username or obvious personal identifiers.
-   Excessively long input handling.
-   Clear feedback to the user.

Do not rely only on rules such as "one uppercase letter and one symbol."
Encourage long, unique passwords.

**Check:** Test common weak passwords and strong passphrases.

## Step 2.5 — Keep and improve TOTP MFA

**What this step does:** Adds the existing TOTP authentication flow to
the new application.

**Why we do it:** Your original P11 project already uses PyOTP and
QR-code enrollment. The new system should preserve that protection.

**Why it matters:** A password alone should not be enough to access an
account when MFA is enabled.

Implementation tasks:

1.  Generate a unique TOTP secret for each user.
2.  Show a QR code during enrollment.
3.  Ask the user to verify a code before enabling MFA.
4.  Require a valid code after password verification.
5.  Apply rate limits to MFA verification.
6.  Handle small clock differences carefully.
7.  Provide a secure way to disable or replace MFA after
    reauthentication.
8.  Reject a TOTP code that was already used. Store the last accepted
    time step for each user so a captured code cannot be replayed
    within its validity window.
9.  After a correct password but before MFA, keep only a short-lived
    "pending MFA" state, never a full session, and do not reveal
    whether an account has MFA before the password is verified.

Encrypt MFA secrets at rest where practical, and keep the encryption key
outside the database.

**Check:** Test enrollment, successful login, incorrect codes, and
clock-skew handling.

## Step 2.6 — Add recovery codes

**What this step does:** Generates one-time backup codes for users who
lose access to their authenticator.

**Why we do it:** A user can lose a phone or uninstall an authenticator
app.

**Why it matters:** Recovery codes prevent a lost device from
permanently locking a legitimate user out.

Implementation tasks:

1.  Generate several random codes.
2.  Show them only once.
3.  Store only secure hashes of the codes.
4.  Mark each code as used after successful recovery.
5.  Require the user to re-enroll MFA if the authenticator is lost.

**Check:** Use one recovery code successfully and confirm that it cannot
be used again.

## Step 2.7 — Add secure session management

**What this step does:** Tracks active login sessions and lets users
terminate them.

**Why we do it:** A stolen or forgotten session may remain active even
after a user changes their password.

**Why it matters:** Users and administrators need a way to identify and
revoke sessions.

**Design decision:** Flask's default session is a signed cookie stored in
the browser, and it cannot be revoked individually. Because this project
needs "list and revoke sessions", use a random opaque session ID in an
`HttpOnly` cookie and keep the matching record (hashed) in the
`user_sessions` table. Check that record on every request.

With a React frontend, avoid cross-origin cookie problems during
development by using the Vite dev-server proxy so the browser sees one
origin. If you use CORS with credentials instead, restrict the allowed
origin explicitly. For CSRF, enable Flask-WTF `CSRFProtect`, provide the
token through a `GET /api/auth/csrf` endpoint, and have React send it in
the `X-CSRFToken` header.

Implementation tasks:

1.  Use secure browser session cookies.
2.  Store a hash of any server-side session token, not the raw token.
3.  Set session expiry and idle timeout policies.
4.  Rotate session identifiers after authentication and privilege
    changes.
5.  Add a page to list the current user's sessions.
6.  Allow users to revoke individual sessions.
7.  Revoke sessions after password reset when appropriate.
8.  Revoke other sessions after a password change or when MFA is
    disabled.

For cookie-based authentication, use `HttpOnly`, `Secure` in HTTPS
environments, and an appropriate `SameSite` setting. Add CSRF protection
to state-changing requests.

**Check:** Log in from two browser sessions and revoke one session from
the other.

## Step 2.8 — Add password reset

**What this step does:** Allows users to reset forgotten passwords using
a secure, temporary token.

**Why we do it:** Users need a safe recovery method when they forget
their password.

**Why it matters:** A poorly designed reset process can become an easier
way to take over an account than the login process itself.

Implementation tasks:

1.  Accept a reset request.
2.  Return a generic response whether or not the account exists.
3.  Generate a cryptographically random token.
4.  Store only a hash of the token.
5.  Give the token a short expiry.
6.  Allow it to be used only once.
7.  Hash the new password with Argon2id.
8.  Revoke existing sessions after a successful reset.
9.  Record a security event.
10. Do not let a password reset bypass MFA. A user with MFA enabled must
    still pass MFA at the next login, otherwise access to the email
    account defeats the second factor.

For a local project, you can initially display reset links only in a
development email console. Do not log reset tokens in production.

**Check:** Test valid, expired, reused, and invalid reset tokens.

## Step 2.9 — Add role-based access control

**What this step does:** Gives different users different permissions.

**Why we do it:** Ordinary users should not be able to inspect security
alerts or manage other accounts.

**Why it matters:** If a normal account is compromised, role
restrictions reduce what the attacker can do.

Initial roles:

-   `user`: can manage their own account and sessions.
-   `admin`: can view security events, investigate alerts, and manage
    approved security settings.

Check permissions on the Flask backend for every protected endpoint.

Never accept a `role` value from the registration request. Create the
first administrator with a command-line or seed script (for example
`flask create-admin`), not through a public endpoint.

**Check:** Confirm that a normal user receives a forbidden response when
accessing an admin-only API.

------------------------------------------------------------------------

# 6. Stage 3 — Build the security-event collection system

**Stage goal:** Record useful authentication activity in a structured
format.

Estimated effort: 3–4 days.

This is the foundation for the main threat-detection feature.

## Step 3.1 — Define event types

**What this step does:** Creates a consistent list of event names for
the application.

**Why we do it:** Different routes should not invent different names for
the same event.

**Why it matters:** Consistent event names make detection rules,
analytics, and reports easier to build.

Initial event types:

| Event type | Meaning |
| --- | --- |
| `LOGIN_SUCCESS` | Password and required authentication checks succeeded |
| `LOGIN_FAILURE` | Login failed |
| `MFA_SUCCESS` | MFA verification succeeded |
| `MFA_FAILURE` | MFA verification failed |
| `ACCOUNT_LOCKED` | Account entered a temporary lockout |
| `PASSWORD_RESET_REQUESTED` | A reset was requested |
| `PASSWORD_RESET_COMPLETED` | A password reset succeeded |
| `SESSION_CREATED` | A session was created |
| `SESSION_REVOKED` | A session was revoked |
| `MFA_ENABLED` | MFA was enabled |
| `MFA_DISABLED` | MFA was disabled |
| `ADMIN_ACTION` | An administrator performed a security action |
| `IP_BLOCKED` | A configured defense blocked an IP |
| `IP_UNBLOCKED` | A blocked IP was released |
| `USER_REGISTERED` | A new account was created |
| `LOGIN_BLOCKED` | A login attempt was rejected because the account was locked |
| `RATE_LIMITED` | A request exceeded a rate limit |
| `PASSWORD_CHANGED` | A signed-in user changed their password |
| `RECOVERY_CODE_USED` | A recovery code was used |

**Check:** Confirm that all authentication routes use the shared event
names.

## Step 3.2 — Create the security-event database model

**What this step does:** Creates a PostgreSQL table for authentication
and security events.

**Why we do it:** The old `auth.log` is useful for Fail2Ban, but it is
not as convenient for filtering and analytics as structured database
records.

**Why it matters:** The detection engine needs reliable event data to
identify patterns over time.

Suggested fields:

| Field | Purpose |
| --- | --- |
| `id` | Event identifier |
| `event_type` | Type of activity |
| `user_id` | Related user, if known |
| `source_ip` | Source address |
| `user_agent` | Browser or client information |
| `timestamp` | UTC event time |
| `success` | Whether the action succeeded |
| `attempted_identifier` | Keyed hash (HMAC) of the normalized username that was typed, so attempts against non-existent accounts can still be counted |
| `details` | Safe extra event information (JSONB) |

Do not name a SQLAlchemy column or attribute `metadata`. That name is
reserved by SQLAlchemy's Declarative API and raises an error, which is why
the field is called `details` here.

Failed logins for usernames that do not exist have no `user_id`. Without
`attempted_identifier`, the detector in Stage 4 could not count them for
credential-stuffing or spraying detection. Do not store the raw typed
username, because users sometimes type their password into that field.

Use indexes for commonly queried fields such as `event_type`, `user_id`,
`source_ip`, and `timestamp`.

**Check:** Insert a test event and retrieve it from PostgreSQL.

## Step 3.3 — Build the event collector

**What this step does:** Creates one shared function for saving security
events.

**Why we do it:** If each route writes logs differently, the system
becomes difficult to maintain.

**Why it matters:** A single collector makes event data more consistent
and reduces mistakes.

Suggested module:

``` text
backend/app/detection/
├── event_types.py
├── event_collector.py
└── event_repository.py
```

Example usage:

``` python
record_security_event(
    event_type="LOGIN_FAILURE",
    user_id=user_id,
    source_ip=source_ip,
    attempted_identifier=attempted_identifier,
    details={"reason": "invalid_credentials"}
)
```

This is an illustrative interface. Implement it with your actual
SQLAlchemy model and application context.

**Security rules:**

-   Never record plaintext passwords.
-   Never record TOTP codes.
-   Never record session cookies or reset tokens.
-   Sanitize user-controlled values.
-   Use UTC timestamps.
-   Apply retention limits to old event data.
-   Do not blindly trust forwarded IP headers. Only use proxy-provided
    client addresses when the proxy is explicitly trusted and correctly
    configured.

**Check:** Trigger several test actions and verify that the database
contains safe, structured events.

## Step 3.4 — Connect events to authentication routes

**What this step does:** Makes authentication routes send events to the
collector.

**Why we do it:** The collector is useful only if the application
actually sends activity to it.

**Why it matters:** The detection engine needs a complete and consistent
view of login and account activity.

Connect the collector to:

1.  Registration.
2.  Successful login.
3.  Failed login.
4.  MFA success and failure.
5.  Account lockout.
6.  Password reset.
7.  Session creation.
8.  Session revocation.
9.  MFA changes.
10. Administrative security actions.

Keep the original Fail2Ban-compatible `auth.log` output until the new
logging integration has been tested. If the log format changes, update
and test the Fail2Ban filter as well.

**Check:** Perform each action and confirm that the expected event
appears.

------------------------------------------------------------------------

# 7. Stage 4 — Build the threat-detection engine

**Stage goal:** Analyze security events and detect suspicious
authentication behavior.

Estimated effort: 5–7 days.

**This is the highest-priority new feature in AuthShield 2.0.**

Start with rule-based detection. Do not begin with machine learning.
Rules are easier to understand, test, and explain during a project
demonstration.

## Step 4.1 — Create the detection module

**What this step does:** Creates a separate part of the backend for
analyzing security events.

**Why we do it:** Event collection and threat detection are different
jobs. The collector records what happened; the detector decides whether
the activity looks suspicious.

**Why it matters:** Separating the two makes the application easier to
test and extend.

Suggested structure:

``` text
backend/app/detection/
├── event_types.py
├── event_collector.py
├── event_repository.py
├── rules.py
├── risk_engine.py
├── detector.py
└── alert_manager.py
```

**When the detector runs:** After a failure-type event is stored, run
only the rules for the affected account and source IP over their time
window (the indexes from Step 3.2 keep this fast). Also run a periodic
sweep, for example every minute with APScheduler or a command-line job,
for window-based rules such as distributed attacks. Do not scan the
whole events table on every request.

**Check:** Import the detection module from a test without starting the
frontend.

## Step 4.2 — Implement brute-force detection

**What this step does:** Detects repeated failed login attempts against
one account.

**Why we do it:** An attacker may repeatedly guess passwords until one
works.

**Why it matters:** Detecting repeated failures helps identify attacks
that the ordinary login response alone cannot explain.

Example starting rule:

-   5 failed attempts against one account within 5 minutes.
-   Create a high-severity alert.
-   Include the number of failures and the time window as evidence.

Because the original lockout policy locks the account after 5 failures,
record later attempts during the lockout as `LOGIN_BLOCKED` events. This
way the detector still sees an attack that continues after the lockout.

These are starting lab values, not universal security settings. Make
thresholds configurable and test them against normal user mistakes.

**Check:** Generate five failed-login test events within the configured
window and verify that an alert is created.

## Step 4.3 — Implement credential-stuffing detection

**What this step does:** Detects a source IP trying many different
accounts.

**Why we do it:** Credential stuffing uses previously leaked
username/password combinations across multiple accounts.

**Why it matters:** A detector that only counts failures for one account
may miss attacks that spread attempts across many accounts.

Example starting rule:

-   One source IP attempts logins against 10 distinct accounts within 10
    minutes.
-   Generate a credential-stuffing indicator.
-   Count distinct `attempted_identifier` values, not only `user_id`,
    because many of the attempts will target accounts that do not exist.

**Check:** Generate failed-login events for several test accounts from
the same simulated source IP.

## Step 4.4 — Implement password-spraying indicators

**What this step does:** Looks for repeated failures across many
accounts that may indicate password spraying.

**Why we do it:** Password spraying tries a small number of likely
passwords against many accounts instead of trying many passwords against
one account.

**Why it matters:** It can avoid simple per-account lockout thresholds.

For privacy and security, do not store attempted plaintext passwords
just to detect this behavior. Use safe signals, such as account
distribution, source patterns, and controlled test metadata. A simple
event-only detector may identify suspicious cross-account behavior but
cannot prove that the same password was used if the application never
stores that information.

**Check:** Simulate the pattern using test metadata or a controlled test
harness.

## Step 4.5 — Implement MFA-failure detection

**What this step does:** Detects repeated incorrect MFA verification
attempts.

**Why we do it:** An attacker who has obtained a password may still try
to guess the second factor.

**Why it matters:** MFA needs its own monitoring and rate limits, not
just password-login monitoring.

Example starting rule:

-   5 MFA failures within 5 minutes for one account.
-   Create a high-severity alert.

**Check:** Generate MFA failure events and verify the alert.

## Step 4.6 — Detect suspicious success after failures

**What this step does:** Identifies a successful login shortly after
repeated failures.

**Why we do it:** A series of failed attempts followed by a successful
login may indicate that an attacker eventually guessed a password.

**Why it matters:** A successful login should not automatically erase
the context of suspicious activity that happened just before it.

Example starting rule:

-   Several failures against an account.
-   A successful login for that account soon afterward.
-   Create an incident for investigation.

Do not assume every such login is malicious. It may be a legitimate user
who mistyped their password.

**Check:** Generate a failure sequence followed by a successful login
and inspect the resulting alert.

## Step 4.7 — Detect distributed attacks

**What this step does:** Looks for many source IPs targeting the same
account.

**Why we do it:** Attackers may distribute attempts across multiple
addresses to avoid simple per-IP thresholds.

**Why it matters:** Monitoring only one IP at a time can miss
coordinated activity.

Example starting rule:

-   Multiple distinct IPs attempt the same account within a defined time
    window.
-   Generate a distributed-attack indicator.

Use appropriate proxy and source-IP handling so that the system does not
accidentally treat every request as coming from the same proxy.

**Check:** Generate events from multiple simulated IP values in the test
dataset.

## Step 4.8 — Build the risk-scoring engine

**What this step does:** Assigns a numeric risk score to suspicious
activity.

**Why we do it:** Different events have different levels of concern. A
few mistakes should not be treated the same as a large coordinated
attack.

**Why it matters:** A risk score helps administrators prioritize
incidents.

Illustrative starting point:

| Signal | Example points |
| --- | --- |
| Several failed logins in a short period | +10 |
| Brute-force threshold reached | +50 |
| Many different accounts targeted by one IP | +40 |
| Repeated MFA failures | +60 |
| Successful login after a failure burst | +30 |
| Many IPs targeting one account | +30 |

Illustrative severity bands:

| Score | Severity |
| --- | --- |
| 0–29 | Low |
| 30–59 | Medium |
| 60–79 | High |
| 80–100 | Critical |

Check that the numbers match your rules: Steps 4.2 and 4.5 call
brute-force and MFA-failure alerts "high severity", so each must reach at
least 60 on its own (brute force: 10 + 50 = 60). A login that succeeds
after a brute-force burst (60 + 30 = 90) correctly becomes Critical.

Implementation rules:

1.  Keep the score between 0 and 100.
2.  Avoid counting the same event repeatedly.
3.  Use time windows and deduplication.
4.  Make the scoring rules configurable.
5.  Record which signals contributed to the score.
6.  Allow scores to decay or expire according to a documented policy.

These scores are project examples. Tune them using your test data and
false-positive evaluation.

**Check:** Test low-, medium-, high-, and critical-risk examples.

## Step 4.9 — Create the alert manager

**What this step does:** Turns detections into stored security alerts.

**Why we do it:** A detection result should become an incident that an
administrator can review.

**Why it matters:** Without an alert record, the application may detect
an attack but provide no useful investigation workflow.

Suggested alert fields:

| Field | Purpose |
| --- | --- |
| `id` | Alert identifier |
| `alert_type` | Brute force, spraying, MFA failures, etc. |
| `severity` | Low, medium, high, critical |
| `risk_score` | Calculated score |
| `source_ip` | Related source |
| `target_user_id` | Related account, if known |
| `description` | Human-readable explanation |
| `evidence` | Safe supporting event details |
| `status` | Open, investigating, resolved |
| `created_at` | Alert time |
| `incident_key` | Grouping key used to avoid duplicates (Step 4.10) |
| `first_seen` / `last_seen` | First and latest evidence time |
| `event_count` | Number of events grouped into the alert |
| `updated_at` / `updated_by` | Who last changed the alert and when |
| `resolved_at` | Used for "time to resolve" analytics |

Example:

``` json
{
  "alert_type": "BRUTE_FORCE",
  "severity": "HIGH",
  "risk_score": 75,
  "description": "Repeated failed login attempts detected",
  "evidence": {"failed_attempts": 5, "window_minutes": 5},
  "status": "OPEN"
}
```

**Check:** Run the detector and verify that it creates one alert with a
clear explanation and supporting evidence.

## Step 4.10 — Prevent duplicate alerts

**What this step does:** Stops the detector from creating a new alert
for every event in the same ongoing incident.

**Why we do it:** A single attack may generate hundreds of failed-login
events.

**Why it matters:** Administrators need a manageable incident list, not
hundreds of duplicate alerts.

Use an incident grouping key, such as alert type, target account, source
IP, and time window. Update an existing incident when new evidence
belongs to it.

**Check:** Generate a large number of events for one incident and
confirm that they are grouped appropriately.

## Step 4.11 — Add tests for detection rules

**What this step does:** Automatically tests each detection rule with
expected event patterns.

**Why we do it:** A small change to one threshold can accidentally break
another rule.

**Why it matters:** Detection must be predictable and explainable if you
want to trust its alerts.

Test cases should include:

-   Normal successful login.
-   A few ordinary failed attempts.
-   Brute-force threshold reached.
-   Many accounts targeted from one IP.
-   MFA failures.
-   Distributed attempts.
-   Successful login after a failure burst.
-   Events outside the configured time window.
-   Duplicate-event handling.
-   Missing or unknown user information.

**Check:** Run the detection tests and confirm that both positive and
negative cases behave correctly.

------------------------------------------------------------------------

# 8. Stage 5 — Add automated defensive responses

**Stage goal:** Allow AuthShield to respond to high-confidence threats
without blindly blocking legitimate users.

Estimated effort: 3–4 days.

## Step 5.1 — Add alert investigation workflow

**What this step does:** Allows an administrator to change an alert's
status.

**Why we do it:** An alert needs to be reviewed, investigated, and
eventually resolved.

**Why it matters:** This makes AuthShield useful as a small
security-monitoring platform rather than just a detection script.

Initial statuses:

-   Open.
-   Investigating.
-   Resolved.

Record who changed the status and when.

**Check:** An administrator can update an alert, while a normal user
cannot.

## Step 5.2 — Add application-level rate limiting

**What this step does:** Limits how frequently a client can call
sensitive endpoints.

**Why we do it:** Account lockout alone does not protect every route or
prevent all request floods.

**Why it matters:** Rate limiting reduces abusive request volume before
it overloads the application.

Apply suitable limits to:

-   Login.
-   MFA verification.
-   Registration.
-   Password-reset requests.
-   Recovery-code verification.

Add a basic Flask-Limiter setup earlier, in Stage 2, because login and MFA
need limits from the start. Flask-Limiter's default in-memory storage is
per process, which is fine for local development; use a shared backend
(for example Redis) if you run several workers.

Use configurable limits and consider account, source, and endpoint
context. Avoid relying on one IP-only rule for users behind shared
networks.

**Check:** Test requests above and below the configured limit.

## Step 5.3 — Connect Fail2Ban to the new event/logging flow

**What this step does:** Keeps Fail2Ban monitoring authentication
failures and blocking abusive source IPs through the firewall.

**Why we do it:** Your original P11 project already uses Fail2Ban and
iptables. They provide a network-level defense that complements
application-level detection.

**Why it matters:** Application lockout protects accounts, while a
firewall ban can stop repeated traffic from a source before it reaches
Flask.

Implementation tasks:

1.  Keep or define a clear authentication log format.
2.  Update the Fail2Ban filter if the log format changes.
3.  Configure the jail for the new application.
4.  Confirm that the correct port and firewall action are used.
5.  Test banning and unbanning in the local lab.
6.  Record the action as a security event when possible.

Lab cautions to check before relying on bans:

-   Fail2Ban ignores `127.0.0.1` by default (`ignoreip`). A Hydra test run
    from the same machine will not be banned unless you change this for
    the test, or you attack from a second machine or VM.
-   Traffic to Docker-published ports passes through the `DOCKER-USER`
    and forwarding chains, so a ban in the default `INPUT` chain may not
    block it. Set the jail's chain accordingly if you use Docker.
-   In WSL2, confirm that the Fail2Ban service and `iptables` actually
    work before you depend on them.

Remember: Fail2Ban is based on log patterns and source IPs. It does not
protect a stolen database from offline password cracking.

**Check:** Generate authorized failed-login traffic in your local lab
and inspect Fail2Ban status and firewall rules.

## Step 5.4 — Add cautious automated response

**What this step does:** Allows selected high-confidence detections to
trigger temporary defensive actions.

**Why we do it:** An administrator may not always be available to
respond immediately.

**Why it matters:** Fast, controlled responses can reduce the impact of
ongoing attacks.

Possible responses:

-   Increase rate limits for suspicious activity.
-   Temporarily restrict a source IP.
-   Require additional verification.
-   Notify an administrator.
-   Mark an account for review.

Do not automatically block every suspicious IP. Shared university,
office, and mobile networks can place many legitimate users behind one
public address.

Require an audit record for every response action. Provide a safe
unban/reversal mechanism and make the response policy configurable.

**Check:** Simulate a high-confidence event and verify the action, audit
record, and reversal process.

------------------------------------------------------------------------

# 9. Stage 6 — Build the React and Tailwind frontend

**Stage goal:** Create a modern interface for authentication,
monitoring, and security administration.

Estimated effort: 7–10 days.

## Step 6.1 — Create the React application

**What this step does:** Creates the frontend application using React
and TypeScript.

**Why we do it:** The original P11 project has a basic Flask interface.
AuthShield needs a more complete user and administrator experience.

**Why it matters:** A separate frontend makes the application easier to
use, demonstrate, and extend.

From the project root:

``` bash
# From the project root:
npm create vite@latest frontend -- --template react-ts
cd frontend

npm install
npm install react-router-dom axios recharts lucide-react
```

Install Node inside WSL2 (for example with nvm) rather than using the
Windows copy. Install `socket.io-client` when you reach Step 6.10, and
Vitest with React Testing Library for Step 7.2.

Install and configure Tailwind CSS. For Tailwind v4 with Vite:

``` bash
npm install tailwindcss @tailwindcss/vite
```

Add `@tailwindcss/vite` plugin to `vite.config.ts`:
``` ts
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
})
```

And in `src/index.css`, replace the contents with:
``` css
@import "tailwindcss";
```

Keep the frontend and backend in separate folders.

**Check:** Start the Vite development server and confirm that the
default React page loads.

## Step 6.2 — Create the frontend structure

**What this step does:** Organizes pages, reusable components, API
calls, and shared types.

**Why we do it:** A dashboard can become difficult to maintain if all UI
code is placed inside one component.

**Why it matters:** Reusable components make it easier to add pages and
keep the design consistent.

Suggested structure:

``` text
frontend/src/
├── components/
│   ├── layout/
│   ├── cards/
│   ├── charts/
│   └── tables/
├── pages/
│   ├── Login.tsx
│   ├── Register.tsx
│   ├── AccountSecurity.tsx
│   ├── Overview.tsx
│   ├── LiveMonitoring.tsx
│   ├── Alerts.tsx
│   ├── IPAnalysis.tsx
│   ├── UserSecurity.tsx
│   ├── Analytics.tsx
│   ├── AuditLogs.tsx
│   └── Settings.tsx
├── services/
│   └── api.ts
├── hooks/
├── layouts/
├── types/
└── App.tsx
```

**Check:** Create the routes and confirm that each page opens.

## Step 6.3 — Build login and registration pages

**What this step does:** Gives users a frontend for registering and
signing in.

**Why we do it:** Users should interact with the new Flask
authentication API through a normal web interface.

**Why it matters:** It connects the authentication work to the actual
product experience.

Build:

-   Registration form.
-   Login form.
-   MFA verification screen.
-   Password-reset request screen.
-   Reset-password screen.
-   Recovery-code flow.
-   Account-security page: MFA setup with QR code, recovery-code
    display, change password, and a list of the user's own sessions
    with a revoke button.

Use client-side validation for usability, but always validate again in
Flask.

**Check:** Register and log in through the frontend, including MFA.

## Step 6.4 — Build the dashboard overview

**What this step does:** Displays the most important security
information in one place.

**Why we do it:** Administrators need a quick view of the current
security situation.

**Why it matters:** A dashboard makes it easier to identify unusual
activity without manually reading logs.

Suggested metrics:

-   Registered users.
-   Successful logins.
-   Failed logins.
-   Active sessions.
-   MFA-enabled users.
-   Open security alerts.
-   Blocked IP addresses.
-   Most targeted accounts.
-   Most active suspicious source IPs.

Use Recharts for graphs and tables for recent activity.

**Check:** The dashboard should display actual API data, not hardcoded
sample numbers.

## Step 6.5 — Build the live-monitoring page

**What this step does:** Displays recent security events as they arrive.

**Why we do it:** Administrators need to see activity while an attack
simulation is running.

**Why it matters:** It makes your threat-detection demonstration much
clearer.

Start with REST API polling. Once it works reliably, add Flask-SocketIO
for live updates.

Display:

-   Event type.
-   Timestamp.
-   Username or account identifier.
-   Source IP.
-   Success or failure.
-   Related alert, if any.

**Check:** Trigger a test login failure and confirm that it appears on
the page.

## Step 6.6 — Build the threat-alert page

**What this step does:** Displays detected incidents and allows
administrators to investigate them.

**Why we do it:** The detector needs a clear place to show its findings.

**Why it matters:** The alert page is the main user-facing part of the
threat-detection feature.

Display:

-   Alert type.
-   Severity.
-   Risk score.
-   Source IP.
-   Target account.
-   Time detected.
-   Explanation.
-   Supporting evidence.
-   Current status.

Add filters for severity, alert type, status, and date.

**Check:** Trigger a brute-force test and confirm that the alert appears
with its explanation.

## Step 6.7 — Build IP analysis

**What this step does:** Shows authentication activity grouped by source
IP.

**Why we do it:** Security administrators need to understand which
sources are producing suspicious activity.

**Why it matters:** It helps investigate repeated attempts and
distributed behavior.

Display:

-   IP address.
-   Number of failed attempts.
-   Number of targeted accounts.
-   Most recent activity.
-   Related alerts.
-   Whether a configured block is active.

Do not claim that an IP's geographic location or identity is known
unless you have a reliable data source for it.

**Check:** Filter events by a test IP and compare the result with the
database.

## Step 6.8 — Build user-security management

**What this step does:** Gives administrators a view of account security
status.

**Why we do it:** Administrators need to identify accounts with repeated
failures, lockouts, or missing MFA.

**Why it matters:** It helps them investigate account-related security
problems.

Display:

-   Username.
-   Role.
-   MFA status.
-   Account status.
-   Active sessions.
-   Recent security events.

Protect all administrative actions with backend authorization and audit
logging.

**Check:** Confirm that normal users cannot access the administrator's
user-management APIs.

## Step 6.9 — Build analytics and audit-log pages

**What this step does:** Shows historical trends and searchable security
activity.

**Why we do it:** One alert tells you about one incident. Historical
analytics help reveal patterns over time.

**Why it matters:** You can evaluate whether security is improving and
explain your experimental results.

Suggested charts:

-   Failed logins over time.
-   Successful versus failed logins.
-   Alert severity distribution.
-   Most common alert types.
-   Top targeted accounts.
-   Alert response time.

The audit-log page should allow authorized administrators to search and
filter records.

**Check:** Compare chart totals with direct database queries to ensure
that the frontend is displaying correct data.

## Step 6.10 — Add real-time updates

**What this step does:** Sends new events and alerts to the frontend
without requiring a manual page refresh.

**Why we do it:** A live monitoring screen is more useful when it
updates as activity happens.

**Why it matters:** During your demonstration, you can run a controlled
attack simulation and show the detection process immediately.

Use Flask-SocketIO after the REST API is stable.

Implementation tasks:

1.  Configure authenticated WebSocket connections.
2.  Ensure users receive only data they are authorized to view.
3.  Publish an update when a new event or alert is created.
4.  Handle reconnects and missed updates.
5.  Keep REST endpoints available as a fallback.

**Check:** Trigger an event and verify that the monitoring page updates
without a reload.

------------------------------------------------------------------------

# 10. Stage 7 — Testing, security hardening, and deployment

**Stage goal:** Make AuthShield reliable, safer, and easy for another
person to run.

Estimated effort: 5–7 days.

## Step 7.1 — Add backend automated tests

**What this step does:** Tests Flask routes, authentication logic,
database operations, and detection rules.

**Why we do it:** Manual testing is not enough when the application has
many security features.

**Why it matters:** Automated tests help prevent old bugs from returning
when you add new features.

Use pytest.

Test:

-   Registration.
-   Correct and incorrect login.
-   Argon2id hash verification.
-   Bcrypt-to-Argon2id migration.
-   MFA enrollment and verification.
-   Lockout behavior.
-   Session creation and revocation.
-   Password reset expiry and reuse.
-   Role-based permissions.
-   Event creation.
-   Every detection rule.
-   Alert creation and updates.

Use a separate test database and synthetic accounts.

**Check:** Run the full test suite and confirm that it passes.

## Step 7.2 — Add frontend tests

**What this step does:** Tests important React components and user
flows.

**Why we do it:** A backend may work correctly while the frontend still
displays wrong information or sends incorrect requests.

**Why it matters:** The complete application needs to work, not only the
API.

Test:

-   Login form validation.
-   MFA form behavior.
-   Dashboard loading and error states.
-   Alert filtering.
-   Alert status updates.
-   Role-based page visibility.

Remember that hiding an admin button in React is not security. The Flask
backend must still enforce permissions.

**Check:** Run frontend tests and manually complete the main login and
dashboard flow.

## Step 7.3 — Add security hardening

**What this step does:** Adds protections around the application and its
API.

**Why we do it:** A secure password system can still be vulnerable
through unsafe sessions, cross-site scripting, CSRF, or exposed secrets.

**Why it matters:** Authentication security depends on the whole
application, not only password hashing.

Implement and verify:

-   HTTPS in deployed environments.
-   Flask debug mode disabled outside local development.
-   Strong random secret keys.
-   Secure, HTTP-only, appropriately configured cookies.
-   CSRF protection for cookie-authenticated state-changing requests.
-   Security headers and a suitable Content Security Policy.
-   Input validation.
-   Parameterized database access.
-   Generic login error messages.
-   Rate limits for sensitive endpoints.
-   Safe error responses that do not expose stack traces.
-   Dependency updates and secret management.
-   Audit logs for administrator actions.

Use Jinja autoescaping for any remaining server-rendered pages. Do not
insert usernames directly into HTML strings.

**Check:** Review the application configuration and run security tests
against your local deployment.

## Step 7.4 — Test with OWASP ZAP

**What this step does:** Scans the application for common web security
problems.

**Why we do it:** Authentication testing alone does not cover every web
vulnerability.

**Why it matters:** A web application can have problems such as missing
security headers, unsafe cookies, or injection weaknesses even when its
login system is strong.

Run scans only against your own local or explicitly authorized test
deployment.

Review findings manually. A scanner warning is not automatically proof
of a vulnerability.

**Check:** Save the scan report and document which findings were fixed,
accepted, or not applicable.

## Step 7.5 — Test attacks against the new defenses

**What this step does:** Repeats controlled security tests against the
new AuthShield application.

**Why we do it:** The original P11 project compares attacks against weak
and hardened applications. AuthShield should continue that experimental
approach.

**Why it matters:** You need evidence that the new defenses actually
work.

Test in your isolated lab:

-   Repeated login failures.
-   Controlled brute-force attempts.
-   Attempts across multiple test accounts.
-   MFA guessing limits.
-   Account lockout and recovery.
-   Session revocation.
-   Password reset token reuse.
-   Unauthorized access to admin endpoints.
-   Fail2Ban and firewall behavior.

Use only dummy accounts and systems you own or have permission to test.

**Check:** Save logs, screenshots, and test results.

## Step 7.6 — Add Docker Compose

**What this step does:** Makes it easier to run the frontend, backend,
and PostgreSQL together.

**Why we do it:** Manually starting several services becomes
inconvenient as the project grows.

**Why it matters:** Docker Compose gives another developer a repeatable
local setup.

Initial services:

-   `frontend` (React + Vite)
-   `backend` (Flask API)
-   `db` (Optional: when using Neon cloud PostgreSQL, the database is hosted externally in the cloud. Keep a local PostgreSQL container here only if providing a 100% offline fallback)

Add Nginx later if you need a reverse proxy.

Do not put production secrets directly in the Compose file. Use
environment configuration and appropriate secret handling.

**Check:** Start the stack from a clean environment and verify that all
services communicate.

## Step 7.7 — Write the final README and project documentation

**What this step does:** Explains how AuthShield works and how another
person can run it.

**Why we do it:** A project is difficult to evaluate if the reviewer
cannot understand its architecture or reproduce its behavior.

**Why it matters:** Clear documentation improves the quality of your
GitHub portfolio and your project presentation.

Include:

1.  Project overview.
2.  Features.
3.  Architecture diagram.
4.  Technology stack.
5.  Folder structure.
6.  Environment setup.
7.  Database setup.
8.  Backend startup.
9.  Frontend startup.
10. Test commands.
11. Security design.
12. Threat-detection rules.
13. Known limitations.
14. Screenshots.
15. Local-lab testing boundary.

**Check:** Follow your own README from a clean environment.

------------------------------------------------------------------------

# 11. Backend API plan

These are the suggested initial REST API endpoints. Implement them
gradually; they do not all need to exist at the beginning.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `POST` | `/api/auth/register` | Register a user |
| `POST` | `/api/auth/login` | Verify password |
| `POST` | `/api/auth/verify-mfa` | Verify TOTP |
| `POST` | `/api/auth/recovery` | Log in with a recovery code |
| `GET` | `/api/auth/csrf` | Get a CSRF token |
| `GET` | `/api/auth/me` | Get the signed-in user |
| `POST` | `/api/auth/change-password` | Change password |
| `POST` | `/api/auth/mfa/setup` | Start MFA enrollment (QR code) |
| `POST` | `/api/auth/mfa/enable` | Confirm a code and enable MFA |
| `POST` | `/api/auth/mfa/disable` | Disable MFA after reauthentication |
| `POST` | `/api/auth/logout` | End the current session |
| `POST` | `/api/auth/forgot-password` | Request password reset |
| `POST` | `/api/auth/reset-password` | Complete password reset |
| `GET` | `/api/auth/sessions` | List the current user's sessions |
| `DELETE` | `/api/auth/sessions/:id` | Revoke one of the current user's sessions |
| `GET` | `/api/health` | Backend and database readiness |
| `GET` | `/api/dashboard/summary` | Get dashboard metrics |
| `GET` | `/api/events` | Search security events |
| `GET` | `/api/alerts` | List alerts |
| `PATCH` | `/api/alerts/:id` | Update alert status |
| `GET` | `/api/analytics/login-trends` | Get login trends |
| `GET` | `/api/analytics/top-threats` | Get threat analytics |
| `GET` | `/api/ips` | IP analysis (admin only) |
| `GET` | `/api/users` | User-security overview (admin only) |
| `GET` | `/api/audit-logs` | Search audit logs (admin only) |
| `POST` | `/api/blocks` | Block an IP (admin only) |
| `DELETE` | `/api/blocks/:id` | Unblock an IP (admin only) |

## API security requirements

-   Check authentication on protected endpoints.
-   Check the user's role on administrator endpoints.
-   Validate all input.
-   Use pagination for event and alert lists.
-   Avoid returning sensitive internal fields.
-   Use CSRF protection when using cookie-based browser authentication.
-   Record important administrator actions.
-   Return consistent error responses.

------------------------------------------------------------------------

# 12. PostgreSQL database plan

Start with these tables and add fields as the application develops.

| Table | Main purpose |
| --- | --- |
| `users` | User accounts, password hashes, roles, MFA state |
| `security_events` | Authentication and security activity |
| `security_alerts` | Detected incidents and their status |
| `user_sessions` | Active and revoked sessions |
| `password_reset_tokens` | Hashed, expiring reset-token records |
| `recovery_codes` | Hashed one-time recovery codes |
| `audit_logs` | Administrative and security-sensitive actions |
| `blocked_ips` | Automated and manual IP restrictions: who, when, why, expiry, and reversal |
| `alert_status_history` | Who changed each alert's status, and when |

## Important database rules

1.  Use database migrations (Flask-Migrate / Alembic).
2.  Add indexes for frequently searched event fields (`event_type`, `user_id`, `source_ip`, `timestamp`).
3.  Use UTC timestamps.
4.  Never store plaintext passwords or reset tokens.
5.  Protect MFA secrets (encrypt at rest).
6.  Restrict database access: never commit Neon credentials to Git.
7.  Keep the original SQLite P11 database separate.
8.  Do not name a model attribute `metadata` (reserved by SQLAlchemy Declarative API).

## Neon Serverless cloud configuration tips

-   **SSL Enforcement:** Neon strictly requires encrypted connections; ensure `?sslmode=require` is appended to `DATABASE_URL`.
-   **Connection Pooling:** Neon provides a pooled connection endpoint (host ending with `-pooler`). Using the pooled endpoint prevents exhausting serverless connections when running multi-threaded Flask workers.
-   **Branching for Testing:** Create a separate `test` branch in the Neon web console for running `pytest` test suites so unit/integration tests do not wipe or clutter development data.

------------------------------------------------------------------------

# 13. Recommended project folder structure

This is the target structure of the repository. It is a guide, not a
requirement to create every file on the first day.

``` text
AuthShield/
│
├── legacy/                       # Isolated P11 Coursework Demonstration Lab
│   ├── app_v1_weak.py            # Phase 1 weak MD5 login app
│   ├── app_v2_hardened.py        # Phase 3 hardened bcrypt/Argon2 + lockout + TOTP app
│   └── database/                 # SQLite coursework database
│       ├── users.db              # Active SQLite DB for legacy lab
│       ├── schemas/              # Schema initializers (init_db_v1.py, init_db_v2.py)
│       ├── seeds/                # Dummy users seed script (seed_users.py)
│       └── backups/              # Baseline snapshot (users_phase1_weak.db.bak)
│
├── backend/                      # AuthShield 2.0 Flask REST API & Threat Engine (Stage 1+)
│   ├── app/
│   │   ├── __init__.py           # Application factory
│   │   ├── config.py             # Config classes
│   │   ├── extensions.py         # SQLAlchemy, Migrate, Limiter, etc.
│   │   │
│   │   ├── auth/                 # Authentication & authorization module
│   │   │   ├── routes.py
│   │   │   ├── password.py
│   │   │   ├── mfa.py
│   │   │   └── sessions.py
│   │   │
│   │   ├── detection/            # Threat detection & risk scoring engine
│   │   │   ├── event_types.py
│   │   │   ├── event_collector.py
│   │   │   ├── event_repository.py
│   │   │   ├── rules.py
│   │   │   ├── risk_engine.py
│   │   │   ├── detector.py
│   │   │   └── alert_manager.py
│   │   │
│   │   ├── alerts/               # Alert management endpoints
│   │   │   └── routes.py
│   │   │
│   │   ├── dashboard/            # Dashboard analytics endpoints
│   │   │   └── routes.py
│   │   │
│   │   └── models/               # PostgreSQL models (Neon Serverless)
│   │       ├── user.py
│   │       ├── security_event.py
│   │       ├── alert.py
│   │       └── session.py
│   │
│   ├── migrations/               # Alembic database migrations
│   ├── tests/                    # Pytest automated test suites
│   ├── requirements.txt          # Backend dependencies
│   └── run.py                    # Server entry point
│
├── frontend/                     # AuthShield 2.0 React + TypeScript + Tailwind UI (Stage 4+)
│   ├── src/
│   │   ├── components/           # UI components
│   │   ├── pages/                # Views (Login, Dashboard, Alerts, Sessions, Analytics)
│   │   ├── layouts/              # Main layout & navigation
│   │   ├── hooks/                # Custom React hooks
│   │   ├── services/             # API client & WebSocket connections
│   │   ├── types/                # TypeScript interfaces
│   │   └── App.tsx
│   └── package.json
│
├── docs/                         # Coursework specifications, rubrics & guides
│   ├── Guide.md                  # Comprehensive P11 lab guide
│   ├── Note.md                   # Lab notes
│   ├── Topic.md                  # Assignment topic description
│   ├── work_factor_comparison.md # Hashing work-factor comparison analysis
│   ├── Evalution_metric.pdf      # Course evaluation criteria
│   ├── Project_proposal.pdf      # Original project proposal
│   ├── packages.txt              # Apt package dependencies
│   └── setup.txt                 # Tool installation notes
│
├── scripts/                      # Lab utility scripts
│   ├── benchmark_hashing.py      # Multi-algorithm hashing benchmark tool
│   └── dump_hashes.py            # SQLite user hash export utility
│
├── hashes/                       # Exported hash dumps for offline cracking
│   ├── md5_hashes.txt            # Unsalted MD5 user hashes
│   ├── bcrypt_hashes.txt         # Bcrypt hashes for cracking experiments
│   └── bcrypt_r10_only.txt / bcrypt_r12_only.txt
│
├── results/                      # Experiment outcome summaries & benchmark data
│   ├── benchmark_hashing.txt
│   ├── cracked_hashcat.txt
│   ├── cracked_hydra_weak.txt
│   └── cracked_john.txt
│
├── Terminal_crack_result/        # Raw terminal logs from offline/online cracking
│   ├── hashcat.txt
│   ├── hydra_weak.txt
│   └── john_the_ripper.txt
│
├── Terminal_defence_result/      # Raw terminal logs from defense verifications
│   ├── bcrypt_benchmark.txt
│   └── hydra_hardened.txt
│
├── wordlists/                    # Dictionaries for password cracking tests
│   └── rockyou.txt
│
├── logs/                         # Runtime log directory
│   └── auth.log                  # Fail2Ban-monitored authentication log
│
├── docker-compose.yml
├── .gitignore
├── README.md
├── requirements.txt
├── setup.sh
└── AuthShield_2.md
```

------------------------------------------------------------------------

# 14. Suggested development schedule

The following is a suggested sequence, not a fixed deadline. You can
spread it over more weeks depending on your available time.

| Stage | Main work | Estimated effort |
| --- | --- | --- |
| 0 | Preserve and organize P11 | 1–2 days |
| 1 | Flask backend and PostgreSQL | 3–5 days |
| 2 | Authentication upgrade | 5–7 days |
| 3 | Security-event collection | 3–4 days |
| 4 | Threat-detection engine | 5–7 days |
| 5 | Automated response | 3–4 days |
| 6 | React and Tailwind dashboard | 7–10 days |
| 7 | Testing, hardening, deployment, documentation | 5–7 days |

## Recommended order

Do not build the frontend first.

Build in this order:

1.  Database and backend.
2.  Authentication.
3.  Event collection.
4.  Detection rules.
5.  Alert storage.
6.  REST API.
7.  React dashboard.
8.  Real-time updates.
9.  Testing and deployment.

This order prevents you from building a dashboard that only displays
hardcoded or fake data.

------------------------------------------------------------------------

# 15. Final project acceptance checklist

Use this checklist to decide whether AuthShield 2.0 is complete.

## Original P11 preserved

-   [ ] Original weak MD5 application still works in the isolated lab.
-   [ ] Original hardened bcrypt/TOTP application is preserved.
-   [ ] John and Hashcat benchmark evidence is preserved.
-   [ ] Hydra weak-versus-hardened test evidence is preserved.
-   [ ] Fail2Ban and iptables demonstration remains reproducible.
-   [ ] Original SQLite database and wordlists are backed up (and not committed to Git).
-   [ ] New Argon2id benchmark results are saved next to the old MD5/bcrypt results.

## Authentication

-   [ ] New accounts use Argon2id.
-   [ ] Existing bcrypt hashes can be verified and upgraded.
-   [ ] Password strength is checked.
-   [ ] TOTP enrollment and verification work.
-   [ ] Recovery codes are one-time use.
-   [ ] A used TOTP code cannot be replayed.
-   [ ] The admin role cannot be set through registration.
-   [ ] A password reset does not bypass MFA.
-   [ ] Sessions can be listed and revoked.
-   [ ] Password reset tokens expire and cannot be reused.
-   [ ] User and admin permissions are enforced by Flask.

## Detection

-   [ ] Authentication events are stored in PostgreSQL.
-   [ ] Brute-force detection works.
-   [ ] Credential-stuffing indicators work.
-   [ ] Password-spraying indicators are tested.
-   [ ] MFA-failure detection works.
-   [ ] Suspicious-success detection works.
-   [ ] Distributed-attempt detection works.
-   [ ] Risk scores have explanations.
-   [ ] Duplicate incidents are grouped.
-   [ ] Attempts against non-existent usernames are counted.
-   [ ] Risk-score bands match rule severities (brute force alone reaches High).
-   [ ] Detection rules have automated tests.

## Dashboard

-   [ ] Login and registration pages work.
-   [ ] Dashboard metrics use real API data.
-   [ ] Live monitoring displays events.
-   [ ] Alerts can be filtered and investigated.
-   [ ] IP analysis displays event history.
-   [ ] User-security management is admin-only.
-   [ ] Analytics match database results.
-   [ ] Real-time updates work if enabled.

## Security and delivery

-   [ ] Debug mode is disabled outside development.
-   [ ] The Fail2Ban filter matches the log format used by the new application.
-   [ ] Secrets are not committed to Git.
-   [ ] HTTPS is configured for deployment.
-   [ ] Secure cookies and CSRF protection are configured.
-   [ ] Backend and frontend tests pass.
-   [ ] OWASP ZAP findings are reviewed.
-   [ ] Docker Compose setup works if included.
-   [ ] README instructions work from a clean environment.
-   [ ] All attack demonstrations are limited to authorized systems.

------------------------------------------------------------------------

# 16. What makes AuthShield 2.0 stand out?

Focus your project presentation on these three points.

## 1. Explainable threat detection

Do not only show a red "High Risk" label.

Show a clear explanation:

> High-risk brute-force activity detected. Repeated failed login
> attempts were recorded against several accounts from the same source
> within a short period.

The administrator should be able to inspect the evidence behind the
alert.

## 2. Multiple layers of security

Demonstrate which defense protects against which attack:

| Defense | What it protects against |
| --- | --- |
| Argon2id | Offline password guessing after a hash leak |
| TOTP MFA | Access using a stolen password alone |
| Account lockout and rate limiting | Repeated online login attempts |
| Fail2Ban and iptables | Repeated abusive network traffic from a source |
| Session revocation | Continued use of a revoked or compromised session |
| Detection engine | Suspicious patterns across accounts, IPs, and time |

No single defense solves every problem. The strength of AuthShield is
combining multiple defenses and showing their results.

## 3. Security analytics

Show trends such as:

-   Failed-login spikes.
-   Frequently targeted accounts.
-   Common alert types.
-   Suspicious source activity.
-   Open versus resolved incidents.
-   Time taken to investigate and resolve alerts.

This makes the project more than a login system.

------------------------------------------------------------------------

# 17. Important limitations to evaluate

A good security project should explain what it cannot fully prevent.

| Risk or limitation | What to explain |
| --- | --- |
| Account-lockout denial of service | An attacker may intentionally cause a legitimate account to be locked |
| Shared IP false positives | A university or office network may have many users behind one public IP |
| Distributed attacks | Attackers can spread attempts across many addresses |
| TOTP clock differences | Device/server clock mismatch can reject valid codes |
| Offline hash theft | Lockout and firewalls cannot protect a stolen password database |
| HTTP without TLS | Credentials and session traffic may be exposed in transit |
| Detection false positives | Normal mistakes may look suspicious |
| Detection false negatives | An attacker may avoid configured thresholds |
| Incomplete IP attribution | An IP address does not reliably identify a person |

Record false positives and false negatives from your test runs. Do not
claim that AuthShield detects every attack.

------------------------------------------------------------------------

# 18. Recommended first milestone

Your first major milestone should be:

**Flask + Neon PostgreSQL + Argon2id authentication + structured security
events + brute-force detection.**

When this milestone works, you will have the most important backend
foundation for the rest of the project.

Your first practical tasks are:

1.  Back up and preserve P11.
2.  Create the `authshield-v2` Git branch.
3.  Create the backend folder and Python virtual environment.
4.  Create and connect the Neon PostgreSQL database.
5.  Create the Flask application factory.
6.  Create the user and security-event models.
7.  Implement Argon2id with bcrypt migration support.
8.  Connect login events to the event collector.
9.  Implement and test the brute-force detection rule.

Only after those tasks work should you spend significant time building
the React dashboard.

------------------------------------------------------------------------

## Final recommendation

Build AuthShield 2.0 gradually. Keep the original P11 work as your
experimental baseline, and build the new application as a separate,
organized system.

The most valuable feature is not the dashboard itself. It is the
complete flow:

**Authentication activity → Security event → Detection rule → Risk score
→ Alert → Administrator investigation → Defensive response.**

If you can demonstrate that flow clearly with real test data, AuthShield
2.0 will be a much stronger and more complete project.
