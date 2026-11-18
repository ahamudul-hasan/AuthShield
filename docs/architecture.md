# AuthShield 2.0 — Architecture & System Design

**Project:** AuthShield 2.0 (Security Event Detection & Threat-Monitoring Platform)  
**Origin:** P11 Authentication & Password Security Coursework  
**Stack:** React + TypeScript + Tailwind CSS | Python + Flask | PostgreSQL (Neon Cloud) | Fail2Ban  

---

## 1. Executive Summary

AuthShield 2.0 evolves a standalone academic password-security lab (P11) into a full-featured, production-ready **authentication security and active threat-monitoring platform**.

Traditional authentication systems only answer binary questions: *"Did the login succeed or fail?"*  
**AuthShield 2.0 answers:**
* *Who* is attempting authentication, from *where*, and with *what patterns*?
* Is this an isolated typographical error, or an automated credential stuffing attack?
* What is the calculated risk score based on historical and cross-account behavior?
* What defensive action should be taken (rate-limiting, session revocation, automated firewall IP bans)?

---

## 2. High-Level System Architecture

The system is organized into decoupled layers: a client user interface, a Python Flask REST/WebSocket application, persistent serverless PostgreSQL storage on Neon Cloud, local host-level defense daemons, and an isolated legacy lab.

```mermaid
flowchart TD
    subgraph ClientLayer["1. Client Layer (Browser)"]
        UI["React + TypeScript + Tailwind SPA"]
        UserPortal["User Portal\n(Login, MFA, Session Manager)"]
        AdminDashboard["Admin Threat Dashboard\n(Live Alert Feed, Risk Gauges, Analytics)"]
        UI --> UserPortal
        UI --> AdminDashboard
    end

    subgraph APILayer["2. API & Communication Gateway"]
        HTTPS["HTTPS REST API\n(JSON Endpoints)"]
        WS["WebSocket Gateway\n(Socket.IO Live Streaming)"]
    end

    subgraph BackendLayer["3. AuthShield Backend (Flask)"]
        direction TB
        AppFactory["Flask Application Factory (create_app)"]
        
        subgraph AuthCore["Authentication Engine"]
            Argon2["Argon2id Hasher\n(t=2, m=19MB, p=1)"]
            BcryptMigrate["Bcrypt Migration Adapter\n(Auto-rehash on login)"]
            TOTPEngine["TOTP MFA Engine\n(PyOTP + Replay Window Check)"]
            SessionMgr["Opaque Session Manager\n(HttpOnly Cookie + SHA-256 DB Hash)"]
        end

        subgraph DetectionCore["Threat Detection Engine"]
            Collector["Event Collector\n(Structured Context Capture)"]
            RuleEngine["Sliding Window Rule Evaluator\n(Brute-force, Stuffing, Spraying)"]
            RiskEngine["Risk Scoring Calculator\n(0 - 100 Anomaly Score)"]
            AlertMgr["Alert & Incident Manager\n(Triage, Status, Evidence)"]
        end

        AppFactory --> AuthCore
        AppFactory --> DetectionCore
    end

    subgraph StorageLayer["4. Data & Persistence Layer"]
        NeonDB[("Neon Serverless PostgreSQL\n(Users, Sessions, Events, Alerts, Audit)")]
        LocalLog["Local Disk: logs/auth.log\n(Fail2Ban-Compatible Format)"]
    end

    subgraph HostDefense["5. Host Defense (WSL2 / Linux)"]
        Fail2Ban["Fail2Ban Daemon"]
        IPTables["Linux iptables / Netfilter Firewall"]
        Fail2Ban -->|Monitors log| LocalLog
        Fail2Ban -->|Drops malicious IPs| IPTables
    end

    subgraph LegacyLab["6. Isolated Demonstration Lab (Coursework)"]
        WeakApp["Phase 1: app_v1_weak.py\n(Unsalted MD5)"]
        HardenedApp["Phase 3: app_v2_hardened.py\n(Legacy Bcrypt)"]
        SQLiteDB[("legacy/database/users.db\n(Coursework SQLite)")]
        WeakApp --> SQLiteDB
        HardenedApp --> SQLiteDB
    end

    %% Interactions
    ClientLayer -->|HTTPS REST| HTTPS
    ClientLayer <-->|Bi-directional Events| WS
    HTTPS --> AppFactory
    WS <--> AppFactory
    
    AuthCore -->|Reads / Writes Users & Sessions| NeonDB
    Collector -->|Dual Write: Database| NeonDB
    Collector -->|Dual Write: Text Log| LocalLog
    DetectionCore -->|Queries Sliding Windows & Saves Alerts| NeonDB
    DetectionCore -.->|Broadcasts New Alerts| WS
```

---

## 3. Subsystem Breakdown & Component Responsibilities

| Subsystem | Primary Responsibilities | Technologies |
| :--- | :--- | :--- |
| **Frontend UI** | Renders login flows, TOTP setup QR codes, session management, real-time alert streams, and analytics charts. Never makes security or authorization decisions. | React 19, TypeScript, Vite, Tailwind CSS, Recharts, Lucide Icons |
| **Flask API Backend** | Handles request validation, password hashing, session lifecycle, error formatting, RBAC checks, and rate-limiting. | Python 3, Flask, Flask-SQLAlchemy, Flask-CORS, Flask-Limiter |
| **Authentication Module** | Enforces password complexity, hashes with Argon2id, verifies and migrates legacy bcrypt hashes, validates TOTP tokens with replay prevention. | `argon2-cffi`, `bcrypt`, `pyotp`, `qrcode`, `cryptography` |
| **Security Event Collector** | Intercepts all authentication actions and extracts structured metadata (IP address, User-Agent, endpoint, outcome, user ID). Performs dual-write to Neon DB and `logs/auth.log`. | Python, SQLAlchemy, Standard Library Logging |
| **Threat-Detection Engine** | Runs sliding-window detection rules across ingested events to flag brute-force attacks, multi-account stuffing, password spraying, and compromised sessions. | In-memory evaluation + PostgreSQL aggregation queries |
| **Risk & Alert Manager** | Calculates risk scores (0–100), assigns severity tiers (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), packages evidence payloads, and manages alert triage states (`OPEN`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`). | PostgreSQL JSONB / Alembic migrations |
| **Persistence (Cloud)** | Serverless, autoscaling PostgreSQL hosting relational tables with connection pooling. | Neon Serverless PostgreSQL, SQLAlchemy ORM, psycopg3 |
| **Network Defense** | Scans `logs/auth.log` for repeated failed authentication attempts from external attackers (e.g. THC-Hydra) and blocks their IP via Linux iptables. | Fail2Ban, iptables (WSL2/Linux) |
| **Legacy Lab** | Preserves original academic coursework demonstrations (MD5 cracking with John the Ripper and Hashcat) isolated inside `legacy/`. | Python Flask, SQLite 3 |

---

## 4. Authentication & Migration Workflow

The authentication flow enforces strong cryptography while transparently upgrading legacy accounts without forcing an immediate password reset.

```mermaid
flowchart TD
    Start(["User submits credentials:\nusername + password"]) --> FindUser{"User exists in\nNeon DB?"}
    
    FindUser -- No --> FakeHash["Run dummy Argon2id hash\n(Mitigates timing attacks)"]
    FakeHash --> RecordFailUnknown["Record LOGIN_FAILED event\n(user=unknown)"]
    RecordFailUnknown --> Ret401["Return 401 Unauthorized"]

    FindUser -- Yes --> CheckLockout{"Is account\nlocked out?\n(lockout_until > now)"}
    
    CheckLockout -- Yes --> RecordLocked["Record LOGIN_BLOCKED event"]
    RecordLocked --> Ret403["Return 403 Forbidden\n(Account temporarily locked)"]

    CheckLockout -- No --> DetectAlgo{"Identify Stored\nPassword Algorithm"}

    DetectAlgo -- "Argon2id ($argon2id$)" --> VerifyArgon2["Verify via Argon2id Hasher"]
    DetectAlgo -- "Legacy Bcrypt ($2b$, $2a$)" --> VerifyBcrypt["Verify via bcrypt.checkpw"]

    VerifyArgon2 --> AuthCheck{"Password\nMatch?"}
    VerifyBcrypt --> AuthCheck

    AuthCheck -- No --> IncrementFailures["Increment failed_attempts (+1)\nIf >= 5, set lockout_until (+15 min)"]
    IncrementFailures --> DualWriteFail["Dual-write failure:\n1. security_events table\n2. logs/auth.log"]
    DualWriteFail --> Ret401

    AuthCheck -- Yes --> CheckNeedsRehash{"Algorithm is bcrypt\nOR Argon2 parameters\noutdated?"}
    
    CheckNeedsRehash -- Yes --> AutoUpgrade["Re-hash password with Argon2id\nUpdate stored hash in DB\nSet algorithm = 'argon2id'"]
    CheckNeedsRehash -- No --> ResetFailures["Reset failed_attempts = 0\nClear lockout_until"]
    AutoUpgrade --> ResetFailures

    ResetFailures --> CheckMFA{"Is TOTP MFA\nenabled for user?"}

    CheckMFA -- Yes --> PendingMFA["Create short-lived pending MFA token\n(Do NOT issue full session)"]
    PendingMFA --> Ret200MFA["Return 200 OK\n('mfa_required': true)"]

    CheckMFA -- No --> IssueSession["Generate cryptographically random session ID\nStore SHA-256 hash in user_sessions table\nSet HttpOnly Secure cookie"]
    IssueSession --> RecordSuccess["Record LOGIN_SUCCESS event"]
    RecordSuccess --> Ret200["Return 200 OK with User Profile"]
```

---

## 5. Security Event Collection & Threat-Detection Pipeline

AuthShield does not treat logs as passive text dumps; it treats security events as structured data streams feeding an active detection engine.

```mermaid
sequenceDiagram
    autonumber
    actor Attacker as Attacker / Client
    participant API as Flask Auth Endpoint
    participant Collector as Security Event Collector
    participant DB as Neon PostgreSQL
    participant Log as logs/auth.log (Local Disk)
    participant F2B as Fail2Ban Daemon
    participant Detector as Threat-Detection Engine
    participant WS as WebSocket Hub
    actor Admin as Admin Dashboard

    Attacker->>API: POST /api/auth/login (Invalid credentials)
    API->>Collector: capture_event(LOGIN_FAILURE, user, ip, user_agent)
    
    par Dual Storage Write
        Collector->>DB: INSERT INTO security_events (event_type, ip, metadata, timestamp)
    and Host Defense Log Write
        Collector->>Log: Append standard auth.log line
    end

    Log-->>F2B: Fail2Ban detects repeated regex pattern
    opt Threshold Exceeded (e.g. 5 failed attempts)
        F2B->>Attacker: iptables DROP rule added for Source IP
    end

    Collector->>Detector: evaluate_rules(event)
    Note over Detector: Runs sliding-window analytics:<br/>1. Single-target Brute Force<br/>2. Multi-target Credential Stuffing<br/>3. Password Spraying<br/>4. Suspicious Geovelocity

    opt Threat Pattern Detected
        Detector->>DB: INSERT INTO alerts (severity, rule_name, risk_score, evidence)
        Detector->>WS: broadcast("NEW_ALERT", alert_payload)
        WS->>Admin: Live toast notification + audio alert
        Admin->>API: GET /api/alerts (Triage and review evidence)
    end

    API-->>Attacker: 401 Unauthorized (attempts remaining: 4)
```

---

## 6. Database Entity-Relationship (ER) Model

The Neon PostgreSQL schema separates account identity, cryptographic secrets, authentication state, and threat audit trails.

```mermaid
erDiagram
    USERS ||--o{ USER_SESSIONS : "has active"
    USERS ||--o{ SECURITY_EVENTS : "generates"
    USERS ||--o{ ALERTS : "targets / involves"
    USERS ||--o{ RECOVERY_CODES : "owns"
    USERS ||--o{ AUDIT_LOGS : "acts in"

    USERS {
        int id PK
        string username UK
        string email UK
        string password_hash
        string password_algorithm
        string role "user | admin"
        string totp_secret "Encrypted at rest"
        boolean mfa_enabled
        int failed_attempts
        timestamptz lockout_until
        timestamptz created_at
        timestamptz updated_at
        boolean is_active
        timestamptz last_login_at
        timestamptz password_changed_at
    }

    USER_SESSIONS {
        int id PK
        int user_id FK
        string session_token_hash UK "SHA-256 of cookie token"
        string ip_address
        string user_agent
        timestamptz created_at
        timestamptz expires_at
        timestamptz last_active_at
        boolean is_revoked
    }

    SECURITY_EVENTS {
        bigint id PK
        int user_id FK "Nullable for unknown users"
        string event_type "LOGIN_SUCCESS, LOGIN_FAILURE, etc."
        string username_attempted
        string ip_address
        string user_agent
        jsonb metadata "geo, headers, reasons"
        timestamptz created_at
    }

    ALERTS {
        int id PK
        string rule_name "BRUTE_FORCE, CREDENTIAL_STUFFING"
        string severity "LOW | MEDIUM | HIGH | CRITICAL"
        int risk_score "0 to 100"
        string status "OPEN | INVESTIGATING | RESOLVED | FALSE_POSITIVE"
        int target_user_id FK "Nullable"
        string source_ip
        jsonb evidence "Triggering event IDs, sample usernames"
        timestamptz created_at
        timestamptz updated_at
        int resolved_by_user_id FK
    }

    RECOVERY_CODES {
        int id PK
        int user_id FK
        string code_hash "Bcrypt or Argon2 hash of recovery token"
        boolean is_used
        timestamptz used_at
        timestamptz created_at
    }

    AUDIT_LOGS {
        bigint id PK
        int admin_user_id FK
        string action "ALERT_STATUS_UPDATE, USER_LOCKED, SESSION_KILLED"
        jsonb details
        timestamptz created_at
    }
```

---

## 7. Defense-in-Depth Layered Model

AuthShield 2.0 employs layered controls so that a failure or vulnerability at any single point is stopped by the surrounding defensive layers.

```mermaid
flowchart TD
    subgraph L1["Layer 1: Network & Firewall Layer"]
        L1_Desc["• Fail2Ban monitoring logs/auth.log\n• iptables IP blocking for automated brute-force attacks\n• Rate-limiting at the transport layer"]
    end

    subgraph L2["Layer 2: Transport & Edge HTTP Layer"]
        L2_Desc["• TLS 1.3 / HTTPS encryption in transit\n• Strict CORS origin whitelisting\n• Flask-Limiter endpoint rate limits\n• Flask-WTF CSRF protection on state-changing requests"]
    end

    subgraph L3["Layer 3: Application & Session Layer"]
        L3_Desc["• Role-Based Access Control (RBAC: user vs admin)\n• Opaque session IDs stored as SHA-256 hashes\n• HttpOnly, SameSite=Lax, Secure session cookies\n• Granular session listing and remote revocation\n• Automatic session termination on password reset"]
    end

    subgraph L4["Layer 4: Authentication & Cryptographic Layer"]
        L4_Desc["• Memory-hard Argon2id hashing (OWASP standard)\n• Automatic transparent migration from legacy bcrypt\n• TOTP Multi-Factor Authentication with anti-replay tracking\n• AES/Fernet encryption for TOTP secrets at rest\n• One-time hashed recovery codes"]
    end

    subgraph L5["Layer 5: Detection & Anomaly Monitoring Layer"]
        L5_Desc["• Structured event capture across all auth endpoints\n• Sliding-window rule detection engine\n• 0-100 risk scoring algorithm\n• Security alerts with evidence capture and incident triage\n• Real-time WebSocket streaming to Admin Dashboard"]
    end

    subgraph L6["Layer 6: Persistence & Cloud Data Layer"]
        L6_Desc["• Cloud-hosted serverless PostgreSQL on Neon\n• Connection pooling to prevent socket exhaustion\n• Database SSL mode required (sslmode=require)\n• Branching for isolated automated test runs"]
    end

    L1 --> L2
    L2 --> L3
    L3 --> L4
    L4 --> L5
    L5 --> L6
```

---

## 8. Legacy Coursework vs AuthShield 2.0 Isolation Boundary

To preserve the historical P11 coursework without compromising the new architecture, the codebase enforces an isolation boundary:

```mermaid
graph LR
    subgraph IsolatedLegacy["Isolated Legacy Lab (legacy/)"]
        direction TB
        V1["app_v1_weak.py\n(MD5, no lockout, no MFA)"]
        V2["app_v2_hardened.py\n(Bcrypt, 5 attempts, TOTP)"]
        OldDB[("legacy/database/users.db\n(SQLite)")]
        V1 --- OldDB
        V2 --- OldDB
        Tools["Attack Tools:\nJohn the Ripper\nHashcat\nTHC-Hydra"]
        Tools -->|Local offline/online attacks| V1
    end

    subgraph ModernAuthShield["AuthShield 2.0 (backend/ + frontend/)"]
        direction TB
        ReactApp["React 19 + TypeScript Dashboard"]
        FlaskBackend["Flask REST API + Socket.IO"]
        NeonPostgres[("Neon Serverless PostgreSQL")]
        Engine["Threat Detection & Risk Engine"]
        ReactApp --- FlaskBackend
        FlaskBackend --- NeonPostgres
        FlaskBackend --- Engine
    end

    Bridge[("Bridge: Bcrypt Migration Logic\n(Allows accounts created in legacy app to\nlog into AuthShield 2.0 and automatically upgrade to Argon2id)")]

    IsolatedLegacy -.->|Hash format compatibility| Bridge
    Bridge -.->|Upgraded credentials| ModernAuthShield

    style IsolatedLegacy fill:#ffe6e6,stroke:#cc0000,stroke-width:2px;
    style ModernAuthShield fill:#e6f3ff,stroke:#0066cc,stroke-width:2px;
    style Bridge fill:#e6ffe6,stroke:#009933,stroke-dasharray: 5 5;
```

---

## 9. Summary of Key Architectural Advantages

1. **Separation of Concerns:** React handles visual presentation and alert interaction; the Flask backend enforces all authentication, detection, and authorization logic.
2. **Resilience to Offline Attacks:** Storing credentials with memory-hard **Argon2id** (`m=19MB`, `t=2`) protects stolen databases against GPU-accelerated cracking clusters (Hashcat/John).
3. **Continuous Detection:** The platform detects attacks *as they happen* rather than post-mortem, alerting administrators to credential stuffing and password spraying within seconds.
4. **Zero-Downtime Migration:** Users from the earlier bcrypt coursework can log in immediately; their credentials are automatically re-hashed with Argon2id on their first successful authentication.
5. **Full Coursework Preservation:** All original Phase 1 (MD5) and Phase 2/3 (Bcrypt) attack demonstrations remain intact in `legacy/` for evaluation and academic review.
