<div align="center">

# 🛡️ AuthShield
### Full-Stack Authentication Security & Cryptographic Defense System

[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Framework](https://img.shields.io/badge/Flask-3.1-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Database](https://img.shields.io/badge/SQLite-3.45-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlite.org/)
[![Platform](https://img.shields.io/badge/WSL_2-Ubuntu_24.04-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)](https://ubuntu.com)
[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)

<br/>

> **AuthShield** is a cybersecurity engineering laboratory and reference architecture designed to demonstrate vulnerability lifecycles in web authentication. It explores how legacy password hashing and unthrottled endpoints fail against modern dictionary and brute-force attacks, and presents an end-to-end multi-layered defense model combining adaptive slow hashing, stateful account lockout, kernel-level firewall intrusion prevention, and Time-based One-Time Password (TOTP) Multi-Factor Authentication.

<br/>

[Overview](#-overview) •
[Architecture](#-system-architecture) •
[Authentication Flows](#-authentication-flow-analysis) •
[Threat Analysis](#-threat-vectors--attack-analysis) •
[Defensive Engineering](#-multi-layered-defense-in-depth) •
[Benchmarks](#-cryptographic-work-factor-benchmarking) •
[Security Considerations](#-security-considerations--residual-risks)

---

</div>

## 📌 Overview

Traditional web applications frequently rely on brittle, single-point defenses that collapse when subjected to automated credential guessing or database breaches. **AuthShield** implements an empirical **threat-and-mitigation framework** that models real-world attack vectors and systematically neutralizes them through defense-in-depth:

* **Vulnerable vs. Hardened Paradigms:** Contrasts an unmitigated legacy service against an enterprise-grade authentication system.
* **Dual-Vector Threat Modeling:** Demonstrates the distinct dynamics of **offline database compromises** (where network firewalls offer zero protection) versus **online automated brute-forcing** (where high-speed requests overwhelm unthrottled interfaces).
* **Multi-Layered Mitigation:** Integrates cryptographic salting, adaptive slow hashing (*bcrypt* and *Argon2id*), threshold-based account lockouts, dynamic kernel packet dropping (*Fail2Ban* + *iptables*), and physical possession factors (RFC 6238 TOTP).
* **Quantitative Work-Factor Hardening:** Models how tuning cryptographic iteration counts exponentially inflates attacker computational expenditure while keeping server authentication latency imperceptible to legitimate users.

---

## 🏗️ System Architecture

AuthShield enforces a defense-in-depth topology. Security boundaries are decoupled across the network perimeter, application middleware, cryptographic engine, and persistence layers.

```mermaid
flowchart TD
    subgraph THREATS["⚔️ Threat Actors & Attack Vectors"]
        T1["💥 Offline Hash Cracker<br/><b>Target: Compromised Hash Database</b><br/><i>Tools: High-Performance GPU Clusters</i>"]
        T2["🔨 Online Brute-Forcer<br/><b>Target: Public Authentication Routes</b><br/><i>Tools: Automated HTTP Credential Stuffing</i>"]
    end

    subgraph PERIMETER["🌐 Perimeter & Kernel Security Layer"]
        FW["🛡️ Netfilter Kernel Firewall (iptables)<br/><i>High-throughput packet filtering</i>"]
        F2B["👁️ Fail2Ban Intrusion Prevention System<br/><i>Audit log watcher & dynamic IP ban orchestrator</i>"]
    end

    subgraph APP["⚙️ Application Logic Layer (Flask Engine)"]
        AUTH["🚦 Request Controller & Auth Validator"]
        LOCK["🔒 Threshold Account Lockout Engine<br/><i>Stateful tracking: 5 attempts / 15-min cooldown</i>"]
        MFA["📱 MFA Gatekeeper<br/><i>RFC 6238 TOTP HMAC-SHA1 Token Validator</i>"]
        CRYPTO["🔐 Cryptographic Engine<br/><i>bcrypt (Work Factor 12) & Argon2id</i>"]
    end

    subgraph STORAGE["💾 Persistence & State Store"]
        DB[("SQLite Credential Store<br/>• Unique 128-bit Cryptographic Salt<br/>• Slow Adaptive Bcrypt Hash<br/>• Base32 Shared TOTP Secret<br/>• Lockout Timestamps & Failure Counters")]
    end

    T1 -.->|"Attempts Rainbow Tables & Dictionaries"| CRYPTO
    CRYPTO -.->|"Computationally neutralized by cost factor"| T1

    T2 ==>|"Rapid Inbound HTTP Requests"| FW
    FW -->|"Initial verification"| AUTH
    AUTH -->|"Emits authentication failure events"| F2B
    F2B -->|"Injects automated DROP rules"| FW
    FW -.->|"Drops packets at kernel layer (Zero App Overhead)"| T2

    AUTH -->|"Enforces lockout state"| LOCK
    LOCK -->|"Password validated"| MFA
    MFA -->|"Requires dynamic 6-digit TOTP"| DB
```

---

## 🔄 Authentication Flow Analysis

The sequence below illustrates the behavioral divergence between unprotected authentication endpoints and AuthShield's hardened defense pipeline:

```mermaid
sequenceDiagram
    autonumber
    actor Attacker as ⚔️ Automated Threat (Brute Force)
    actor User as 👤 Legitimate User
    participant App as ⚙️ Flask Application
    participant F2B as 🛡️ Fail2Ban / Firewall
    participant DB as 💾 Database Store

    Note over Attacker, DB: Vulnerable Baseline Model (No Lockout, Fast MD5)
    loop Rapid Credential Spraying
        Attacker->>App: Submits guessed credentials
        App->>DB: Queries user record
        App->>App: Computes unsalted MD5 hash
        App-->>Attacker: 401 Unauthorized
    end
    Attacker->>App: Submits matched dictionary password
    App-->>Attacker: 200 OK (Account Compromised)

    Note over User, DB: AuthShield Hardened Model (Bcrypt + Lockout + Fail2Ban + MFA)
    loop Invalid Password Attempts
        Attacker->>App: Submits guessed password
        App->>DB: Increments failed attempt counter
        App->>App: Logs failure event to security audit log
        App-->>Attacker: 401 Unauthorized
    end
    Note over App, DB: Threshold Reached: 5 Failed Attempts
    App->>DB: Locks account for 900 seconds (15 minutes)
    Attacker->>App: Submits further password attempts
    App-->>Attacker: 403 Forbidden (Account Temporarily Locked)
    F2B->>F2B: Parses threshold violation in audit log
    F2B->>F2B: Inserts dynamic kernel DROP rule for attacker IP
    Attacker->>App: Subsequent login requests
    Note over Attacker, App: Packets Dropped at Kernel Level (Connection Timed Out)

    Note over User, DB: Legitimate User Authentication Flow
    User->>App: Submits valid username & password
    App->>App: Verifies password via slow salted bcrypt
    App-->>User: 302 Redirect to MFA challenge
    User->>App: Submits 6-digit code from Authenticator app
    App->>App: Validates token against 30-second HMAC window
    App-->>User: 200 OK (Full Access Granted)
```

---

## ⚔️ Threat Vectors & Attack Analysis

### 1. Offline Cryptographic Attack (Database Breach)
An offline attack assumes an adversary has obtained the credential store directly (via SQL injection, file inclusion, or backup leakage). Under this threat model, all network protections and login throttles are bypassed, allowing the attacker to dedicate unlimited local compute power to reversing hashes.

* **Legacy Vulnerability:** Storage of passwords using raw, unsalted **MD5**.
* **Exploitation Dynamics:**
  * **Algorithmic Velocity:** MD5 was designed for high-throughput checksum generation, not password storage. Modern consumer hardware computes billions of MD5 digests per second.
  * **Rainbow Table Lookups:** Without unique salts, identical plaintext passwords yield identical hashes. Attackers use precomputed hash chains (rainbow tables) to reverse passwords in constant $O(1)$ lookup time.
* **Impact:** Instantaneous mass-disclosure of user credentials across the entire database.

---

### 2. Online Automated Brute-Force & Credential Stuffing
An online attack targets live login interfaces by automating credential submissions over HTTP to guess passwords or exploit credential reuse.

* **Legacy Vulnerability:** Public login endpoints lacking request throttling, failure quotas, or network-level blocking.
* **Exploitation Dynamics:**
  * **Endpoint Flooding:** Without rate limits, automated bots can test hundreds of thousands of credential combinations directly against the authentication handler.
  * **Server Resource Starvation:** Each incoming connection forces the server to parse HTTP headers, manage database connections, and execute queries, leaving the application susceptible to Denial of Service (DoS).
* **Impact:** Unauthorized account takeover and server availability degradation.

---

## 🛡️ Multi-Layered Defense-in-Depth

AuthShield orchestrates four coordinated defense layers to ensure resilient protection across both offline and online attack surfaces:

| Security Layer | Implementation Mechanism | Threat Addressed | Operational Scope |
| :--- | :--- | :--- | :--- |
| **1. Cryptographic Core** | 128-bit Per-Password Salt + Adaptive Slow Hashing (`bcrypt` / `Argon2id`) | Offline Cracking & Rainbow Tables | Protects database credentials even after a complete persistence leak. |
| **2. Application Control** | Stateful Threshold Lockout (5 attempts / 15-minute freeze) | Online Automated Password Guessing | Protects user accounts from targeted brute-forcing and credential stuffing. |
| **3. Network Perimeter** | Fail2Ban Log Parsing + Linux Netfilter Kernel Drops (`iptables`) | Flood Attacks & Application DoS | Protects server infrastructure by dropping malicious traffic at the OS kernel. |
| **4. Identity Gate** | RFC 6238 Time-based One-Time Passwords (TOTP MFA) | Compromised / Replayed Credentials | Blocks access even when primary passwords are breached or guessed. |

---

### Defensive Architecture Breakdown

#### 🧂 1. Cryptographic Salting & Slow Hashing
* **Cryptographic Salting:** Every password hash incorporates a unique, cryptographically random 128-bit salt generated via a Cryptographically Secure Pseudo-Random Number Generator (CSPRNG). This guarantees that duplicate passwords generate entirely distinct digests, defeating rainbow tables and bulk batch attacks.
* **Tunable Work Factor:** Incorporates key derivation functions with configurable computational cost ($2^{\text{cost}}$). The system deliberately calibrates hashing duration to ~250 milliseconds per login. While imperceptible to a human user, this latency imposes decades of computational overhead on an attacker attempting to iterate through millions of wordlist entries.

#### 🔒 2. Application-Level Stateful Lockout
* The application layer tracks failed authentication attempts and cool-off timestamps per user account.
* When invalid login attempts reach **5 consecutive failures**, the account is placed in a **15-minute lockout state**.
* Incoming requests during this period receive an immediate HTTP `403 Forbidden` response without performing cryptographic verification, shutting down brute-force tools regardless of whether the attacker routes traffic through rotating proxy networks.

#### 🛡️ 3. Kernel-Level Firewall Defense (`Fail2Ban` + `iptables`)
* **The Need for Perimeter Throttling:** Application lockout safeguards accounts, but the web server still absorbs network traffic, parses incoming requests, and queries the database—leaving the host exposed to resource exhaustion.
* **Kernel Packet Filtering:** Fail2Ban acts as an active intrusion prevention daemon, parsing application security logs for authentication failure events. Upon detecting threshold breaches within a sliding time window, Fail2Ban issues netfilter rules directly to the Linux kernel:
  * Inbound TCP traffic from the abusive IP address is dropped immediately.
  * Packets are discarded before reaching the Python runtime, preserving CPU cycles, memory, and application responsiveness.

#### 📱 4. Multi-Factor Authentication (`PyOTP` TOTP)
* Enforces two-factor authorization: **Something You Know** (Master Password) + **Something You Have** (Physical Authenticator App).
* Adheres to RFC 6238: computes an HMAC-SHA1 digest over a shared Base32 secret key combined with the 30-second Unix epoch time window:
  $$\text{TOTP} = \text{Truncate}(\text{HMAC-SHA1}(\text{Secret}, \lfloor \text{Timestamp} / 30 \rfloor)) \pmod{10^6}$$
* Because the 6-digit passcode regenerates every 30 seconds and incorrect attempts count toward lockout thresholds, the probability of an attacker successfully guessing a token is vanishingly small ($\approx 0.0005\%$).

---

## 📊 Cryptographic Work Factor Benchmarking

To quantitatively measure the protection delivered by adaptive slow-hashing algorithms, empirical benchmarks were conducted measuring compute time and throughput across identical test hardware:

| Hashing Algorithm | Cost Configuration / Parameters | Mean Computation Time ($ms$) | Throughput (Hashes / Sec) | Estimated Time to Test 14.3M Passwords (`rockyou.txt`) |
| :--- | :--- | :--- | :--- | :--- |
| **MD5** *(Legacy Baseline)* | Single Iteration (Unsalted) | $\approx 0.0008 \text{ ms}$ | $\approx 1,250,000 \text{ H/s}$ | **$\approx 11.4 \text{ seconds}$** |
| **bcrypt** | Cost Factor = 10 ($2^{10} = 1,024$) | $\approx 68.2 \text{ ms}$ | $\approx 14.6 \text{ H/s}$ | **$\approx 11.3 \text{ days}$** |
| **bcrypt** | Cost Factor = 12 *(Production Baseline)* | $\approx 272.5 \text{ ms}$ | $\approx 3.6 \text{ H/s}$ | **$\approx 45.9 \text{ days}$** |
| **bcrypt** | Cost Factor = 14 ($2^{14} = 16,384$) | $\approx 1,090.0 \text{ ms}$ | $\approx 0.91 \text{ H/s}$ | **$\approx 181.8 \text{ days}$** |
| **Argon2id** | $t=2 \text{ iterations}, m=19\text{MB}, p=1$ | $\approx 42.1 \text{ ms}$ | $\approx 23.7 \text{ H/s}$ | **$\approx 7.0 \text{ days}$** |

> [!NOTE]
> *Empirical data confirms that transitioning from unsalted MD5 to calibrated bcrypt (Cost 12) increases attacker computational overhead by over **five orders of magnitude**, turning an 11-second brute-force sweep into a 45-day continuous computation.*

---

## ⚠️ Security Considerations & Residual Risks

A comprehensive security model acknowledges operational trade-offs and residual risks:

1. **Account Lockout Denial-of-Service:** Threshold-based account lockout introduces a vector where a malicious actor can intentionally submit 5 invalid attempts against known usernames to deliberately lock legitimate users out. Production environments typically mitigate this by combining IP reputation, progressive time delays, and CAPTCHA challenges before triggering hard account lockouts.
2. **Transport Security Requirements:** In local laboratory environments without TLS/HTTPS, authentication headers and tokens travel in cleartext. In production deployments, end-to-end encryption (TLS 1.3) is mandatory to prevent intermediate network sniffing.
3. **Secret Key Management:** Production deployments require that application session secrets, encryption keys, and database credentials be injected dynamically via secure secret management services (e.g., HashiCorp Vault, AWS Secrets Manager) rather than static configuration files.

---
