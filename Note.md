# 🛡️ AuthShield: Authentication & Password Security

> **Quick Reference Guide & Security Blueprint**  
> *Core concepts covering password attack vectors, modern cryptographic hashing, and layered defense mechanisms.*

---

## 📊 Security Architecture Overview

```mermaid
flowchart TD
    subgraph ATTACKS["⚔️ Attack Vectors"]
        A1["💥 Weak Hashes<br/><i>Fast / Insecure algorithms</i>"]
        A2["🔨 Brute-Force Attack<br/><i>Automated credential guessing</i>"]
    end

    subgraph DEFENSES["🛡️ Defensive Controls"]
        D1["🧂 Salted Hashing<br/><i>Unique per-password salt</i>"]
        D2["⏳ Slow Hashing<br/><i>bcrypt / Argon2</i>"]
        D3["🔒 Account Lockout<br/><i>Threshold rate limiting</i>"]
        D4["📱 Multi-Factor Auth (MFA)<br/><i>TOTP / Authenticator</i>"]
    end

    A1 -.->|"Cracked via John / Hashcat"| D1
    A1 -.->|"Slowed down by work factor"| D2
    A2 -.->|"Blocked after N attempts"| D3
    A2 -.->|"Blocked without physical token"| D4

    classDef attack fill:#ffebee,stroke:#d32f2f,stroke-width:2px,color:#b71c1c;
    classDef defense fill:#e8f5e9,stroke:#388e3c,stroke-width:2px,color:#1b5e20;
    class A1,A2 attack;
    class D1,D2,D3,D4 defense;
```

---

## ⚔️ Threat & Attack Concepts

### 1. ⚠️ Weak Hashes
> **Definition:** Passwords that are stored using insecure or fast hashing methods, making it easier for attackers to guess the original password using tools like **John the Ripper** or **Hashcat**.

* **Why it is vulnerable:** Algorithms like MD5, SHA-1, or unsalted SHA-256 compute billions of hashes per second on modern GPUs. Attackers can quickly run dictionary attacks or precomputed lookups.
* **Exploitation Tools:** `John the Ripper`, `Hashcat`.
* **Impact:** Complete exposure of plaintext credentials in the event of a database leak.

> [!WARNING]
> Fast cryptographic hashes are intended for message integrity, **not** password storage. Storing raw or single-iteration hashes leaves credentials vulnerable to near-instant cracking.

---

### 2. 🔨 Brute-Force Attack
> **Definition:** An attack where someone repeatedly tries different password combinations on a login page until they find the correct password. Tools like **Hydra** automate this process.

* **Execution:** Attackers test wordlists, common passwords, or systematic permutations against authentication interfaces.
* **Exploitation Tools:** `THC-Hydra`, `Burp Suite Intruder`, custom credential stuffing scripts.
* **Impact:** Unauthorized account takeover when weak, default, or reused passwords exist.

> [!CAUTION]
> Online brute-force attacks continuously stress server resources and can compromise user accounts unless active throttling or lockout controls are enforced.

---

## 🛡️ Defensive Controls & Mitigation

### 3. 🧂 Salted Hashing
> **Definition:** Adds a random value (called a **salt**) to a password before hashing it. This makes identical passwords produce different hashes and makes precomputed attacks harder.

* **Key Mechanics:**
  $$\text{Stored Record} = \{\text{salt}, \text{Hash}(\text{password} + \text{salt})\}$$
* **Defeats:** Rainbow tables and precomputed hash tables.
* **Benefit:** Two users with the password `P@ssword123` will store completely distinct hashes, preventing bulk cracking.

> [!TIP]
> Always generate a cryptographically strong, unique pseudo-random salt for every single password entry. Salts do not need to be secret, but must never be reused.

---

### 4. ⏳ Slow Hashing
> **Definition:** Uses algorithms like **bcrypt** or **Argon2** that intentionally take more time and memory to calculate each password hash, making password cracking much harder.

* **Standard Algorithms:** `Argon2id` (winner of the Password Hashing Competition), `bcrypt`, `PBKDF2`, `scrypt`.
* **Configurable Work Factor:** Allows administrators to tune iteration counts or memory parameters as hardware improves over time.
* **Real-World Impact:**
  * Fast Hash (MD5/SHA1): **Billions** of attempts/second.
  * Slow Hash (bcrypt / Argon2): **Tens or hundreds** of attempts/second per GPU.

> [!IMPORTANT]
> Tune your slow-hashing work factor to consume ~100–500ms on server authentication. This creates zero perceptible delay for legitimate users while making offline brute-force cracking practically impossible.

---

### 5. 🔒 Account Lockout
> **Definition:** Temporarily blocks an account after several failed login attempts to prevent attackers from continuously guessing passwords.

* **Implementation Strategies:**
  * **Progressive Delay:** Incremental sleep delays between failed attempts (e.g., 1s, 2s, 4s, 8s).
  * **Threshold Lockout:** Temporary lockout after $N$ failed attempts (e.g., 5 attempts locks out for 15 minutes).
  * **Network Throttling:** Blocking abusive source IPs using tools such as `fail2ban`.
* **Protection Focus:** Neutralizes automated online brute-force tools (like Hydra).

> [!NOTE]
> Consider combining username lockouts with IP rate-limiting and CAPTCHA to mitigate Denial-of-Service (DoS) risks where an attacker maliciously locks out legitimate users.

---

### 6. 📱 MFA (Multi-Factor Authentication)
> **Definition:** Requires an additional verification method besides the password, such as a code from **Google Authenticator**, to log in.

* **Core Principles:**
  * **Something you know:** Master Password / Passphrase
  * **Something you have:** Authenticator App (TOTP - RFC 6238), Security Key (FIDO2 / WebAuthn)
  * **Something you are:** Biometrics (Fingerprint / Face ID)
* **Threat Mitigation:** Even if an attacker cracks a password hash or guesses credentials via brute force, access is blocked without the secondary verification factor.

> [!TIP]
> Time-based One-Time Password (TOTP) implementations like Google Authenticator or Microsoft Authenticator provide strong, cost-effective MFA with no reliance on vulnerable SMS networks.

---

## 📋 Summary Matrix

| Concept | Classification | Primary Mechanism | Key Tools / Standards | Primary Countermeasure Against |
| :--- | :---: | :--- | :--- | :--- |
| **Weak Hashes** | 🔴 Threat | Outdated/fast hash algorithms without computational cost | John the Ripper, Hashcat | Upgrading to Argon2 / bcrypt |
| **Brute-Force Attack** | 🔴 Threat | Rapid, automated password guessing against login endpoints | Hydra, Burp Suite | Account lockout, rate limits & MFA |
| **Salted Hashing** | 🟢 Defense | Unique random seed prepended/appended to password | Cryptographic PRNG | Rainbow tables & cross-user cracking |
| **Slow Hashing** | 🟢 Defense | Adjustable memory & CPU work factors | Argon2id, bcrypt, PBKDF2 | Offline hardware-accelerated cracking |
| **Account Lockout** | 🟢 Defense | Threshold-based temporary suspension & request limiting | fail2ban, redis rate-limiter | Online automated guessing (Hydra) |
| **MFA** | 🟢 Defense | Multi-layered independent authentication factors | TOTP (RFC 6238), WebAuthn | Credential leakage & password reuse |

---

## 🚀 Defense-in-Depth Best Practices Checklist

- [x] **Store passwords using Argon2id or bcrypt** with calibrated cost factors.
- [x] **Enforce unique per-user cryptographic salts** automatically handled by the hashing library.
- [x] **Deploy online rate limiting & fail2ban rules** to thwart automated login attacks.
- [x] **Integrate TOTP Multi-Factor Authentication (MFA)** for all sensitive user accounts.
- [x] **Implement secure password policies** focusing on length and entropy rather than complex arbitrary rotations.

