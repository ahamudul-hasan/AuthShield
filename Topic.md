## P11 · Authentication & Password Security

**Theme:** Web / System

### Scope

- Crack weak hashes (John / Hashcat) and brute-force a login (Hydra).
- Defenses: bcrypt / Argon2 with salting, account lockout (fail2ban), and TOTP MFA.
- Compare crack times and show the brute force stopped.

### Tools

John the Ripper, Hashcat, Hydra; fail2ban; a TOTP library.

### Lab

A login app and a cracking host.

### Milestones

1. Crack weak hashes and brute-force the login.
2. Add salted slow hashing, lockout, and MFA.
3. Re-run and tabulate crack-time vs. work factor.

### Deliverables

A cracking comparison, an MFA-enabled app, and a demo.
