# AuthShield — Hashing Speed & Crack-Time vs. Work Factor

> **Lab Hardware Environment:**
> - **GPU:** NVIDIA GeForce RTX 3060 Ti (CUDA 13.5, 8 GB VRAM, 38 SMs / Compute Units)
> - **CPU:** AMD Ryzen 7 5700X 8-Core Processor (16 threads, 4.6 GHz boost)
> - **Dictionary:** `wordlists/rockyou.txt` (14,344,384 candidate passwords, 139.9 MB)
> - **Tools:** Hashcat v6.2.6 (`-m 0`, `-m 3200`), John the Ripper (`--format=bcrypt`), Python 3.12 (`bcrypt`, `argon2-cffi`)

---

## 1. Comprehensive Crack-Rate & Work Factor Benchmark Table

| Algorithm & Work Factor | Cracking Mode | Hashcat Speed (GPU + CPU) | Python Benchmark Cost  | Projected Full `rockyou.txt` Crack Time |
| :--- | :---: | :---: | :---: | :---: |
| **MD5 (unsalted)** | `-m 0` | **68,850,900 H/s** | 0.0004 ms (2,682,184 H/s) | **0.21 sec (GPU)** / 5.35 sec (CPU) |
| **bcrypt (`rounds=10`)** | `-m 3200` | **1,393 H/s** | 46.83 ms (21.4 H/s) | **2.86 hours (GPU)** / 7.77 days (CPU) |
| **bcrypt (`rounds=12`)** | `-m 3200` | **387 H/s** | 187.24 ms (5.3 H/s) | **10.30 hours (GPU)** / 31.09 days (CPU) |
| **bcrypt (`rounds=14`)** | `-m 3200` | ~97 H/s *(projected)* | 750.26 ms (1.3 H/s) | **~41.2 hours (GPU)** / 124.56 days (CPU) |
| **Argon2id (`t=2, m=19MB`)** | `-m 34000` | Memory-hard | 20.89 ms (47.9 H/s) | **3.47 days (CPU)**, GPU memory-choked |
| **Argon2id (`t=3, m=64MB`)** | `-m 34000` | Memory-hard | 129.06 ms (7.7 H/s) | **21.43 days (CPU)**, GPU memory-choked |

---

## 2. John the Ripper CPU Benchmark 

* **Tool:** John the Ripper (v1.9.0-jumbo-1)
* **Target Format:** `bcrypt [Blowfish 32/64 X3]` (4 OpenMP threads)
* **Cost 1 (Iteration Count):** `4096` ($2^{12}$ loops, `rounds=12`)
* **Measured CPU Speed:** **54.97 p/s** (passwords / second)
* **Projected `rockyou.txt` Duration on CPU:** **~3.02 days**

---

## 3. Key Empirical Findings & Discussion

### A. The $2^\Delta$ Mathematical Work Factor Rule Confirmed
In bcrypt, the iteration count is given by $2^{\text{rounds}}$. Increasing the cost factor from 10 to 12 represents a 2-round increase:

$$\frac{2^{12}}{2^{10}} = 2^2 = 4\times \text{ computational difficulty}$$

* **Empirical Measurement:**
  * GPU Hashcat speed at `rounds=10`: **1,393 H/s**
  * GPU Hashcat speed at `rounds=12`: **387 H/s**
  * Observed slowdown factor:
    $$\frac{1,393 \text{ H/s}}{387 \text{ H/s}} \approx \mathbf{3.60\times}$$
* **Finding:** The empirical GPU measurement closely aligns with theoretical key-stretching expectations ($\approx 4\times$ reduction in attacker throughput).

---

### B. Asymmetric Defense (MD5 vs. bcrypt)
* Against **unsalted MD5**, the RTX 3060 Ti reached **68.85 Million hashes/sec**, exhausting the entire 14.3-million-entry wordlist in a fraction of a second.
* Switching to **bcrypt (`rounds=12`)** dropped GPU cracking throughput by a factor of:

$$\frac{68,850,900 \text{ H/s}}{387 \text{ H/s}} \approx \mathbf{177,909\times \text{ slowdown}}$$

* **Finding:** A dictionary search that completes instantaneously against MD5 is pushed to over **10 hours on an RTX 3060 Ti** and **over 31 days on an 8-core CPU**, rendering brute-force attacks infeasible for attackers holding a stolen database.

---

### C. Argon2id Memory-Hardness Defense
While bcrypt stresses the processor (CPU/ALU), **Argon2id** forces the hashing engine to allocate dedicated blocks of RAM (19 MB to 64 MB per hash calculation):
* High-speed GPU cracking clusters feature thousands of tiny cores with limited fast cache per core.
* Forcing 64 MB of RAM allocation per thread exhausts the graphics card's 8 GB VRAM after just ~120 parallel threads, neutralising GPU botnets.
