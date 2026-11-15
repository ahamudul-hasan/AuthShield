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

print("Benchmarking MD5...")
md5_t = time_fn(lambda: hashlib.md5(b"testpassword123").hexdigest(), n=2000)
record("MD5 (unsalted)", "-", md5_t)

print("Benchmarking bcrypt rounds 10, 12, 14...")
for rounds in [10, 12, 14]:
    t = time_fn(lambda r=rounds: bcrypt.hashpw(b"testpassword123", bcrypt.gensalt(rounds=r)), n=5)
    record("bcrypt", f"rounds={rounds}", t)

print("Benchmarking Argon2id profiles...")
for label, t_cost, m_cost, p_cost in [
    ("t=2, m=19MB, p=1", 2, 19456, 1),
    ("t=3, m=64MB, p=1", 3, 65536, 1),
]:
    ph = PasswordHasher(time_cost=t_cost, memory_cost=m_cost, parallelism=p_cost)
    t = time_fn(lambda p=ph: p.hash("testpassword123"), n=5)
    record("Argon2id", label, t)

OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
report = "\n".join(lines)
print("\n" + report)
OUT_FILE.write_text(report + "\n")
print(f"\nSaved to {OUT_FILE}")
