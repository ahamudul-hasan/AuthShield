#!/usr/bin/env bash
# ==============================================================================
# AUTHSHIELD - AUTOMATED ENVIRONMENT SETUP SCRIPT
# Recreates the entire lab environment on a fresh clone.
# Usage:
#   chmod +x setup.sh
#   ./setup.sh
#   # or: bash setup.sh
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "===================================================================="
echo "  AuthShield Environment Setup (P11 Lab)"
echo "===================================================================="

# 1. Verify OS environment
if ! command -v apt >/dev/null 2>&1; then
    echo "[!] Warning: 'apt' package manager not found. This script targets Ubuntu/Debian (e.g. WSL 2)."
    echo "    Please install dependencies manually on your distribution."
fi

# 2. Install Linux system packages from packages.txt
if [ -f "packages.txt" ] && command -v apt >/dev/null 2>&1; then
    echo "[+] Updating apt repositories and installing system packages..."
    PACKAGES=$(grep -v '^[[:space:]]*#' packages.txt | grep -v '^[[:space:]]*$' | tr '\n' ' ')
    sudo apt update
    sudo apt install -y $PACKAGES
    echo "[✓] System packages installed successfully."
fi

# 3. Create required single-purpose project directories
echo "[+] Ensuring project directories exist..."
mkdir -p app database/{schemas,seeds,backups} hashes logs results scripts Terminal_crack_result wordlists
touch logs/auth.log
echo "[✓] Project directories and logs/auth.log initialized."

# 4. Set up Python virtual environment
VENV_DIR=".venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "[+] Creating Python virtual environment at $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
fi

echo "[+] Activating virtual environment and installing Python packages..."
# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    echo "[✓] Python packages installed from requirements.txt."
fi

# 5. Check / download rockyou.txt wordlist if missing
WORDLIST_FILE="wordlists/rockyou.txt"
if [ ! -f "$WORDLIST_FILE" ] || [ ! -s "$WORDLIST_FILE" ]; then
    echo "[+] Downloading rockyou.txt (~134 MB) to $WORDLIST_FILE..."
    curl -L -o "$WORDLIST_FILE" \
      https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt || {
        echo "[!] Download failed or was interrupted. Please obtain rockyou.txt manually."
    }
fi
if [ -f "$WORDLIST_FILE" ]; then
    echo "[✓] Wordlist verified: $WORDLIST_FILE ($(wc -l < "$WORDLIST_FILE" | tr -d ' ') lines)"
fi

# 6. Verify security tools respond
echo ""
echo "===================================================================="
echo "  Verifying Tool Installations"
echo "===================================================================="
python3 -c "import flask, bcrypt, argon2, pyotp, qrcode, sqlite3; print('[✓] Python stack (Flask, bcrypt, Argon2id, pyotp, qrcode, sqlite3) OK')"

if command -v john >/dev/null 2>&1; then
    echo "[✓] John the Ripper: $(john --list=build-info 2>/dev/null | head -n1 || echo 'Installed')"
fi

if command -v hashcat >/dev/null 2>&1; then
    echo "[✓] Hashcat: $(hashcat --version 2>/dev/null || echo 'Installed')"
fi

if command -v hydra >/dev/null 2>&1; then
    echo "[✓] THC-Hydra: $(hydra -h 2>&1 | head -n1)"
fi

if command -v fail2ban-client >/dev/null 2>&1; then
    echo "[✓] Fail2Ban: $(fail2ban-client --version 2>/dev/null || echo 'Installed')"
fi

echo ""
echo "===================================================================="
echo "  [✓] Setup Complete!"
echo "  Activate your environment anytime with:"
echo "    source $VENV_DIR/bin/activate"
echo "===================================================================="

