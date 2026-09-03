#!/usr/bin/env bash
# =============================================================================
# crack_all.sh — ENTRY POINT for the WPA2 crack pipeline.
#
# THIS IS THE SHELL WRAPPER. It:
#   1. Checks the environment (python3, hashcat, OpenCL/GPU, wordlists).
#   2. Installs anything missing (pacman for hashcat; clone for wordlists).
#   3. Delegates ALL cracking logic to crack.py, passing through every argument.
#
# So the entry point is ALWAYS this .sh file, never crack.py directly.
# (Unless you pass --python to run crack.py straight, for debugging.)
#
# USAGE (same semantics as crack.py):
#   ./crack_all.sh                     # crack all pending
#   ./crack_all.sh "<hash file .22000>" # crack a single file
#   ./crack_all.sh --dry               # dry run (no crack, no file move)
#   ./crack_all.sh --background        # run all pending detached
#
# =============================================================================

set -u
shopt -s nullglob nocaseglob

HASHCLR="\033[0m"; RED="\033[31m"; GREEN="\033[32m"; YEL="\033[33m"; BLU="\033[34m"
OK()  { echo -e "${GREEN}[+]${HASHCLR} $*"; }
WARN(){ echo -e "${YEL}[!]${HASHCLR} $*"; }
ERR() { echo -e "${RED}[x]${HASHCLR} $*"; }
die() { ERR "$*"; exit 1; }

BASE="$HOME/wifi-cracker"
WORDLISTS="$BASE/wordlists"
DL_DIR="$WORDLISTS/vie_wpa2_pw"
VI_DIR="$WORDLISTS/wordlists-vi"

# ---- cross-distro: detect package manager from /etc/os-release ----
detect_pkg() {
  if   command -v apt-get   >/dev/null 2>&1; then echo "apt";   # Debian/Ubuntu
  elif command -v dnf       >/dev/null 2>&1; then echo "dnf";   # Fedora/RHEL/Rocky
  elif command -v yum       >/dev/null 2>&1; then echo "yum";   # RHEL/CentOS (older)
  elif command -v pacman    >/dev/null 2>&1; then echo "pacman";# Arch/CachyOS/Manjaro
  elif command -v zypper    >/dev/null 2>&1; then echo "zypper";# openSUSE
  elif command -v apk       >/dev/null 2>&1; then echo "apk";   # Alpine
  else echo "unknown"; fi
}
PKG="$(detect_pkg)"

# install_pkg <package>  — tries the distro's manager, tolerates existing packages.
install_pkg() {
  local p="$1"
  case "$PKG" in
    apt)   sudo apt-get update -qq 2>&1 | tail -1; sudo apt-get install -y "$p" 2>&1 | tail -2 ;;
    dnf)   sudo dnf install -y "$p" 2>&1 | tail -2 ;;
    yum)   sudo yum install -y "$p" 2>&1 | tail -2 ;;
    pacman) sudo pacman -S --needed --noconfirm "$p" 2>&1 | tail -2 ;;
    zypper) sudo zypper --non-interactive install "$p" 2>&1 | tail -2 ;;
    apk)   sudo apk add "$p" 2>&1 | tail -2 ;;
    *)     WARN "unsupported package manager; you must install '$p' manually"; return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# 0. Presence of crack.py (must be co-located)
# ---------------------------------------------------------------------------
PY="$BASE/crack.py"
[ -f "$PY" ] || die "crack.py not found at $PY. This wrapper must live next to crack.py."

# ---------------------------------------------------------------------------
# 1. python3
# ---------------------------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
  WARN "python3 missing — installing..."
  case "$PKG" in
    apt)   install_pkg python3 ;;
    dnf)   install_pkg python3 ;;
    pacman) install_pkg python ;;
    zypper) install_pkg python3 ;;
    *)     die "python3 required but no package manager detected." ;;
  esac
fi
PYVER=$(python3 -V 2>&1 | awk '{print $2}')
OK "python3 ${PYVER}"

# ---------------------------------------------------------------------------
# 2. hashcat + rules
# ---------------------------------------------------------------------------
HASHCAT_BIN=$(command -v hashcat || true)
if [ -z "$HASHCAT_BIN" ]; then
  WARN "hashcat not found — installing..."
  install_pkg hashcat || die "Failed to install hashcat."
  HASHCAT_BIN=$(command -v hashcat)
fi
OK "hashcat: $($HASHCAT_BIN --version 2>/dev/null | head -1)"

# hashcat rules live in different places on different distros.
# Try the common candidates in order.
HASHCAT_RULE_DIR=""
for cand in /usr/share/doc/hashcat/rules /usr/share/hashcat/rules /usr/share/doc/packages/hashcat/rules; do
  if [ -d "$cand" ] && [ -n "$(ls -A "$cand" 2>/dev/null)" ]; then
    HASHCAT_RULE_DIR="$cand"; break
  fi
done
if [ -n "$HASHCAT_RULE_DIR" ]; then
  OK "hashcat rules: $HASHCAT_RULE_DIR"
  # On some distros (Arch) the rules dir is NOT shipped with the binary package.
  if [ ! -f "$HASHCAT_RULE_DIR/best66.rule" ]; then
    WARN "best66.rule missing (hashcat rules not shipped on this distro)."
    WARN "Install the hashcat rules package if available, or copy rules manually."
    WARN "Rule layers will be skipped; wordlist/mask attacks still work."
  fi
else
  WARN "No hashcat rules dir found — rule layers will be skipped (wordlist/mask still run)."
  WARN "On Kali/BlackArch, rules ship with hashcat. On Arch, use 'hashcat-utils' or copy from a Kali box."
fi

# --- OpenCL/GPU backend sanity (per-distro, non-fatal) ---
if ! $HASHCAT_BIN -I 2>/dev/null | grep -qiE "OpenCL|CUDA"; then
  WARN "No hashcat device/backend detected."
  WARN "Install the OpenCL runtime + GPU driver (varies by distro):"
  WARN "  Debian/Ubuntu : ocl-icd-libopencl1 + your GPU driver (nvidia-opencl-icd / mesa-opencl-icd)"
  WARN "  Fedora/RHEL   : ocl-icd + nvidia/amdgpu OpenCL (e.g. 'mesa-filesystem' or vendor)"
  WARN "  Arch/CachyOS  : nvidia-utils (provides OpenCL) or 'ocl-icd' + 'opencl-clhpp'"
  WARN "  openSUSE      : 'ocl-icd' + vendor OpenCL"
  WARN "Cracking will be slow or fail entirely without a backend."
fi

# ---------------------------------------------------------------------------
# 3. Wordlists (rockyou + VN). Clone from canonical sources if missing.
# ---------------------------------------------------------------------------
[ -d "$WORDLISTS" ] || mkdir -p "$WORDLISTS"

# rockyou: expect the full 14.3M-line one. A tiny subset is NOT usable.
ROCKYOU="$WORDLISTS/rockyou.txt"
rc_size() { [ -f "$1" ] && stat -c%s "$1" 2>/dev/null || echo 0; }
if [ "$(rc_size "$ROCKYOU")" -lt 10000000 ]; then
  WARN "rockyou.txt missing/too small — trying to obtain a full copy..."
  # 1) system seclists copy
  SYS_RY="/usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt"
  if [ -f "$SYS_RY" ] && [ "$(stat -c%s "$SYS_RY")" -gt 10000000 ]; then
    cp "$SYS_RY" "$ROCKYOU"; OK "Copied system rockyou.txt ($(du -h "$ROCKYOU" | cut -f1))"
  else
    # 2) download a canonical google-10000 / rockyou mirror (worst case fallback)
    WARN "No local full rockyou. Attempting download (~134MB)..."
    curl -fsSL --retry 3 -o "$ROCKYOU" \
      "https://raw.githubusercontent.com/brannondorsey/naive-hashcat/master/rockyou.txt" \
      && OK "Downloaded rockyou.txt ($(du -h "$ROCKYOU" | cut -f1))" \
      || { WARN "Download failed. Try:  sudo pacman -S seclists  (then run again)."
           WARN "   or manually place a plaintext rockyou.txt (14.3M lines, >10MB) at $ROCKYOU."; }
  fi
else
  OK "rockyou.txt ($(du -h "$ROCKYOU" | cut -f1))"
fi

# VN wordlists: clone the two canonical repos if the files are absent.
if [ ! -d "$DL_DIR" ] || [ ! -f "$DL_DIR/vie-personal_dehashed_dict-18may2025.txt" ]; then
  WARN "Vietnamese wordlists missing — cloning vie_wpa2_pw..."
  mkdir -p "$WORDLISTS"
  git clone --depth 1 https://github.com/sakkarose/vie_wpa2_pw.git "$DL_DIR" \
    2>&1 | tail -2 || WARN "clone vie_wpa2_pw failed (skip: network?)"
fi
if [ ! -d "$VI_DIR" ] || [ ! -f "$VI_DIR/wordlists-vn1k.txt" ]; then
  WARN "Vietnamese wordlists missing — cloning wordlists-vi..."
  mkdir -p "$WORDLISTS"
  git clone --depth 1 https://github.com/lucthienphong1120/wordlists-vi.git "$VI_DIR" \
    2>&1 | tail -2 || WARN "clone wordlists-vi failed (skip: network?)"
fi

# ---------------------------------------------------------------------------
# 4. GPU / OpenCL sanity
# ---------------------------------------------------------------------------
if $HASHCAT_BIN -I 2>/dev/null | grep -qiE "OpenCL|CUDA"; then
  OK "OpenCL/CUDA backend detected"
else
  WARN "No hashcat device/backend detected. On a headless or laptop without driver, cracking will be slow/fail."
  WARN "On Arch/CachyOS: install the OpenCL ICD or the Nvidia driver for compute (nvidia-utils provides OpenCL)."
fi

# ---------------------------------------------------------------------------
# 5. Delegate to crack.py (pass ALL args through)
# ---------------------------------------------------------------------------
OK "Handing off to crack.py (entry logic is in Python)..."
echo
# If the caller wants a root-level hint about which dir rules live in, bake it in:
export HASHCAT_RULE_DIR="${HASHCAT_RULE_DIR}"
exec python3 "$PY" "$@"
