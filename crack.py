#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
crack.py — WPA2 .22000 crack pipeline (Vietnamese wordlists + masks)
Target: Dell Precision 7520 (CachyOS/Arch), GPU Quadro M2200 via OpenCL, hashcat 7.x (~94k H/s WPA2).

MANAGED HANDSUCK ORGANIZATION
-----------------------------
Folder  handshakes/
├── pending/   # new / not-yet-tried hashes (drop .pcap + _hs.22000 here)
├── success/   # cracked -> password recovered (auto-moved after run)
└── fail/      # not cracked after full pipeline (auto-moved after run)

TWO MODES
---------
1) All (default, no args):  crack.py
   -> iterate every `*_hs.22000` in handshakes/pending, crack sequentially, classify each.
2) Single (file arg):       crack.py "handshakes/pending/FOO_hs.22000"
   -> crack ONLY that hash, then classify it (moves it to success/ or fail/).

Both modes classify (move to success/fail) after cracking. If you drop a new
.pcap + .22000 into pending, the "all" mode picks it up on the next run.

HOW CLASSIFY WORKS (bug fixed vs old bash script)
-------------------------------------------------
The OLD script checked a SINGLE shared potfile — if a leftover password from a
previous crack sat in it, it wrongly reported "cracked" and stopped early.
THIS script uses ONE potfile PER HASH (work/potfiles/<stem>.potfile) and checks
whether THAT hash specifically appears in it. Switching potfiles is safe because
hashcat v7 supports one --potfile-path per invocation.

Usage
-----
    ./crack.py                       # crack all pending
    ./crack.py "<hash.22000>"        # crack one file
    ./crack.py "<hash.22000>" --dry  # dry-run (print commands, don't crack)
    ./crack.py --background          # run all pending detached (nohup) -> log to work/crack.log
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import urllib.parse
from pathlib import Path
from datetime import datetime

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE       = Path.home() / "wifi-cracker"
HANDSHAKES = BASE / "handshakes"
SUCCESS    = HANDSHAKES / "success"
FAIL       = HANDSHAKES / "fail"
PENDING    = HANDSHAKES / "pending"
WORDLISTS  = BASE / "wordlists"
DL_DIR     = WORDLISTS / "vie_wpa2_pw"
VI_DIR     = WORDLISTS / "wordlists-vi"
WORK       = BASE / "work"
POTFILES   = WORK / "potfiles"
LOGDIR     = WORK / "logs"
RULE_DIR = Path(os.environ.get("HASHCAT_RULE_DIR", "/usr/share/doc/hashcat/rules"))

ROCKYOU    = WORDLISTS / "rockyou.txt"          # full 14.3M line rockyou
PERS       = DL_DIR / "vie-personal_dehashed_dict-18may2025.txt"

HASHCAT    = "hashcat"
# -m 22000: WPA/WPA2. -w 3: max workload. --backend-ignore-cuda: silence CUDA-RTC spinner.
# --hwmon-temp-abort 95: auto-stop if GPU hits 95°C (protects CPU too via shared heatsink).
HC_BASE    = ["-m", "22000", "-w", "3", "--backend-ignore-cuda",
              "--status", "--status-timer", "5", "--hwmon-temp-abort", "95"]
# --- GPU power limit (only applied if the user opts in via --limit-power N) ---
GPU_POWER_LIMIT_W = None

# ---------------------------------------------------------------------------
# Telegram notification (optional). Token read from ~/wifi-cracker/.telegram_secret
# (gitignored, chmod 600). If missing, notifications are silently skipped.
# ---------------------------------------------------------------------------
TELEGRAM_CHAT_ID = "5697772057"
TELEGRAM_SECRET_FILE = BASE / ".telegram_secret"

def _tg_token():
    try:
        data = TELEGRAM_SECRET_FILE.read_text().strip()
        return data if data else None
    except Exception:
        return None

def send_telegram(message, silent=True):
    """Best-effort Telegram send to the user's chat. Never raises."""
    token = _tg_token()
    if not token:
        return
    try:
        payload = urllib.parse.urlencode({
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "disable_notification": "true" if silent else "false",
        }).encode()
        with urllib.request.urlopen(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=payload, timeout=15) as r:
            r.read()
    except Exception as e:
        print(f"[telegram] send failed: {e}", flush=True)

# ---------------------------------------------------------------------------
# Colors (only when on a TTY)
# ---------------------------------------------------------------------------
if sys.stdout.isatty():
    C = dict(off="\033[0m", red="\033[31m", green="\033[32m", yel="\033[33m", blu="\033[34m")
else:
    C = dict(off="", red="", green="", yel="", blu="")
OK  = lambda *a: print(f"{C['green']}[+]{C['off']}", *a)
WARN= lambda *a: print(f"{C['yel']}[!]{C['off']}", *a)
ERR = lambda *a: print(f"{C['red']}[x]{C['off']}", *a)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def normalize_crlf(src: Path, dst: Path) -> int:
    """Strip CRLF. Returns line count."""
    data = src.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    dst.write_bytes(data)
    return data.count(b"\n")


def mask_count(path: Path) -> int:
    return sum(1 for ln in path.open(errors="replace") if ln.strip())


def is_cracked(hash_path: Path, potfile: Path) -> bool:
    """True if THIS hash's password is present in the potfile.

    Robust check: let hashcat itself map the hash<->potfile via `--show`.
    (The naive 'compare first colon field' approach breaks because hashcat 7.x
    stores the PMKID hash-field, which never matches a raw token split from the
    .22000 line — so every hash was wrongly classified fail.)
    """
    if not potfile.exists() or potfile.stat().st_size == 0:
        return False
    try:
        out = subprocess.run(
            [HASHCAT, "-m", "22000", f"--potfile-path={potfile}", "--show", str(hash_path)],
            capture_output=True, text=True, timeout=30)
    except Exception:
        return False
    text = out.stdout
    # --show prints the recovered line "<hash>:<password>" when cracked, and
    # nothing (or only informational text) when not. A real result always has
    # a ':' and the final field is the password. Ignore known info lines.
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("No hashes") or line.startswith("Separator"):
            continue
        if ":" in line:
            return True
    return False


def show_result(hash_path: Path, potfile: Path) -> None:
    print()
    OK("=" * 62)
    OK("CRACKED! Recovered password:")
    print("-" * 62)
    subprocess.run([HASHCAT, "-m", "22000", f"--potfile-path={potfile}", "--show", str(hash_path)])
    print("-" * 62)
    print()


def find_sibling_pcap(hash_path: Path) -> Path | None:
    """Locate the companion .pcap for a _hs.22000 hash file, if any."""
    stem = hash_path.stem              # e.g. "ANH HY_FC4009E1E14E_hs"
    base = re.sub(r"_hs$", "", stem)
    pcap = hash_path.parent / (base + ".pcap")
    if pcap.exists():
        return pcap
    for cand in hash_path.parent.glob(base + ".*"):
        if cand.suffix in (".pcap", ".cap", ".pcapng"):
            return cand
    return None


def classify(hash_path: Path, potfile: Path, dry: bool = False) -> str:
    """Move hash (+ sibling .pcap) to success/ or fail/. Returns 'success'/'fail'.

    NOTE: in --dry mode we NEVER touch the filesystem — just report the
    classification and leave the file where it is.
    """
    if is_cracked(hash_path, potfile):
        dest = SUCCESS
        result = "success"
        OK(f"→ SUCCESS: {hash_path.name}")
    else:
        dest = FAIL
        result = "fail"
        WARN(f"→ FAIL:    {hash_path.name}")

    if dry:
        WARN(f"  (dry) would move {hash_path.name} → {dest}")
        return result

    pcap = find_sibling_pcap(hash_path)
    # move the .22000
    dest_path = dest / hash_path.name
    shutil.move(str(hash_path), str(dest_path))
    # move sibling .pcap if present
    if pcap:
        shutil.move(str(pcap), str(dest / pcap.name))
    return result


# ---------------------------------------------------------------------------
# Attack layers (rule-based first -> wordlists -> masks)
# ---------------------------------------------------------------------------
def run_dict(label, wordlist, hash_path, potfile, dry=False):
    log = LOGDIR / f"{label}.log"
    log.write_text("")
    OK(f"Step: {label}")
    if not dry:
        send_telegram(f"[WIFI-CRACKER] \u25b6 START {label}")
    if dry:
        print(f"  (dry) hashcat -a 0 {' '.join(HC_BASE)} --potfile-path {potfile} {hash_path} {wordlist}")
        return
    with log.open("a") as f:
        subprocess.run(
            [HASHCAT, "-a", "0", *HC_BASE, f"--potfile-path={potfile}",
             str(hash_path), str(wordlist)],
            stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.STDOUT)


def run_dict_rule(label, wordlist, rule, hash_path, potfile, dry=False):
    if not rule.exists():
        WARN(f"skip {label}: rule missing {rule}")
        return
    log = LOGDIR / f"{label}.log"
    log.write_text("")
    OK(f"Step: {label}   (wordlist + {rule.name})")
    if not dry:
        send_telegram(f"[WIFI-CRACKER] \u25b6 START {label}")
    if dry:
        print(f"  (dry) hashcat -a 0 {' '.join(HC_BASE)} -r {rule} --potfile-path {potfile} {hash_path} {wordlist}")
        return
    with log.open("a") as f:
        subprocess.run(
            [HASHCAT, "-a", "0", *HC_BASE, "-r", str(rule), f"--potfile-path={potfile}",
             str(hash_path), str(wordlist)],
            stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.STDOUT)


def run_maskfile(label, maskfile, hash_path, potfile, dry=False):
    log = LOGDIR / f"{label}.log"
    log.write_text("")
    masks = mask_count(maskfile)
    OK(f"Layer: {label} ({masks} masks, -a 3)")
    if not dry:
        send_telegram(f"[WIFI-CRACKER] \u25b6 START {label} ({masks} masks)")
    with maskfile.open(errors="replace") as mf:
        for i, line in enumerate(mf, 1):
            line = line.strip()
            if not line:
                continue
            OK(f"  [mask {i}/{masks}] {line}")
            if dry:
                print(f"    (dry) hashcat -a 3 {' '.join(HC_BASE)} --potfile-path {potfile} {hash_path} \"{line}\"")
                continue
            with log.open("a") as f:
                subprocess.run(
                    [HASHCAT, "-a", "3", *HC_BASE, f"--potfile-path={potfile}",
                     str(hash_path), line],
                    stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.STDOUT)
            if is_cracked(hash_path, potfile):
                return True
    return is_cracked(hash_path, potfile)


def run_mask(label, mask_string, hash_path, potfile, dry=False):
    log = LOGDIR / f"{label}.log"
    log.write_text("")
    OK(f"Step: {label}")
    if not dry:
        send_telegram(f"[WIFI-CRACKER] \u25b6 START {label}")
    if dry:
        print(f"  (dry) hashcat -a 3 {' '.join(HC_BASE)} --potfile-path {potfile} {hash_path} {mask_string}")
        return
    with log.open("a") as f:
        subprocess.run(
            [HASHCAT, "-a", "3", *HC_BASE, f"--potfile-path={potfile}",
             str(hash_path), mask_string],
            stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.STDOUT)


# ---------------------------------------------------------------------------

def _finish(hash_path: Path, potfile: Path, dry: bool, _t0: float) -> str:
    """Classify a hash and notify Telegram with the outcome + elapsed time."""
    __r = classify(hash_path, potfile, dry)
    __dur = time.time() - _t0
    __msg = (f"[WIFI-CRACKER] DONE {hash_path.name}: " +
              ("CRACKED \u2705" if __r == "success" else "FAIL \u2716") +
              f" in {__dur/60:.1f} min")
    send_telegram(__msg)
    return __r


# Main pipeline
# ---------------------------------------------------------------------------
def crack_one(hash_path: Path, dry: bool = False) -> str:
    _t0 = time.time()
    """Run the full layered attack on one .22000. Returns 'success' or 'fail'."""
    if not hash_path.exists():
        ERR(f"hashfile not found: {hash_path}")
        return "fail"

    stem = hash_path.stem
    potfile = POTFILES / f"{stem}.potfile"
    # Ensure all work subdirs exist. The whole work/ dir is regenerable (logs,
    # potfiles, normalized masks), so if the user deleted it we recreate it here.
    for _d in (WORK, POTFILES, LOGDIR):
        _d.mkdir(parents=True, exist_ok=True)

    # If already cracked in a prior run (retry), report and classify immediately.
    if is_cracked(hash_path, potfile):
        WARN(f"Already cracked previously — classifying as success without re-running.")
        return _finish(hash_path, potfile, dry, _t0)

    OK(f"{'='*62}")
    OK(f"Hashfile : {hash_path.name}")
    OK(f"Potfile  : {potfile.name}")
    OK(f"{'='*62}")
    print()

    # --- normalize mask files (strip CRLF) ---
    M_MAIN = WORK / "vie-phonenumber_main.hcmask"
    M_SUB  = WORK / "vie-phonenumber_sub.hcmask"
    M_MISC = WORK / "vie-miscnumber.hcmask"
    for src, dst in [(DL_DIR/"vie-phonenumber_main.rule", M_MAIN),
                     (DL_DIR/"vie-phonenumber_sub.rule",  M_SUB),
                     (DL_DIR/"vie-miscnumber.rule",       M_MISC)]:
        if src.exists():
            n = normalize_crlf(src, dst)
    OK(f"Mask files normalized: main={mask_count(M_MAIN)}, sub={mask_count(M_SUB)}, misc={mask_count(M_MISC)}")
    print()

    # --- Phase A: rule/dict (cheap, high hit) ---
    if ROCKYOU.exists():
        run_dict_rule("A1_rockyou_best66", ROCKYOU, RULE_DIR/"best66.rule", hash_path, potfile, dry)
        if is_cracked(hash_path, potfile): return _finish(hash_path, potfile, dry, _t0)
    if PERS.exists():
        run_dict_rule("A2_vn_best66", PERS, RULE_DIR/"best66.rule", hash_path, potfile, dry)
        if is_cracked(hash_path, potfile): return _finish(hash_path, potfile, dry, _t0)
        run_dict_rule("A3_vn_leetspeak", PERS, RULE_DIR/"leetspeak.rule", hash_path, potfile, dry)
        if is_cracked(hash_path, potfile): return _finish(hash_path, potfile, dry, _t0)
    if ROCKYOU.exists():
        run_dict_rule("A4_rockyou_leetspeak", ROCKYOU, RULE_DIR/"leetspeak.rule", hash_path, potfile, dry)
        if is_cracked(hash_path, potfile): return _finish(hash_path, potfile, dry, _t0)
        run_dict_rule("A5_rockyou_combinator", ROCKYOU, RULE_DIR/"combinator.rule", hash_path, potfile, dry)
        if is_cracked(hash_path, potfile): return _finish(hash_path, potfile, dry, _t0)

    # --- Phase B: wordlists ---
    b_list = [
        ("B1_common_date", DL_DIR/"vie-common_date.txt"),
        ("B2_vn1k",        VI_DIR/"wordlists-vn1k.txt"),
        ("B3_vn10k",       VI_DIR/"wordlists-vn10k.txt"),
        ("B4_vn1m",        VI_DIR/"wordlists-vn1m.txt"),
        ("B5_vn_wifi",     VI_DIR/"wordlists-vn-wifi.txt.txt"),
    ]
    for label, wl in b_list:
        if wl.exists():
            run_dict(label, wl, hash_path, potfile, dry)
            if is_cracked(hash_path, potfile): return _finish(hash_path, potfile, dry, _t0)

    # --- Phase C: masks ---
    for label, mf in [("C1_phone_main", M_MAIN), ("C2_phone_sub", M_SUB), ("C3_misc", M_MISC)]:
        if mf.exists() and run_maskfile(label, mf, hash_path, potfile, dry):
            return _finish(hash_path, potfile, dry, _t0)
    for label, mask in [("C4_8digit", "?d?d?d?d?d?d?d?d"), ("C5_leading0", "0?d?d?d?d?d?d?d")]:
        run_mask(label, mask, hash_path, potfile, dry)
        if is_cracked(hash_path, potfile): return _finish(hash_path, potfile, dry, _t0)

    WARN(f"No password recovered for {hash_path.name}.")
    WARN(f"Review logs: {LOGDIR}")
    return _finish(hash_path, potfile, dry, _t0)


def main(argv):
    dry = False
    bg  = False
    hash_file = None
    args = [a for a in argv[1:] if a not in ("--dry", "--background")]
    if "--dry" in argv: dry = True
    if "--background" in argv: bg = True
    if args:
        hash_file = Path(args[0]).expanduser()

    if bg and not hash_file:
        # run 'all pending' detached; log to work/crack.log
        logf = WORK / "crack.log"
        logf.parent.mkdir(parents=True, exist_ok=True)
        print(f"Starting background run → logging to {logf}")
        with logf.open("a") as f:
            n = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), *args],
                                 stdout=f, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL, start_new_session=True)
        print(f"PID {n.pid}")
        return 0

    OK("=== WPA2 crack pipeline (rule-based + masks) ===")
    if hash_file:
        OK(f"Mode: SINGLE → {hash_file}")
        crack_one(hash_file, dry)
        return 0

    OK("Mode: ALL → cracking every pending hash sequentially")
    print()
    pending = sorted(PENDING.glob("*_hs.22000"))
    if not pending:
        WARN("No *_hs.22000 files in handshakes/pending.")
        WARN("Drop a .pcap + _hs.22000 into pending/, or pass a file path.")
        return 0
    OK(f"Found {len(pending)} pending hash(es).")
    print()

    summary = {"success": 0, "fail": 0}
    for h in pending:
        result = crack_one(h, dry)
        summary[result] += 1
        print()

    print("=" * 62)
    OK(f"Done. success={summary['success']}  fail={summary['fail']}")
    print(f"  success → {SUCCESS}")
    print(f"  fail    → {FAIL}")
    print("=" * 62)
    send_telegram(
        f"[WIFI-CRACKER] RUN FINISHED ✨  success={summary['success']}  fail={summary['fail']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
