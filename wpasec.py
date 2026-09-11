#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wpasec.py -- push / pull client for wpa-sec (wpa-sec.stanev.org).

Splitting the work with the local pipeline: whatever the local box CANNOT do
(the huge generic dictionaries, the complete 8-digit space, WPSkey, the dynamic
cracked.txt) is handed to wpa-sec's volunteer GPUs. The local box keeps the
Vietnamese layers, which the server has nothing for.

KEY: read from the WPASEC_KEY environment variable, or from
     ~/wifi-cracker/.wpasec_key  (gitignored, chmod 600).
     NEVER hardcode a key in this file -- this repository is PUBLIC.
     Get a key at https://wpa-sec.stanev.org/?get_key

API (verified against the server source, dwpa/web/content/submit.php + common.php):
  - upload : POST https://wpa-sec.stanev.org/?submit
             multipart/form-data, field name "webfile"
             Cookie: key=<32 hex>   (common.php: $userkey = $_COOKIE['key'])
             the server accepts native pcap / pcapng ONLY -> never send .22000
  - results: GET  https://wpa-sec.stanev.org/?api&dl=1  + Cookie key=<hex>

Usage:
    ./wpasec.py pull                       # download passwords already cracked
    ./wpasec.py push capture.pcap          # upload one capture
    ./wpasec.py push handshakes/fail/      # upload every .pcap in a folder (recursive)
    ./wpasec.py status                     # check the key + counters

NOTE: wpa-sec results are public and searchable by BSSID+SSID. Never upload your
own home network -- lab captures only.
"""
from __future__ import annotations

import argparse
import mimetypes
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from uuid import uuid4

BASE = Path(os.environ.get("WIFI_CRACKER_DIR", "") or (Path.home() / "wifi-cracker"))
WPASEC_KEY_FILE = BASE / ".wpasec_key"
UPLOADED_LOG = BASE / "work" / "wpasec_uploaded.txt"
RESULTS_FILE = BASE / "work" / "wpasec_results.txt"

HOST = "wpa-sec.stanev.org"
SUBMIT_URL = f"https://{HOST}/?submit"
POTFILE_URL = f"https://{HOST}/?api&dl=1"
TIMEOUT = 180

# native pcap / pcapng -- what the server actually accepts
CAPTURE_EXT = (".pcap", ".pcapng", ".cap")


def key() -> str | None:
    """32 hex characters. env WPASEC_KEY > ~/wifi-cracker/.wpasec_key. None if unset."""
    k = os.environ.get("WPASEC_KEY", "").strip()
    if not k:
        try:
            k = WPASEC_KEY_FILE.read_text().strip()
        except Exception:
            return None
    if not k:
        return None
    if not re.fullmatch(r"[0-9a-fA-F]{32}", k):
        print(f"  ! malformed key (need 32 hex characters, got {len(k)})", file=sys.stderr)
        return None
    return k


def _require_key() -> str:
    k = key()
    if not k:
        sys.exit(
            "No wpa-sec key configured.\n"
            f"  Get one: https://wpa-sec.stanev.org/?get_key\n"
            f"  Then:    printf '%s' '<32-hex-key>' > {WPASEC_KEY_FILE} && chmod 600 {WPASEC_KEY_FILE}\n"
            "  (or: export WPASEC_KEY=<key>)"
        )
    return k


# ---------------------------------------------------------------------------
# Upload tracking -- avoids re-sending (the server also dedupes by hash)
# ---------------------------------------------------------------------------
def _load_uploaded() -> set[str]:
    try:
        return {ln.strip() for ln in UPLOADED_LOG.read_text().splitlines() if ln.strip()}
    except Exception:
        return set()


def _mark_uploaded(name: str) -> None:
    UPLOADED_LOG.parent.mkdir(parents=True, exist_ok=True)
    with UPLOADED_LOG.open("a") as f:
        f.write(name + "\n")


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------
def _multipart(field: str, filepath: Path):
    """Build a multipart/form-data body + boundary (pure stdlib)."""
    boundary = "----WiFiCracker" + uuid4().hex
    ctype = mimetypes.guess_type(filepath.name)[0] or "application/octet-stream"
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field}"; filename="{filepath.name}"\r\n'
        f"Content-Type: {ctype}\r\n\r\n"
    ).encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    return boundary, head + filepath.read_bytes() + tail


def push_file(pcap: Path, k: str | None = None, quiet: bool = False) -> bool:
    """Upload one capture to wpa-sec. True when the server accepted it."""
    k = k or _require_key()
    if not pcap.exists():
        print(f"  ! no such file: {pcap}")
        return False
    if pcap.suffix.lower() not in CAPTURE_EXT:
        print(f"  ! {pcap.name}: the server only accepts {', '.join(CAPTURE_EXT)} -- skipped")
        return False

    boundary, body = _multipart("webfile", pcap)
    req = urllib.request.Request(
        SUBMIT_URL,
        data=body,
        method="POST",
        headers={
            "Cookie": f"key={k}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
            "User-Agent": "wifi-cracker/wpasec.py",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            code, text = r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        if e.code == 409:                      # already submitted before
            _mark_uploaded(pcap.name)
            if not quiet:
                print(f"  = {pcap.name}: already on the server (409)")
            return True
        print(f"  ! {pcap.name}: HTTP {e.code} {e.reason}")
        return False
    except Exception as e:
        print(f"  ! {pcap.name}: {type(e).__name__}: {e}")
        return False

    # The server prints its verdict inside <pre>
    m = re.search(r"<pre>(.*?)</pre>", text, re.S)
    summary = (m.group(1).strip() if m else text.strip())[:400]
    bad = "not a valid capture" in summary.lower()
    if bad:
        print(f"  ! {pcap.name}: server rejected it -- {summary}")
        return False
    _mark_uploaded(pcap.name)
    if not quiet:
        print(f"  + {pcap.name}: OK -- {summary or 'accepted'}")
    return True


def find_capture_for(hash_path: Path) -> Path | None:
    """The capture belonging to a <base>_hs.22000 file (the server needs pcap, not 22000)."""
    stem = hash_path.name
    for suf in ("_hs.22000", ".22000", ".hc22000", ".hccapx"):
        if stem.endswith(suf):
            stem = stem[: -len(suf)]
            break
    for cand in (hash_path.with_name(stem + ".pcap"),
                 hash_path.with_name(stem + ".pcapng"),
                 hash_path.with_name(stem + ".cap"),
                 hash_path.with_suffix(".pcap")):
        if cand.exists():
            return cand
    return None


def push_path(target: Path) -> int:
    """Upload one file or a whole folder. Returns the number of new uploads."""
    k = _require_key()
    if target.is_dir():
        files = sorted(p for p in target.rglob("*") if p.suffix.lower() in CAPTURE_EXT)
    elif target.suffix.lower() in (".22000", ".hc22000"):
        p = find_capture_for(target)
        if not p:
            print(f"  ! {target.name}: no .pcap next to it.")
            print("    wpa-sec does NOT accept .22000 -- keep the original .pcap from Porkchop.")
            return 0
        files = [p]
    else:
        if target.suffix.lower() not in CAPTURE_EXT:
            print(f"  ! {target.name}: not a capture ({', '.join(CAPTURE_EXT)}) -- nothing to upload")
            return 0
        files = [target]

    if not files:
        print(f"  (no capture files in {target})")
        return 0

    done = _load_uploaded()
    ok = 0
    print(f"Uploading {len(files)} file(s) to {HOST} ...")
    for f in files:
        if f.name in done:
            print(f"  = {f.name}: already uploaded, skipped")
            continue
        if push_file(f, k):
            ok += 1
    print(f"-> done: {ok}/{len(files)} new upload(s)")
    return ok


# ---------------------------------------------------------------------------
# Pull cracked results
# ---------------------------------------------------------------------------
def pull() -> int:
    k = _require_key()
    req = urllib.request.Request(POTFILE_URL, headers={"Cookie": f"key={k}",
                                                       "User-Agent": "wifi-cracker/wpasec.py"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            data = r.read().decode("utf-8", "replace")
    except Exception as e:
        print(f"  ! could not download results: {type(e).__name__}: {e}")
        return 0
    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_FILE.write_text(data)
    lines = [ln for ln in data.splitlines() if ln.strip()]
    print(f"Saved {len(lines)} line(s) to {RESULTS_FILE}")
    if lines:
        print("Passwords wpa-sec found for your uploads:")
        for ln in lines[:40]:
            # potfile format: <hash>*<essid>:<pass>
            print("   " + ln)
        if len(lines) > 40:
            print(f"   ... and {len(lines)-40} more")
    else:
        print("(no results yet -- new key, or your captures have not been reached in the queue)")
    return len(lines)


def status() -> int:
    k = key()
    if not k:
        print("Status: NO key configured")
        print(f"  -> printf '%s' '<key>' > {WPASEC_KEY_FILE} && chmod 600 {WPASEC_KEY_FILE}")
        return 1
    print(f"Status: key OK ({k[:8]}...{k[-4:]})")
    print(f"  key file  : {WPASEC_KEY_FILE}")
    print(f"  uploaded  : {len(_load_uploaded())} file(s) (log: {UPLOADED_LOG})")
    if RESULTS_FILE.exists():
        n = len([l for l in RESULTS_FILE.read_text().splitlines() if l.strip()])
        print(f"  results   : {n} line(s) in {RESULTS_FILE}")
    print(f"  results URL: {POTFILE_URL}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="wpa-sec push/pull (wpa-sec.stanev.org)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("push", help="upload a .pcap capture to wpa-sec")
    p.add_argument("target", type=Path, help=".pcap file or a folder")
    sub.add_parser("pull", help="download passwords wpa-sec already cracked")
    sub.add_parser("status", help="check the key + counters")
    a = ap.parse_args(argv)

    if a.cmd == "push":
        return 0 if push_path(a.target.expanduser()) else 1
    if a.cmd == "pull":
        pull()
        return 0
    return status()


if __name__ == "__main__":
    sys.exit(main())
