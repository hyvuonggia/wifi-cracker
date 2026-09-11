#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wpasec.py — đẩy / kéo wpa-sec (wpa-sec.stanev.org)

Chia việc với pipeline local: cái gì pipeline local KHÔNG làm được (từ điển
generic khổng lồ + toàn bộ 8 số + WPSkey + cracked.txt động) thì để wpa-sec gặm.

KEY: đọc từ env WPASEC_KEY, hoặc file ~/wifi-cracker/.wpasec_key (gitignore, chmod 600).
KHÔNG hardcode key vào file này — repo WiFi-cracker là PUBLIC.

API (đã đối chiếu source server dwpa/web/content/submit.php + common.php):
  - upload : POST https://wpa-sec.stanev.org/?submit
             multipart/form-data, field name = "webfile"
             Cookie: key=<32 hex>   (common.php: $userkey = $_COOKIE['key'])
             server CHỈ nhận pcap native / pcapng  -> KHÔNG gửi .22000
  - kết quả: GET  https://wpa-sec.stanev.org/?api&dl=1  + Cookie key=<hex>

Dùng:
    ./wpasec.py pull                      # tải mật khẩu đã crack về
    ./wpasec.py push capture.pcap         # gửi 1 pcap
    ./wpasec.py push handshakes/fail/     # gửi mọi .pcap trong thư mục (đệ quy)
    ./wpasec.py status                    # kiểm tra key + thống kê
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

BASE = Path.home() / "wifi-cracker"
WPASEC_KEY_FILE = BASE / ".wpasec_key"
UPLOADED_LOG = BASE / "work" / "wpasec_uploaded.txt"
RESULTS_FILE = BASE / "work" / "wpasec_results.txt"

HOST = "wpa-sec.stanev.org"
SUBMIT_URL = f"https://{HOST}/?submit"
POTFILE_URL = f"https://{HOST}/?api&dl=1"
TIMEOUT = 180

# pcap native / pcapng — thứ server thực sự nhận
CAPTURE_EXT = (".pcap", ".pcapng", ".cap")


def key() -> str | None:
    """Key 32 hex. env WPASEC_KEY > ~/wifi-cracker/.wpasec_key. None nếu chưa có."""
    k = os.environ.get("WPASEC_KEY", "").strip()
    if not k:
        try:
            k = WPASEC_KEY_FILE.read_text().strip()
        except Exception:
            return None
    if not k:
        return None
    if not re.fullmatch(r"[0-9a-fA-F]{32}", k):
        print(f"  ! key sai định dạng (cần 32 ký tự hex, đang có {len(k)})", file=sys.stderr)
        return None
    return k


def _require_key() -> str:
    k = key()
    if not k:
        sys.exit(
            "Chưa có key wpa-sec.\n"
            f"  Lấy key: https://wpa-sec.stanev.org/?get_key\n"
            f"  Rồi:    printf '%s' '<key-32-hex>' > {WPASEC_KEY_FILE} && chmod 600 {WPASEC_KEY_FILE}\n"
            "  (hoặc: export WPASEC_KEY=<key>)"
        )
    return k


# ---------------------------------------------------------------------------
# Upload tracking — tránh gửi trùng (server cũng dedup theo hash, nhưng đỡ tốn)
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
    """Dựng body multipart/form-data + boundary (thuần stdlib)."""
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
    """Gửi 1 file capture lên wpa-sec. True nếu server nhận."""
    k = k or _require_key()
    if not pcap.exists():
        print(f"  ! không có file: {pcap}")
        return False
    if pcap.suffix.lower() not in CAPTURE_EXT:
        print(f"  ! {pcap.name}: server chỉ nhận {', '.join(CAPTURE_EXT)} — bỏ qua")
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
        if e.code == 409:                      # đã gửi trước đó
            _mark_uploaded(pcap.name)
            if not quiet:
                print(f"  = {pcap.name}: đã có trên server (409)")
            return True
        print(f"  ! {pcap.name}: HTTP {e.code} {e.reason}")
        return False
    except Exception as e:
        print(f"  ! {pcap.name}: {type(e).__name__}: {e}")
        return False

    # Server in kết quả trong <pre>
    m = re.search(r"<pre>(.*?)</pre>", text, re.S)
    summary = (m.group(1).strip() if m else text.strip())[:400]
    bad = "not a valid capture" in summary.lower()
    if bad:
        print(f"  ! {pcap.name}: server từ chối — {summary}")
        return False
    _mark_uploaded(pcap.name)
    if not quiet:
        print(f"  + {pcap.name}: OK — {summary or 'đã nhận'}")
    return True


def find_capture_for(hash_path: Path) -> Path | None:
    """Với 1 file _hs.22000, tìm .pcap đi kèm (server cần pcap, không nhận 22000)."""
    stem = hash_path.name
    for suf in ("_hs.22000", ".22000", ".hccapx"):
        if stem.endswith(suf):
            stem = stem[: -len(suf)]
            break
    for cand in (hash_path.with_name(stem + ".pcap"),
                 hash_path.with_name(stem + ".pcapng"),
                 hash_path.with_suffix(".pcap")):
        if cand.exists():
            return cand
    return None


def push_path(target: Path) -> int:
    """Gửi 1 file hoặc cả thư mục. Trả về số file gửi thành công."""
    k = _require_key()
    if target.is_dir():
        files = sorted(p for p in target.rglob("*") if p.suffix.lower() in CAPTURE_EXT)
    elif target.suffix.lower() == ".22000":
        p = find_capture_for(target)
        if not p:
            print(f"  ! {target.name}: không thấy .pcap đi kèm.")
            print("    Server wpa-sec KHÔNG nhận .22000 — cần giữ file .pcap gốc từ PorkChop.")
            return 0
        files = [p]
    else:
        files = [target]

    if not files:
        print(f"  (không có file capture nào trong {target})")
        return 0

    done = _load_uploaded()
    ok = 0
    print(f"Gửi {len(files)} file lên {HOST} ...")
    for f in files:
        if f.name in done:
            print(f"  = {f.name}: đã gửi trước đó, bỏ qua")
            continue
        if push_file(f, k):
            ok += 1
    print(f"→ xong: {ok}/{len(files)} gửi mới")
    return ok


# ---------------------------------------------------------------------------
# Pull kết quả đã crack
# ---------------------------------------------------------------------------
def pull() -> int:
    k = _require_key()
    req = urllib.request.Request(POTFILE_URL, headers={"Cookie": f"key={k}",
                                                       "User-Agent": "wifi-cracker/wpasec.py"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            data = r.read().decode("utf-8", "replace")
    except Exception as e:
        print(f"  ! không tải được kết quả: {type(e).__name__}: {e}")
        return 0
    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_FILE.write_text(data)
    lines = [ln for ln in data.splitlines() if ln.strip()]
    print(f"Đã lưu {len(lines)} dòng vào {RESULTS_FILE}")
    if lines:
        print("Mật khẩu wpa-sec đã tìm được cho bạn:")
        for ln in lines[:40]:
            # định dạng potfile: <hash>*<essid>:<pass>
            print("   " + ln)
        if len(lines) > 40:
            print(f"   ... và {len(lines)-40} dòng nữa")
    else:
        print("(chưa có kết quả nào — key mới hoặc các mạng chưa crack xong)")
    return len(lines)


def status() -> int:
    k = key()
    if not k:
        print("Trạng thái: CHƯA cấu hình key")
        print(f"  → printf '%s' '<key>' > {WPASEC_KEY_FILE} && chmod 600 {WPASEC_KEY_FILE}")
        return 1
    print(f"Trạng thái: key OK ({k[:8]}…{k[-4:]})")
    print(f"  file key : {WPASEC_KEY_FILE}")
    print(f"  đã gửi   : {len(_load_uploaded())} file (log: {UPLOADED_LOG})")
    if RESULTS_FILE.exists():
        n = len([l for l in RESULTS_FILE.read_text().splitlines() if l.strip()])
        print(f"  kết quả  : {n} dòng trong {RESULTS_FILE}")
    print(f"  tải kết quả: {POTFILE_URL}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="wpa-sec push/pull (wpa-sec.stanev.org)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("push", help="gửi capture .pcap lên wpa-sec")
    p.add_argument("target", type=Path, help="file .pcap hoặc thư mục")
    sub.add_parser("pull", help="tải mật khẩu wpa-sec đã crack về")
    sub.add_parser("status", help="kiểm tra key + thống kê")
    a = ap.parse_args(argv)

    if a.cmd == "push":
        return 0 if push_path(a.target.expanduser()) else 1
    if a.cmd == "pull":
        pull()
        return 0
    return status()


if __name__ == "__main__":
    sys.exit(main())
