# Wi-Fi Cracker — WPA/WPA2 handshake cracking, pcap-first

Drop a **`.pcap`** capture in, get the passphrase out.

This tool converts your capture to a hashcat hash file with `hcxpcapngtool`
(hcxtools), attacks it with **hashcat** on a **Dell Precision 7520** (CachyOS/Arch,
GPU **Quadro M2200** over OpenCL, ~**94k H/s** at `-m 22000`), and hands whatever
it cannot crack to **wpa-sec.stanev.org** for the volunteer queue to chew on.

The pipeline is deliberately **rule-based first, wordlists second, masks last**,
because real passphrases are a word plus a small variation (`trung123`,
`Trung@2026`, `hoang1234`) rather than random noise — a rule attack beats a mask
attack over the same keyspace.

> ⚠️ **Only crack networks and machines you own or are licensed to test.**
> Capturing a stranger's handshake and cracking it is unauthorised access
> (Article 291 of the Vietnamese Penal Code). Use your own lab: one phone as a
> hotspot, one phone as the victim.

---

## 1. What it does, end to end

```
 handshakes/pending/ANH HY_FC4009E1E14E.pcap
              │
              │  ① hcxpcapngtool   (pcap/pcapng -> hashcat -m 22000)
              ▼
        ANH HY_FC4009E1E14E_hs.22000  +  work/essids/<name>.essid
              │
              │  ② hashcat -m 22000   (layered: rules -> wordlists -> masks)
              ▼
   cracked ──► handshakes/success/      (+ password in work/potfiles/<stem>.potfile)
   not cracked ──► ③ upload the .pcap to wpa-sec  ──►  handshakes/fail/
```

The original capture is **kept next to the hash file** and travels with it,
because **wpa-sec accepts `.pcap`/`.pcapng` and NOT `.22000`** — its conversion
step rejects an already-converted file.

---

## 2. Requirements

| Need | Why | Install |
|---|---|---|
| `hashcat` 6.x or 7.x | the cracking engine | Arch/CachyOS `sudo pacman -S hashcat` · Debian/Ubuntu `sudo apt install hashcat` |
| `hcxpcapngtool` (hcxtools) | converts the capture to `.22000` | Arch `sudo pacman -S hcxtools` · Debian/Ubuntu `sudo apt install hcxtools` |
| `python3` (3.10+) | runs `crack.py` / `wpasec.py` | usually already there |
| working OpenCL GPU | real cracking speeds | Arch: `nvidia-utils` provides OpenCL; otherwise `ocl-icd` |
| a wpa-sec key | hands the rest of the keyspace to the queue | https://wpa-sec.stanev.org/?get_key → save to `~/wifi-cracker/.wpasec_key` (chmod 600) |

`crack_all.sh` checks all of this for you and installs what is missing (it
detects apt / dnf / yum / pacman / zypper / apk).

With the default settings **you do not need `rockyou.txt`** (134 MB) — it is only
used by `--full`, and `crack_all.sh` downloads it on demand.

---

## 3. Repository layout

```
wifi-cracker/
├── crack.py                 # the pipeline (pcap -> 22000 -> crack -> classify -> wpa-sec)
├── wpasec.py                # manual wpa-sec client: status | push <file|dir> | pull
├── crack_all.sh             # entry point: environment check + install + hand off to crack.py
├── requirements.txt
├── handshakes/
│   ├── pending/             # DROP NEW CAPTURES HERE (.pcap / .pcapng / .cap)
│   ├── success/             # cracked  -> password recovered (moved automatically)
│   └── fail/                # not cracked locally (moved automatically)
├── wordlists/
│   ├── rockyou.txt          # NOT committed (134 MB > GitHub limit) -> crack_all.sh fetches it
│   ├── vn-heavy.rule        # 446 Vietnamese rules  -> SMALL wordlists
│   ├── vn-lite.rule         #  63 Vietnamese rules  -> LARGE wordlists
│   ├── vie_wpa2_pw/         # VN leaked passwords + VN phone mask files (cloned from GitHub)
│   └── wordlists-vi/        # VN general wordlists (cloned from GitHub)
└── work/                    # scratch, NOT committed (gitignored)
    ├── potfiles/            # one potfile PER HASH — the source of truth for success/fail
    ├── logs/                # one log per layer (S1, A2, B1, C1, ...)
    ├── essids/              # ESSID wordlist produced by the conversion step
    └── nohandshake.txt      # captures that contained no EAPOL/PMKID
```

`handshakes/`, `wordlists/` and the scripts are committed (one-stop repo).
`work/` and anything large/cached is gitignored.

---

## 4. Quick start

```bash
# 1. one-time
git clone https://github.com/hyvuonggia/wifi-cracker.git ~/wifi-cracker
cd ~/wifi-cracker
printf '%s' '<your-32-hex-key>' > .wpasec_key && chmod 600 .wpasec_key   # key from wpa-sec.stanev.org/?get_key

# 2. drop a capture in the queue
cp /run/media/sdcard/ANH\ HY_FC4009E1E14E.pcap ~/wifi-cracker/handshakes/pending/

# 3. run it (converts, cracks, classifies, hands the rest to wpa-sec)
./crack_all.sh --background     # detached, progress logged to work/crack.log
```

Look at the result with:

```bash
ls ~/wifi-cracker/handshakes/success/          # cracked captures
hashcat -m 22000 --potfile-path ~/wifi-cracker/work/potfiles/<stem>.potfile --show <file.22000>
```

---

## 5. Division of labour with wpa-sec — this is the DEFAULT

Cracking the same keyspace twice is pure waste. `wpa-sec.stanev.org` already
covers a big generic dictionary set, the complete 8-digit space and the WPS keys,
so **the local machine by default only runs the layers wpa-sec cannot do**, and
uploads every capture it could not crack.

| Layer | wpa-sec already has it? | Who runs it by default |
|---|---|---|
| `S1` SSID-as-password | no — only your own capture knows the ESSID | **local** |
| `A2` VN leaked dict + `vn-heavy.rule` | no VN rules server-side | **local** |
| `A3` VN leaked dict + `leetspeak` | no VN data server-side | **local** |
| `B1`–`B7` VN wordlists (dates, vn1k/10k/1m/wifi + rules) | no VN dictionaries server-side | **local** |
| `C1`–`C3` Vietnamese phone masks (10 digits) | wpa-sec's `Num8` is 8 digits only | **local** |
| `A1`/`A4`/`A5` rockyou + rules | yes (hashes.org, OffSec 33M, InsidePro, Wikipedia ×5, OpenWall) | wpa-sec |
| `C4`/`C5` any 8 digits / 8 digits starting with 0 | yes (`Num8` = the whole 10⁸ space) | wpa-sec |
| everything still unsolved | — | wpa-sec queue, 24/7 |

* **`--full`** runs the wpa-sec-covered layers locally as well (the old behaviour).
* **`--no-wpasec`** never uploads; local only.
* Skipping rockyou + the 8-digit masks saves **~5 hours per hash** on a Quadro
  M2200 (see the budget table below) and removes the need for `rockyou.txt`.

**Privacy:** wpa-sec results are public and searchable by BSSID+SSID. Upload lab
captures, never your own home network.

---

## 6. Layer reference and cost

Keyspaces/seconds assume **94k H/s** (`-m 22000`, Quadro M2200, OpenCL).

| Step | What it is | Keys | Time |
|---|---|---|---|
| `S1` | the ESSID itself + `vn-heavy.rule` | ~450 | instant |
| `A2` | 384,189 leaked VN passwords × 446 VN rules | 171 M | **30 min** |
| `A3` | 384,189 VN × `leetspeak` (25 rules) | 9.6 M | 1.7 min |
| `B1` | common date patterns (`vie-common_date`, 44,736 lines) | 45 k | instant |
| `B2`–`B5` | vn1k / vn10k / vn1m / vn-wifi wordlists | 1.4 M | ~20 s |
| `B6` | vn-wifi (418k) × `vn-lite` (63 rules) | 26 M | 4.7 min |
| `B7` | vn10k × `vn-heavy` (446 rules) | 4.5 M | 0.8 min |
| `C1` | 27 VN phone prefixes × 10⁷ (10-digit numbers) | 270 M | **48 min** |
| `C2` | 12 more prefixes × 10⁷ | 120 M | **21 min** |
| `C3` | hotline / misc numbers | 10 k | instant |
| **local default total** | | | **~1.8 h per hash** |
| `A1` rockyou (14.3 M) × `best66` (78) | *`--full` only* | 1.1 B | 198 min |
| `A4` rockyou × `leetspeak` | *`--full` only* | 359 M | 64 min |
| `C4`/`C5` 8-digit masks | *`--full` only* | 200 M | 36 min |
| **`--full` total** | | | **~6.7 h per hash** |

The run **stops at the first hit**, so a password that shows up in `S1` costs
milliseconds, not hours. `vn-heavy.rule` is for SMALL wordlists and `vn-lite.rule`
for LARGE ones — 446 rules × a million words would explode the keyspace.

---

## 7. Command line

```bash
./crack.py                       # convert + crack every pending capture
./crack.py "capture.pcap"        # one capture (a bare .22000 works too)
./crack.py --background          # detached; log to work/crack.log
./crack.py --dry                 # print every command, touch nothing
./crack.py --convert-only        # only pcap -> _hs.22000 (no cracking)
./crack.py --full                # also run the layers wpa-sec covers
./crack.py --no-wpasec           # never upload to wpa-sec
./crack.py --vn-only             # accepted for compatibility (= default)
```

| Flag | Effect |
|---|---|
| *(none)* | local = layers wpa-sec does **not** cover, upload failures to wpa-sec |
| `--full` | local = **every** layer, including the wpa-sec-covered ones |
| `--no-wpasec` | disable the upload |
| `--dry` | print the plan, never write or move a file |
| `--convert-only` | just run `hcxpcapngtool`, exit |
| `--background` | detach (use this for long runs) |
| `--vn-only`, `--wpasec` | legacy flags, now the default behaviour |

Same command line works through the wrapper: `./crack_all.sh --background`.

### Naming convention

```
  capture:  <base>.pcap          hash:  <base>_hs.22000
            ANH HY_FC4009E1E14E.pcap  ->  ANH HY_FC4009E1E14E_hs.22000
```

The pair is derived from the file name, which is why the two names must stay
together: `*_hs.22000` is how the upload step finds the `.pcap` to send. If you
drop in only a `.22000`, cracking still works but wpa-sec cannot be used for it.

---

## 8. Capturing a handshake (Porkchop on the Cardputer)

1. Porkchop → **OINK** → pick the target → deauth → capture a complete 4-way
   handshake or a PMKID → eject the SD card.
2. Copy the **`.pcap`** to `~/wifi-cracker/handshakes/pending/`.
   (If Porkchop also wrote a `_hs.22000`, copy it too — the pipeline re-generates
   it from the `.pcap` anyway.)
3. Run `./crack_all.sh --background`.

If the capture contains **no EAPOL/PMKID at all**, the pipeline says so, logs the
file to `work/nohandshake.txt`, and moves it to `fail/` — re-capture with a longer
deauth or wait for the client to reconnect.

---

## 9. Where the recovered passwords are

* **One potfile per hash:** `work/potfiles/<stem>.potfile` — `hash:password` lines.
  This is deliberate: a single shared potfile is what made the older bash script
  report a false "cracked" whenever a stale password was still in it.
* Show one hash's password:
  ```bash
  hashcat -m 22000 --potfile-path work/potfiles/<stem>.potfile --show <file.22000>
  ```
* Passwords recovered by wpa-sec (after a pull): `work/wpasec_results.txt`.
* Captures are filed automatically: `handshakes/success/` vs `handshakes/fail/`.

---

## 10. Manual wpa-sec client

```bash
./wpasec.py status                    # key check + counters
./wpasec.py push handshakes/fail/      # upload every .pcap that was not sent yet
./wpasec.py push capture.pcap          # upload a single capture
./wpasec.py pull                      # download passwords already cracked for you
```

The key comes from `WPASEC_KEY` or `~/wifi-cracker/.wpasec_key` (gitignored,
chmod 600). **Never commit the key** — this repository is public. Uploads are
tracked in `work/wpasec_uploaded.txt` so nothing is sent twice (the server also
answers `409` for a duplicate).

---

## 11. Improvements over the old bash-only `crack_all.sh`

| Problem | Old bash | This Python pipeline |
|---|---|---|
| No conversion step: you had to convert the pcap yourself | ⚠️ | ✅ `hcxpcapngtool` runs inside the pipeline, and a capture with no handshake is reported instead of silently failing |
| `is_cracked()` used **one shared potfile** → a stale password from another hash made it stop early and mis-classify | ⚠️ | ✅ **one potfile per hash**, matched with `hashcat --show` |
| `--dry` still moved files | ⚠️ | ✅ dry mode never touches the filesystem |
| Only one file per run, manual classification | ⚠️ | ✅ all-pending + single-file modes, automatic success/fail filing |
| Rule directory hardcoded and rule named `best66.rule` on hashcat 6 (where it does not exist) → **the whole Phase A was dead code and never ran** | ⚠️ | ✅ rules are resolved at runtime (`best66.rule` *or* `best64.rule`, whichever exists), every resolved path is printed, and a missing rule warns loudly instead of silently skipping a layer |
| Re-cracking keyspace wpa-sec already covers | ⚠️ | ✅ local runs only the VN/SSID/phone layers by default, the rest is uploaded |
| `mask_count()` crashed the entire run on a missing mask file (`FileNotFoundError`) | ⚠️ | ✅ every helper is guarded against missing files |

---

## 12. Troubleshooting

* **"SKIP <layer>: rule file not found"** — the pipeline prints the resolved rule
  paths in the banner. hashcat 7.x ships `best66.rule`, hashcat 6.x ships
  `best64.rule`; both are accepted. If you see `NONE FOUND`, install the rules or
  copy them into `wordlists/`.
* **A layer "ran" but did nothing** — a missing rule file is not an error to
  hashcat, it just runs zero keys. Always run `--dry` after changing the pipeline
  and count the layers that were actually emitted.
* **Everything is slow on a CPU-only box** (e.g. the Hermes LXC) — that is
  expected: use a CPU box to *prepare* wordlists and rules, and the M2200 to
  crack. Real numbers above assume the GPU.
* **`.22000` cannot be uploaded to wpa-sec** — correct, it only accepts native
  `.pcap`/`.pcapng`. Keep the original capture.
* **`hcxpcapngtool` appends to its output files.** Running it twice on the same
  capture doubles the hash lines, so the pipeline deletes the outputs first.
  Never call it twice by hand into the same file.
* **The laptop suspends / blackscreens mid-crack** — `crack.py` wraps every
  hashcat call in `systemd-inhibit --what=idle --mode=block`, so the idle lock
  is held for exactly as long as hashcat runs (the banner prints whether the
  inhibition is active). Without that, `systemd-logind` sees a headless machine
  and suspends it mid-crack; on this laptop a suspend hangs the GPU (failing BGA
  joint) and needs a reboot.
* **`work/crack.log` stays empty during a `--background` run** — the child is
  now spawned with `-u`/`PYTHONUNBUFFERED=1`, so `tail -f work/crack.log` shows
  progress live. (A Python process whose stdout is a file or pipe block-buffers
  4–8 KB before anything appears, which is what made the old log look frozen.)
* **A 0-try capture for the wrong reason** — Porkchop sometimes writes a `.pcap`
  with only the beacon. Check `work/nohandshake.txt`.

---

## 13. Legal

Only ever captive/crack your own networks or a lab you are authorised to test.
Capturing a third party's handshake and cracking it is a criminal offence in
Vietnam (Article 291) and in most other jurisdictions. The two-phone lab (one
hotspot, one victim) is the right place to learn this.
