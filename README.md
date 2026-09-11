# Wi-Fi Cracker — WPA/WPA2 .22000 pipeline

Crack WPA/WPA2 handshakes & PMKID (`.22000` trích từ Porkchop / Cardputer) bằng
**hashcat** trên máy **Dell Precision 7520** (CachyOS/Arch, GPU **Quadro M2200**
qua OpenCL ~**94k H/s**).

Pipeline thiết kế **rule-based trước, wordlist giữa, mask cuối** — vì pass thật
người Việt hầu hết là **từ + biến thể nhỏ** (`trung123`, `Trung@2026`,
`hoang1234`) chứ không phải số thuần. Rule attack trúng cao hơn bruteforce.

> ⚠️ **Chỉ crack mạng/máy bạn sở hữu hoặc được phép.** Bắt handshake + crack pass
> người khác = xâm nhập trái phép (Điều 291 Bộ luật Hình sự VN).

---

## Cấu trúc repo

```
wifi-cracker/
├── crack.py                  # Pipeline chính (Python) — 2 mode
├── requirements.txt          # hashcat 7.x trên Arch
├── handshakes/
│   ├── pending/              # hash mới, chưa thử — thả .pcap + _hs.22000 vào đây
│   ├── success/              # đã crack (có password) — tự động chuyển vào sau khi chạy
│   └── fail/                 # không crack được sau full pipeline — tự động chuyển vào
├── wordlists/
│   ├── rockyou.txt           # (KHÔNG commit — 134MB > giới hạn GitHub; crack_all.sh tự tải)
│   ├── vie_wpa2_pw/          # wordlist + mask VN (cloned, bỏ .git)
│   └── wordlists-vi/         # wordlist VN phổ thông (cloned, bỏ .git)
└── work/                     # tạm — KHÔNG commit (gitignore)
    ├── potfiles/             # 1 potfile riêng / hash — nguồn phân loại success/fail
    └── logs/                 # log từng layer (A1..C5)
```

- `handshakes/` + `wordlists/` + `crack.py` được **commit** (repo all-in-one).
- `work/` (**tạm**) và mọi file lớn/cache **gitignore**.
- `wordlists/` là từ 2 repo ngoài (vie_wpa2_pw, wordlists-vi) — đã **gỡ `.git`
  lồng nhau** để nằm gọn trong 1 repo.

---

## Cách dùng

### Mode 1: Crack tất cả pending (mặc định, không truyền tham số)

```bash
cd ~/wifi-cracker
python3 crack.py
```

Nó duyệt lần lượt mọi `*_hs.22000` trong `handshakes/pending/`, crack, rồi **tự
phân loại**: có pass → `success/`, không có → `fail/`. Sau mỗi lần chạy, thả
file mới vào `pending/` là lần chạy sau tự xử lý.

### Mode 2: Crack 1 file cụ thể (truyền tham số)

```bash
python3 crack.py "handshakes/pending/ANH HY_FC4009E1E14E_hs.22000"
```

Chỉ crack **file đó**, sau đó cũng tự phân loại (move sang success/fail).

### Chạy nền (để máy treo)

```bash
python3 crack.py --background          # crack mọi pending, log ra work/crack.log, chạy detach
python3 crack.py "file.22000" --background
```

### Dry-run (xem lệnh, không crack, KHÔNG đụng file)

```bash
python3 crack.py --dry                 # liệt kê lệnh cho mọi pending
python3 crack.py "file.22000" --dry    # liệt kê lệnh cho 1 file
```

> Dry-run **không di chuyển file** — chỉ in ra file sẽ được xếp vào success/fail.

### Chia việc với WPA-SEC (không làm trùng)

`wpa-sec.stanev.org` đã có sẵn kho từ điển generic khổng lồ (hashes.org, OffSec 33M,
InsidePro, Wikipedia ×5, OpenWall), **toàn bộ số 8 chữ số** (Num8) và khoá WPS mặc
định. Chạy lại mấy thứ đó ở máy là làm trùng — dùng 2 cờ này để chia việc:

```bash
python3 crack.py --vn-only                          # CHỈ chạy phần wpa-sec KHÔNG có
python3 crack.py --vn-only --wpasec                 # + tự đẩy .pcap lên wpa-sec khi fail
python3 crack.py --background --vn-only --wpasec    # combo khuyến nghị
```

| Tầng | Ai làm | Lý do |
|---|---|---|
| `A1`/`A4`/`A5` (rockyou + rule) | **wpa-sec** | kho generic khổng lồ |
| `C4`/`C5` (8 chữ số) | **wpa-sec** | Num8 = toàn bộ 10⁸ |
| `A2`/`A3` (VN + rule VN) | máy bạn | wpa-sec không có rule tiếng Việt |
| `B1`–`B7` (wordlist VN) | máy bạn | wpa-sec không có từ điển Việt |
| `C1`–`C3` (mask ĐT VN) | máy bạn | ĐT VN là **10 số**, wpa-sec chỉ có 8 số |

→ `--vn-only` tiết kiệm ~**7,4 giờ/hash** trên Quadro M2200, và **không cần tải
`rockyou.txt`** (134MB) nữa.

Thao tác tay với wpa-sec:

```bash
python3 wpasec.py status                  # kiểm tra key
python3 wpasec.py push handshakes/fail/   # đẩy mọi .pcap chưa gửi
python3 wpasec.py pull                    # tải mật khẩu wpa-sec đã tìm được
```

Key lấy ở https://wpa-sec.stanev.org/?get_key, lưu vào `~/wifi-cracker/.wpasec_key`
(chmod 600, đã gitignore) hoặc biến môi trường `WPASEC_KEY`. **Không commit file
key** — repo này là PUBLIC.

⚠️ Server wpa-sec **CHỈ nhận `.pcap`/`.pcapng`, KHÔNG nhận `.22000`** (nó chạy
`hcxpcapngtool`, tool này từ chối định dạng 22000). Phải giữ file `.pcap` gốc cạnh
file `_hs.22000`, nếu không thì không đẩy lên được.

---

## Cách capture handshake (từ Cardputer/Porkchop)

1. Porkchop **OINK** (quét) → chọn mạng mục tiêu → deauth → bắt đủ 4-way
   handshake / PMKID → cắm SD → copy file `.pcap` + `_hs.22000` về laptop.
2. Đặt vào `~/wifi-cracker/handshakes/pending/` (cả `.pcap` + `_hs.22000`).
3. Chạy `python3 crack.py`.

> Lưu ý: chỉ cần file `.22000` để crack; `.pcap` (bản gốc) được kéo theo để markup
> SSID/BSSID dễ đọc, và **bắt buộc giữ lại** nếu muốn đẩy lên wpa-sec (`--wpasec`
> hoặc `wpasec.py push`) — server chỉ nhận pcap, không nhận `.22000`.

---

## Chi tiết pipeline (thứ tự tấn công)

**Phase A — Ưu tiên tiếng Việt** (rẻ, tỉ lệ trúng cao nhất — chạy trước)
- `A2` VN leaked + `vn-heavy.rule` (446 rule: năm 1960–2029, đuôi số phổ biến,
  `@`/`.`/`_`/`-`, leet)
- `A3` VN leaked + `leetspeak.rule` (`trung@123` → `trung123`)

**Phase A′ — Generic** (wpa-sec ĐÃ CÓ → bỏ khi `--vn-only`)
- `A1` rockyou + `best64.rule` · `A4` rockyou + `leetspeak` · `A5` rockyou + `combinator`

**Phase B — Wordlist VN**
- `B1` ngày tháng `vie-common_date` · `B2` vn1k · `B3` vn10k · `B4` vn1m ·
  `B5` vn-wifi
- `B6` vn-wifi + `vn-lite.rule` · `B7` vn10k + `vn-heavy.rule`

**Phase C — Mask** (brute theo pattern — sau cùng, trúng thấp)
- `C1` phone VN main (28 prefix) · `C2` phone VN sub (13) · `C3` misc (hotline)
- `C4` 8-số bất kỳ · `C5` 8-số bắt đầu bằng 0 — *wpa-sec đã có (Num8) → bỏ khi `--vn-only`*

Pipeline **dừng ngay khi crack được** (tiết kiệm thời gian trên máy Quadro).

> `vn-heavy.rule` (446 rule) dùng cho wordlist **NHỎ**, `vn-lite.rule` (63 rule)
> cho wordlist **LỚN** — nhiều rule × wordlist lớn = nổ không gian khoá. Cả 2 file
> nằm trong `wordlists/`. Rule sinh từ **384.189 mật khẩu VN bị lộ**, đã tự kiểm
> cú pháp bằng hashcat (0 lỗi).

---

## Cải tiến so với phiên bản bash `crack_all.sh`

| Vấn đề | Bash cũ | Python mới |
|---|---|---|
| `is_cracked()` dùng **potfile chung** → tưởng nhầm đã crack nếu potfile còn pass file trước, dừng sớm + phân loại sai | ⚠️ &nbsp;nbsp;có | ✅ **1 potfile riêng / hash** (`work/potfiles/<stem>.potfile`), `is_cracked()` chỉ khớp **chính hash đó** |
| Dry-run **vẫn move file** (move nhầm sang fail) | ⚠️ có | ✅ dry-run **chỉ in, không đụng filesystem** |
| Chỉ crack 1 file (phải truyền) | ⚠️ có | ✅ **2 mode** (all-pending + 1 file) và phân loại tự động |
| Phân loại thủ công | ⚠️ có | ✅ tự động success/fail/pending |
| `RULE_DIR` trỏ `/usr/share/doc/hashcat/rules` (sai trên Debian/Arch) + rule `best66.rule` **không tồn tại** trong hashcat → **toàn bộ Phase A là code chết, chưa từng chạy** | ⚠️ có | ✅ tự dò đúng thư mục rules, dùng `best64.rule`, guard file thiếu (không crash) |
| Chạy trùng keyspace với wpa-sec | ⚠️ có | ✅ `--vn-only` (bỏ tầng đã được cover) + `--wpasec` (đẩy phần còn lại) |

---

## Yêu cầu môi trường

- **hashcat 7.x** trên Arch: `sudo pacman -S hashcat`
- GPU hoạt động qua **OpenCL**. Nếu bị cảnh báo "CUDA SDK not installed", thêm
  `--backend-ignore-cuda` (mặc định trong script) để sạch log.
- `rockyou.txt` (134MB) KHÔNG commit (vượt giới hạn GitHub). `crack_all.sh` tự tải về
  khi thiếu 2014 từ seclists hệ thống hoặc mirror online.
  → **Chạy `--vn-only` thì KHÔNG cần `rockyou.txt`** (bỏ luôn tầng generic cho wpa-sec).
---

## Password đã crack nằm ở đâu?

- Mỗi hash có potfile riêng: `work/potfiles/<stem>.potfile`.
- Xem pass của 1 hash cụ thể:
  ```bash
  hashcat -m 22000 --potfile-path work/potfiles/<stem>.potfile --show <file.22000>
  ```
- Hoặc đọc trực tiếp potfile (dòng `<hash>:<password>`).
- Mật khẩu wpa-sec đã crack (sau `python3 wpasec.py pull`): `work/wpasec_results.txt`.
