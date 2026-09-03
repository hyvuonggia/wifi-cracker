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

---

## Cách capture handshake (từ Cardputer/Porkchop)

1. Porkchop **OINK** (quét) → chọn mạng mục tiêu → deauth → bắt đủ 4-way
   handshake / PMKID → cắm SD → copy file `.pcap` + `_hs.22000` về laptop.
2. Đặt vào `~/wifi-cracker/handshakes/pending/` (cả `.pcap` + `_hs.22000`).
3. Chạy `python3 crack.py`.

> Lưu ý: chỉ cần file `.22000` để crack; `.pcap` (bản gốc) được kéo theo để markup
> SSID/BSSID dễ đọc, và để `hcxpcapngtool` xử lý lại nếu cần.

---

## Chi tiết pipeline (thứ tự tấn công)

**Phase A — Rule/Dictionary** (rẻ, tỉ lệ trúng cao nhất — chạy trước)
- `A1` rockyou + `best66.rule` (biến thể append số / đổi hoa thường)
- `A2` VN leaked + `best66`
- `A3` VN leaked + `leetspeak.rule` (`trung@123` → `trung123`)
- `A4` rockyou + `leetspeak`
- `A5` rockyou + `combinator.rule` (`tên` + `năm`)

**Phase B — Wordlist** (VN-specific)
- `B1` ngày tháng `vie-common_date` · `B2` vn1k · `B3` vn10k · `B4` vn1m ·
  `B5` vn-wifi

**Phase C — Mask** (brute theo pattern — sau cùng, trúng thấp)
- `C1` phone VN main (28 prefix) · `C2` phone VN sub (13) · `C3` misc (hotline)
- `C4` 8-số bất kỳ · `C5` 8-số bắt đầu bằng 0

Pipeline **dừng ngay khi crack được** (tiết kiệm thời gian trên máy quadrọ).

---

## Cải tiến so với phiên bản bash `crack_all.sh`

| Vấn đề | Bash cũ | Python mới |
|---|---|---|
| `is_cracked()` dùng **potfile chung** → tưởng nhầm đã crack nếu potfile còn pass file trước, dừng sớm + phân loại sai | ⚠️ &nbsp;nbsp;có | ✅ **1 potfile riêng / hash** (`work/potfiles/<stem>.potfile`), `is_cracked()` chỉ khớp **chính hash đó** |
| Dry-run **vẫn move file** (move nhầm sang fail) | ⚠️ có | ✅ dry-run **chỉ in, không đụng filesystem** |
| Chỉ crack 1 file (phải truyền) | ⚠️ có | ✅ **2 mode** (all-pending + 1 file) và phân loại tự động |
| Phân loại thủ công | ⚠️ có | ✅ tự động success/fail/pending |

---

## Yêu cầu môi trường

- **hashcat 7.x** trên Arch: `sudo pacman -S hashcat`
- GPU hoạt động qua **OpenCL**. Nếu bị cảnh báo "CUDA SDK not installed", thêm
  `--backend-ignore-cuda` (mặc định trong script) để sạch log.
- `rockyou.txt` (134MB) KHÔNG commit (vượt giới hạn GitHub). `crack_all.sh` tự tải về khi thiếu 2014 từ seclists hệ thống hoặc mirror online.
---

## Password đã crack nằm ở đâu?

- Mỗi hash có potfile riêng: `work/potfiles/<stem>.potfile`.
- Xem pass của 1 hash cụ thể:
  ```bash
  hashcat -m 22000 --potfile-path work/potfiles/<stem>.potfile --show <file.22000>
  ```
- Hoặc đọc trực tiếp potfile (dòng `<hash>:<password>`).
