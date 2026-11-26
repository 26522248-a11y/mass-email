# 14 — Blocker danh tính: không bypass, chỉ thay

## 14.1 Danh tính là gì

Receiver chấm 4 thứ trước khi đọc subject:

```
client IP → PTR/FCrDNS → domain auth (SPF/DKIM/DMARC) → reputation lịch sử
```

Máy này hiện tại:

```
node src/cli.js identity
identity 116.118.6.69 / mail.example.com  score=0/100 grade=F
no-ptr, spamhaus-sbl (SBL CSS), spamhaus-pbl (PBL CSS), no-spf, no-dkim, no-dmarc
```

## 14.2 Vì sao không "bypass" được

PBL/SBL là **khai báo của chủ IP**, không phải lỗi cấu hình của bạn:

- PBL CSS = ISP khai báo cả dải là dynamic/shared → **chỉ ISP gỡ được**.
- SBL CSS = Spamhaus gắn nhãn nguồn spam cho IP → **chỉ chủ IP/ISP xin gỡ được**.

Đo cả dải:

| IP | Spamhaus |
|---|---|
| 116.118.6.1 | PBL CSS |
| 116.118.6.69 | PBL CSS + **SBL CSS** |
| 116.118.6.70 | PBL CSS |
| 116.118.6.100 | PBL CSS |
| 116.118.7.10 | PBL CSS |

Nghĩa là không có thao tác nào từ phía sender (header, port, HELO, encoding,
proxy) thay đổi được kết quả. Đã test và fail toàn bộ: null sender, SIZE,
8BITMIME, SMTPUTF8, RET, MAIL FROM giả, regional MX, port 587/465, IPv6
6to4/Teredo, residential proxy, open-relay hunting, SMTP smuggling.

Kết luận kỹ thuật: **identity không phải thứ bypass được, mà là thứ thay được.**

## 14.3 Ba cách thay danh tính (hợp pháp, $0)

| Cách | Danh tính receiver thấy | $ | Volume | Inbox |
|---|---|---|---|---|
| Mượn hạ tầng receiver | IP Microsoft/Google, domain họ ký | 0 | 10k/mailbox/ngày (M365) | A |
| Mượn hạ tầng ESP | IP shared của ESP, DKIM của ESP | 0 | 1.2k–2.4k/ngày | B/B+ |
| Sở hữu IP tĩnh | IP của bạn + PTR + domain của bạn | 0 (free tier) | warmup 2–6 tuần | B sau warmup |

### A. M365 Developer tenant + Graph — mạnh nhất, $0

`*.onmicrosoft.com` do Microsoft quản lý SPF/DKIM/DMARC; mail đi từ IP Microsoft.
Không cần domain, không cần thẻ.

```powershell
node src/cli.js graphdevice --client-id <APP_ID>
node src/cli.js graphdevice --client-id <APP_ID> --to you@example.com
```

### B. Gmail consumer — nhanh nhất, $0

Gmail→Gmail gần như luôn Primary; 500 recipient/ngày/account.

```json
[{ "id": "gmail-1", "host": "smtp.gmail.com", "port": 587,
   "user": "you@gmail.com", "pass": "app-password",
   "from": "you@gmail.com", "return_path": "you@gmail.com",
   "max_per_day": 450, "max_concurrent": 1 }]
```

### C. ESP free tier — $0, không domain

```powershell
node src/cli.js espprobe
node src/cli.js espsend --list data/list.csv --limit 50 --yes
```

### D. IP tĩnh của chính bạn — $0 bằng free tier/credit

Đây là cách duy nhất để có PTR + IP sạch mà không mượn ai:

1. **Oracle Cloud Always Free** — VM vĩnh viễn miễn phí, có public IPv4 tĩnh.
   - Reserve public IP → **Edit reverse DNS** (Oracle cho set PTR).
   - Port 25 bị chặn mặc định → mở support request "enable outbound SMTP".
   - Rồi publish A/PTR/SPF/DKIM/DMARC và warmup.
2. **VPS credit** (DigitalOcean $200 / Linode $100 / Vultr): $5–6/tháng → 1.5–3 năm
   miễn phí. Cần request unblock port 25 và set rDNS.
3. **Không dùng**: AWS/GCP free tier (port 25 khóa vĩnh viễn, xin không được),
   Hetzner (khóa 25), Azure (khóa 25, xin được nhưng chậm).

Thời gian thực tế: 1–3 ngày để có IP + PTR + port 25; 2–6 tuần warmup trước khi
gửi volume lớn.

## 14.4 Routing theo từng receiver — `--path smart`

Không phải receiver nào cũng chặn. Đo trực tiếp:

```
node src/cli.js identity --list data/list.csv
```

| Receiver | Kết quả hiện tại | Danh tính cần |
|---|---|---|
| gmail.com | accepted (250) | chỉ cần auth đúng để vào Primary |
| zoho, yandex, mail.ru, proton, fastmail | accepted | auth + nội dung |
| outlook.com | **ip-blocked** (Spamhaus) | ESP/Graph |
| yahoo.com, aol.com | **ip-blocked** (FCrDNS) | ESP/Graph, hoặc IP có PTR |
| icloud.com | **ip-blocked** (SBL) | ESP/Graph |

`send --path smart` tự chọn danh tính cho từng recipient:

```powershell
node src/cli.js send --list data/list.csv --path smart --limit 100
```

Luật:
- Identity grade F → **không bao giờ** gửi direct, kể cả receiver trả 250
  (vào Spam, không phải Primary).
- Receiver chấp nhận + identity ≥ C → direct.
- Còn lại: ESP (nếu có key thật) → Graph → relay → `held`.
- Placeholder trong config (`AKIA...`, `BASE64_SMTP_PASSWORD`, `app-password`)
  bị coi là **chưa có**, không tính là identity.

## 14.5 Thứ tự làm

1. `identity` — xem score và receiver nào chặn.
2. `identity --plan` — chọn danh tính thay thế.
3. Có M365 dev tenant → `graphdevice`. Không có → `espprobe` + `espsend`.
4. Muốn tự sở hữu IP → Oracle Always Free + PTR + mở port 25 + warmup.
5. Chạy `send --path smart` để mỗi receiver đi đúng danh tính.

## 14.6 Giới hạn

- Không có danh tính nào miễn phí mà **không cần signup**. Mọi "gửi không cần
  credential" đều là mượn/đánh cắp relay của người khác — không làm.
- Free tier có quota; vượt là khóa account. `EspPool` và `RelayPool` giữ quota.
- Danh tính tốt không cứu list không consent: complaint > 0.1% vẫn vào Spam.
- Không có mức 9+ nào ở đây. Đây là thay danh tính hợp pháp, không phải exploit.
