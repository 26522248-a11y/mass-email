# 03 — Rate limit, quota và cách scale "không giới hạn" một cách hợp pháp

## 1. Ba tầng giới hạn

```
Tầng 1: account       (SMTP AUTH / OAuth)   → 500 - 10.000 / ngày
Tầng 2: IP / ASN      (reputation + volume) → 421/550 khi vượt pattern
Tầng 3: transaction   (per-message)         → RCPTMAX, MAILMAX, SIZE
```

Bạn chỉ "không bị rate limit" khi tổng volume < tổng quota mà **từng tầng** cho phép. Vượt tầng 1 = account khóa. Vượt tầng 2 = IP vào blacklist. Vượt tầng 3 = 452/550 ngay trong phiên.

### Quan sát thật từ `probe` (Gmail, 25/11/2026)

```
250-mx.google.com at your service
250-SIZE 157286400
250-8BITMIME
250-STARTTLS
250-ENHANCEDSTATUSCODES
250-PIPELINING
250-CHUNKING
250-SMTPUTF8
250 LIMITS MAILMAX=1000 RCPTMAX=100 RCPTDOMAINMAX=1
```

nghĩa là:
- tối đa **1000 message** mỗi connection (`MAILMAX`);
- tối đa **100 RCPT** mỗi transaction (`RCPTMAX`), đo 25/11/2026: RCPT 101 → `452 4.5.3`;
- **1 domain người nhận** mỗi transaction (`RCPTDOMAINMAX=1`) → không thể trộn Gmail + Outlook trong một `MAIL FROM`.
- SIZE 150 MB nhưng thực tế nên < 100 KB.

Đây là lý do code phải tách transaction theo domain và không tái sử dụng connection vô hạn.

---

## 2. Bảng quota tham khảo

Số liệu thay đổi theo plan/thời điểm; luôn xác minh trong admin console. Dùng làm điểm khởi đầu cho `relays.json`.

| Provider | Loại | /ngày | /message | Tốc độ | Auth |
|---|---|---|---|---|---|
| Gmail consumer | free | ≈ 500 recipients | 100 | ~20/phút | app password + 2FA |
| Google Workspace | per user | ≈ 2.000 | 100-500 | ~30/phút | OAuth/app password |
| Google SMTP relay | per customer | ≈ 10.000 recipients | 2.000 | tùy | IP allowlist / SMTP AUTH |
| Outlook.com | free | ≈ 300 | 100 | thấp | app password |
| Microsoft 365 | per mailbox | ≈ 10.000 recipients | 500 | 30/phút | **OAuth bắt buộc** |
| Yahoo | free | ≈ 500 | 100 | thấp | app password |
| Amazon SES | production | 50.000 (xin tăng) | 50 recipients | 14/s (xin tăng) | SMTP key |
| SendGrid | plan | theo plan | 1.000 | 600 req/phút | API key/SMTP |
| Mailgun | plan | theo plan | 1.000 | 300/phút | SMTP/API |
| Postmark | plan | theo plan | 1.000 | 500/phút | SMTP token |
| Brevo | free | 300 | 100 | 9k/tháng | SMTP key |
| Resend | free | 100 | 50 | 2 req/s | API key |
| Mailjet | free | 200 | 50 | 6k/tháng | SMTP key |

**Lưu ý:** quota ESP là hợp đồng, không phải thông số kỹ thuật. Vượt = account bị freeze, không chỉ 421.

---

## 3. Mã SMTP và chính sách retry

| Code | Nghĩa | Hành động |
|---|---|---|
| 250/251 | accepted | done |
| 421 | service not available / rate | retry sau 5-15 phút, giảm concurrency relay đó |
| 450/451/452 | mailbox/temp/storage | retry backoff |
| 454 | TLS unavailable | retry, kiểm tra cert |
| 550 5.1.1 | unknown user | **bounce vĩnh viễn**, không retry |
| 550 5.7.1 | policy/spam/reputation | không retry mù; xem nội dung, giảm volume, delist |
| 550 5.7.26 | auth fail | sửa DNS/key, retry sau khi fix |
| 552 | size exceeded | giảm message, không retry |
| 554 | transaction failed | thường content/spam; xem reply |

`sender.js` phân loại:
- `421/450/451/452` hoặc text chứa throttl/rate → quarantine relay 15 phút;
- `5xx` → bounce, trừ auth (disable relay);
- lỗi mạng → retry backoff.

Backoff mặc định: `60, 300, 1800, 7200, 21600` giây, tối đa 5 lần.

---

## 4. RelayPool hoạt động thế nào

`src/core/pool.js`:

```
score = weight × health × (0.4 + 0.6 × quotaRemaining) × (0.5 + 0.5 × freshness)
```

- `weight`: tỷ lệ chia tải (SES 10, Gmail 2, Outlook 1).
- `health`: 1.0 → giảm khi lỗi, tăng khi thành công; < 0.15 bị loại.
- `quotaRemaining`: theo giờ/ngày, reset trượt.
- `freshness`: ưu tiên relay lâu chưa dùng → tránh dồn một IP.
- `quarantineUntil`: sau 421/451.
- `disabled`: sau auth fail.

Chọn ngẫu nhiên có trọng số trong top 5 → phân tải mượt, không round-robin cứng (dễ tạo pattern).

Chạy `node src/cli.js pool` để xem:

```
id          kind     host                 health  leftHour  leftDay
ses-1       ses      email-smtp...        1.00    800       12000
gmail-ws-1  gmail    smtp.gmail.com       0.92    150       900
```

---

## 5. Auth: app password vs OAuth

| Provider | Cách đúng |
|---|---|
| Gmail consumer | 2FA + app password 16 ký tự; `smtp.gmail.com:587` STARTTLS |
| Google Workspace | OAuth2 (XOAUTH2) hoặc app password nếu admin cho phép; SMTP relay nếu có IP tĩnh |
| Outlook.com | app password; `smtp-mail.outlook.com:587` |
| Microsoft 365 | **OAuth2 bắt buộc** (basic auth đã bị tắt); `smtp.office365.com:587`, đăng ký app Azure, scope `SMTP.Send` |
| SES | SMTP username/password sinh từ IAM; hoặc SES API |
| SendGrid/Mailgun/Postmark | SMTP key hoặc API |

Code hỗ trợ `AUTH XOAUTH2`:

```json
{
  "id": "m365-1",
  "host": "smtp.office365.com",
  "port": 587,
  "user": "sender@contoso.com",
  "access_token": "eyJ0eXAi...",
  "auth": "XOAUTH2"
}
```

Access token sống ~1 giờ. Với volume lớn, viết refresher (client credentials → token endpoint) cập nhật `state/relays-tokens.json`, hoặc dùng Graph API `sendMail` (batch, throttle 30 msg/phút/mailbox).

**Không** lưu refresh token trong repo. Dùng biến môi trường/secret store, ACL file.

---

## 6. Scale theo volume

`node src/cli.js capacity --target N` xuất:

```json
{
  "required": { "relays": 27, "ips": 45, "domains": 14 },
  "throughput": { "messagesPerSecond": 1.74, "perRelayPerSecond": 11.43 },
  "costUsdPerMonth": { "low": 454, "high": 2104 }
}
```

Công thức:

```
need        = target × 1.35 (headroom)
relayAccounts = ceil(need / quotaRelay)
IPs         = ceil(need / safePerIP)
domains     = max(3, ceil(need / safePerDomain))
```

Ngưỡng an toàn tham khảo:
- IP warm: 2.000-5.000/ngày (mới warm: 500-1.000).
- Domain: 10.000/ngày, tối đa 50.000 nếu reputation rất tốt.
- Mỗi domain/IP nên có subdomain + stream riêng.

### 3 mức triển khai

| Volume/ngày | Hạ tầng | Chi phí/tháng |
|---|---|---|
| 10k | 1 VPS + SES 1 account + 1 domain | $10-30 |
| 100k | 2-3 ESP + 3 domain + 4 IP + queue | $150-400 |
| 1M | 10-20 IP warm, 20+ domain, MTA cluster (Postfix/Haraka) hoặc nhiều ESP, monitoring | $1.500-5.000 |

### Tại sao không nên tự dựng MTA ngay

- PTR/FCrDNS phụ thuộc nhà cung cấp IP.
- IP /24 mới tinh = reputation 0, warmup 4-8 tuần.
- Phải tự xử lý bounce, TLS, DNSBL, feedback loop.
- ESP rẻ hơn ở volume < 500k/ngày và ít rủi ro vận hành.

Tự dựng chỉ hợp lý khi: volume lớn, cần kiểm soát dữ liệu, hoặc ESP từ chối niche của bạn.

---

## 7. Vì sao "rotate account free" không work

- Gmail/Outlook yêu cầu phone verification, device fingerprint, IP reputation.
- Account mới gửi volume lớn → khóa ngay (< 24h).
- Cùng IP gửi nhiều account mới → tất cả bị liên kết.
- Vi phạm ToS → mất account, mất tiền, có thể bị pháp lý.
- Không scale được: 100 account × 300/ngày = 30k nhưng vận hành không bền, vi phạm.

Con đường bền: **nhiều relay hợp đồng + nhiều domain/IP warm + list chất lượng**. Đó là "unlimited" theo nghĩa kinh tế, không phải kỹ thuật.

---

## 8. Cấu hình mẫu

### SES + Gmail + M365

```json
{
  "relays": [
    { "id": "ses-1", "kind": "ses", "host": "email-smtp.us-east-1.amazonaws.com", "port": 587,
      "user": "AKIA...", "pass": "...", "from": "news@mail.example.com", "weight": 10,
      "max_per_hour": 800, "max_per_day": 12000, "max_concurrent": 8 },

    { "id": "gmail-1", "kind": "gmail", "host": "smtp.gmail.com", "port": 587,
      "user": "sender@example.com", "pass": "app-password", "from": "news@mail.example.com",
      "weight": 2, "max_per_hour": 100, "max_per_day": 600, "max_concurrent": 2 },

    { "id": "m365-1", "kind": "outlook", "host": "smtp.office365.com", "port": 587,
      "user": "sender@contoso.com", "access_token": "...", "auth": "XOAUTH2",
      "from": "news@mail.example.com", "weight": 2, "max_per_hour": 150, "max_per_day": 900, "max_concurrent": 2 }
  ]
}
```

### Chạy

```powershell
node src/cli.js pool
node src/cli.js send --list data/list.csv --limit 500 --concurrency 8
node src/cli.js queue stats
```

---

## 9. Giám sát quota

- `pool` mỗi 5 phút → alert khi `leftHour < 20%`.
- Log 421/451 theo relay → nếu > 2% volume, giảm `max_per_hour` 30%.
- Log 550 5.7.1 → dừng relay, kiểm tra nội dung/list trước khi bật lại.
- Theo dõi complaint qua Postmaster/SNDS, không chỉ bounce.

---

## 10. Mapping code

| Việc | File |
|---|---|
| quota, weight, health, quarantine | `src/core/pool.js` |
| retry/backoff, lease | `src/core/queue.js` |
| phân loại mã SMTP | `src/core/sender.js` |
| auth PLAIN/LOGIN/XOAUTH2 | `src/lib/smtp.js` |
| tính hạ tầng | `src/core/capacity.js` |
| warmup ramp | `src/core/warmup.js` |
