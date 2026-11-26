# 07 — Runbook: từ 0 đến gửi ổn định

## Phase 0 — Chuẩn bị

- [ ] Domain riêng cho gửi (không dùng domain chính nếu mới).
- [ ] Quyền sửa DNS (TXT/MX/CNAME).
- [ ] 1 ESP account (SES/SendGrid/Mailgun…) hoặc mailbox SMTP.
- [ ] Node 20+ trên máy chủ gửi.
- [ ] Consent proof cho list (nguồn, thời gian, IP).
- [ ] Suppression list (bounce/complaint/unsub cũ).

## Phase 1 — Domain & subdomain

Chọn:
```
example.com            ← web/brand, không gửi bulk
mail.example.com       ← From + Return-Path + DKIM
go.example.com         ← click tracking (CNAME)
```

```powershell
cd C:\Users\Administrator\mass-email
node src/cli.js init
```

Sửa `config/policy.json`:
```json
{
  "from_name": "Brand",
  "from_address": "news@mail.example.com",
  "from_domain": "mail.example.com",
  "return_path": "bounce@mail.example.com",
  "return_path_domain": "mail.example.com",
  "unsubscribe_mailto": "unsub@mail.example.com",
  "unsubscribe_url": "https://go.example.com/u/{token}"
}
```

## Phase 2 — DNS

Chạy:
```powershell
.\scripts\New-SendingDomain.ps1 -Domain mail.example.com -Selector s1 -Ip 203.0.113.10
```

Publish tối thiểu:

| Type | Name | Value |
|---|---|---|
| A | `mail.example.com` | IP gửi |
| MX | `mail.example.com` | `10 inbound.example.com.` |
| TXT | `mail.example.com` | `v=spf1 ip4:203.0.113.10 -all` |
| TXT | `s1._domainkey.mail.example.com` | `v=DKIM1; k=rsa; p=...` |
| TXT | `_dmarc.mail.example.com` | `v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100; rua=mailto:dmarc@example.com` |
| TXT | `_mta-sts.mail.example.com` | `v=STSv1; id=...` |
| TXT | `_smtp._tls.mail.example.com` | `v=TLSRPTv1; rua=mailto:tlsrpt@example.com` |
| PTR | IP → `mail.example.com` | nhờ nhà cung cấp IP |

MTA-STS policy (HTTPS):
```
https://mta-sts.mail.example.com/.well-known/mta-sts.txt
version: STSv1
mode: enforce
mx: mail.example.com
max_age: 86400
```

Kiểm tra:
```powershell
node src/cli.js dnscheck --domain mail.example.com --ip 203.0.113.10
```
Mục tiêu: grade A/B, không critical/high. Chờ TTL trước khi gửi thật.

## Phase 3 — Relay

Copy `config/relays.example.json` → `config/relays.json`, điền credential thật.

```powershell
node src/cli.js pool
```

Kỳ vọng: mỗi relay `health 1.00`, quota đúng.

Nếu AUTH fail:
- Gmail: bật 2FA, tạo app password 16 ký tự.
- M365: OAuth2 (client credentials), scope `SMTP.Send`, `access_token` + `auth: XOAUTH2`.
- SES: SMTP credential từ IAM, region đúng.

## Phase 4 — Template & preflight

Sửa `templates/newsletter.txt` + `.html`. Giữ:
- 1 CTA, text thật, footer unsubscribe.
- Không ảnh base64, không link shortener.

```powershell
.\scripts\Preflight.ps1 -Ip 203.0.113.10
```

Mục tiêu: score < 2.5, DKIM trong dry-run, DNS A/B.

## Phase 5 — List

CSV tối thiểu:
```csv
email,name,token
alice@example.com,Alice,a1b2c3
```

Trước khi gửi:
```powershell
node src/cli.js verify --list data/list.csv --out reports/verify.json
```

- `valid` → gửi.
- `invalid` → loại vĩnh viễn.
- `risky` (catch-all) → gửi volume thấp, theo dõi bounce.
- `unknown` → retry sau 24h, không gửi ngay.

## Phase 6 — Seed test

Tạo mailbox seed thật (Gmail Primary, Gmail Promotions, Outlook Focused/Other, Yahoo, Proton, iCloud). Gửi:

```powershell
node src/cli.js send --list config/seed-list.csv --limit 7 --yes
```

Kiểm tra từng mailbox:
- inbox/spam/promotions/other?
- show original: SPF/DKIM/DMARC pass? alignment?
- link, ảnh, mobile.
- Gmail: tab nào? Outlook: Focused?

Nếu < 100% inbox → sửa, không scale.

## Phase 7 — Warmup

```powershell
node src/cli.js warmup --start 50 --target 5000 --days 28 --out reports/warmup.csv
```

Ngày 1-7: 50-100/ngày, chỉ engaged_30.
Ngày 8-14: 150-300/ngày.
Ngày 15-21: 400-800/ngày.
Ngày 22-28: 800-1.500/ngày nếu sạch.

Chạy hằng ngày:
```powershell
.\scripts\Send-Batch.ps1 -List data/engaged30.csv -Limit 100 -Concurrency 2
```

Không tăng nếu:
- complaint > 0.05%
- 421/451 > 2%
- DNSBL listing
- seed < 95% inbox

## Phase 8 — Scale

Khi 1 relay ổn định:
1. Thêm relay thứ 2 cùng domain (nếu ESP cho phép) → chia weight.
2. Thêm domain thứ 2 khi volume > 10k/ngày/domain.
3. Thêm IP khi cần, warm từng IP.
4. Dùng `capacity` để tính.

```powershell
node src/cli.js capacity --target 100000
node src/cli.js pool
```

## Phase 9 — Monitoring

Daily:
```powershell
.\scripts\Health.ps1 -Ip 203.0.113.10
node src/cli.js diagnose
```

- Egress: PTR/FCrDNS, Spamhaus codes, per-receiver MAIL verdict.
- Mail-Tester: `node src/cli.js mailtest --path relay` (1 test/run).
- Queue: pending không tăng liên tục; oldest < 2h.
- Pool: không relay nào health < 0.3; quota còn ≥ 20%.
- DNS: không DNSBL; PTR/FCrDNS OK.
- Postmaster/SNDS: complaint < 0.1%, reputation OK.

Weekly:
- Inbox rate theo provider (seed).
- Bounce/complaint theo segment.
- So sánh campaign, subject, CTA.
- Backup `data/`, `state/`, `keys/`.

## Incident playbook

### 550 5.7.1 tăng đột ngột
1. Dừng campaign/relay liên quan.
2. `dnscheck` → DNSBL?
3. Postmaster/SNDS → complaint?
4. Nếu DNSBL: delist, giảm volume 70%, gửi lại engaged_30 sau 48h.
5. Nếu content: sửa link/subject, seed test lại.

### 421/451 > 2%
1. Giảm `max_per_hour` relay 50%.
2. Giảm concurrency.
3. Kiểm tra relay có bị ESP throttle không.
4. Tăng khoảng cách gửi (pacing).

### Complaint > 0.1%
1. Dừng ngay.
2. Xem segment nào complaint.
3. Loại segment đó, re-permission.
4. Giảm frequency.
5. Chỉ gửi engaged_30 trong 2 tuần.

### Relay auth fail
1. `pool` xem `disabled`.
2. Gmail: app password mới.
3. M365: refresh token.
4. SES: kiểm tra credential/region.
5. Sửa `relays.json`, xóa state relay hoặc chờ reload.

### Queue kẹt
1. `queue stats` → pending/leased.
2. Lease còn hạn 10 phút; crash sẽ recover.
3. Nếu pending tăng: thêm worker/relay, giảm limit.
4. Nếu file lỗi: kiểm tra JSON, xóa job hỏng.

### Bị chặn domain
1. Kiểm tra DNSBL + Postmaster.
2. Tách domain khác cho stream, giữ domain cũ warm.
3. Không dùng domain mới tinh gửi volume lớn ngay.
4. Root cause trước khi resume.

## Command cheat sheet

```powershell
node src/cli.js init
node src/cli.js keys --domain mail.example.com --selector s1
node src/cli.js dns-records --domain mail.example.com
node src/cli.js dnscheck --domain mail.example.com --ip 203.0.113.10
node src/cli.js probe --target gmail,outlook,yahoo,proton
node src/cli.js score --text templates/newsletter.txt --html templates/newsletter.html --subject "Hello"
node src/cli.js send --list data/list.csv --limit 100 --concurrency 4
node src/cli.js send --list data/list.csv --path auto --limit 100
node src/cli.js send --list data/list.csv --path direct --dry-run --yes
node src/cli.js verify --list data/list.csv --out reports/verify.json
node src/cli.js warmup --start 50 --target 5000
node src/cli.js capacity --target 100000
node src/cli.js pool
node src/cli.js diagnose
node src/cli.js proxycheck
node src/cli.js relaytest --id gmail-1 --auth-only
node src/cli.js relaytest --id gmail-1 --to you@example.com
node src/cli.js queue stats
node src/cli.js queue failed
node src/cli.js queue retry
```
