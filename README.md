# mass-email

Bulk mail engine nhiều relay + bộ probe hành vi receiver (Gmail, Outlook, Yahoo, Proton…), viết bằng Node.js thuần, **không dependency**.

Mục tiêu: gửi email opt-in với hiệu suất cao, ổn định, hạ tầng nhỏ, và **đo được** lý do email vào inbox/spam thay vì đoán.

> Đây là hạ tầng email marketing hợp pháp. Không có tính năng spoof domain, đánh cắp credential, hay né consent. Mọi kỹ thuật "khó phát hiện" trong tài liệu đều là giảm dấu hiệu *bulk xấu* (pacing, segmentation, authentication), không phải giả mạo danh tính.

---

## Quick start

```powershell
cd C:\Users\Administrator\mass-email

# 1. Khởi tạo
node src/cli.js init

# 2. Sinh DKIM key + in record DNS
node src/cli.js keys --domain mail.example.com --selector s1

# 3. Kiểm tra DNS/PTR/reputation của domain gửi
node src/cli.js dnscheck --domain mail.example.com --ip <IP_egress>

# 4. Fingerprint receiver (không gửi mail, chỉ SMTP handshake)
node src/cli.js probe --target gmail,outlook,yahoo,proton
node src/cli.js diagnose
node src/cli.js proxycheck --user <u> --pass <p>
node src/cli.js relaytest --id gmail-1 --auth-only
node src/cli.js graphtest --to you@example.com
node src/cli.js ratelimit --target gmail.com --connections 8 --rcpt 5
node src/cli.js mailtest --path direct

# 5. Tính hạ tầng cho volume mục tiêu
node src/cli.js capacity --target 100000

# 6. Soạn + gửi thử (dry-run in ra MIME + DKIM)
node src/cli.js send --list config/recipients.example.csv `
  --text templates/newsletter.txt --html templates/newsletter.html --dry-run --yes

# 7. Gửi thật (relays.json phải có credential thật)
node src/cli.js send --list data/list.csv --limit 100

# 8. Đường chi phí 0: ESP free tier qua HTTPS API, không cần domain
node src/cli.js espprobe
node src/cli.js espsend --list data/list.csv --limit 50 --yes

# 9. Đường chi phí 0 + inbox tốt nhất: M365 dev tenant + device code
node src/cli.js graphdevice --client-id <APP_ID>
node src/cli.js graphdevice --client-id <APP_ID> --to you@example.com

# 10. Danh tính: đo blocker và route từng receiver
node src/cli.js identity
node src/cli.js identity --plan
node src/cli.js identity --list data/list.csv
node src/cli.js send --list data/list.csv --path smart
```

## Lệnh

| Lệnh | Việc |
|---|---|
| `init` | tạo policy/relays/dir |
| `keys` | RSA-2048 DKIM, in bản ghi TXT |
| `send` | render → ký DKIM → chọn relay → SMTP → retry queue |
| `verify` | MX + RCPT probe, phát hiện catch-all/disposable/role |
| `dnscheck` | audit SPF/DKIM/DMARC/PTR/FCrDNS/DNSBL/MTA-STS/TLS-RPT/DNSSEC |
| `probe` | capability matrix + hành vi receiver + TLS cert + giới hạn EHLO |
| `diagnose` | egress IP, PTR/FCrDNS, mã Spamhaus, chặn ở MAIL FROM theo receiver |
| `ratelimit` | đo RCPT/connection limit thật của Gmail/Outlook |
| `relaytest` | test AUTH hoặc gửi 1 message qua đúng relay |
| `proxycheck` | test proxy có mở port 25/587 không + reputation IP ra |
| `graphtest` | gửi 1 message qua Microsoft 365 Graph |
| `graphdevice` | Graph bằng device-code (không cần app secret, không admin consent) |
| `espprobe` | reachability + free capacity của 8 ESP free tier |
| `espsend` | gửi qua free ESP bằng HTTPS API (không dùng port 25/587) |
| `identity` | score danh tính, chiếu lên từng receiver, inventory identity đã có |
| `identity --plan` | bậc thang identity $0 (M365 dev, Gmail, ESP, IP tĩnh) |
| `mailtest` | gửi 1 mail tới mail-tester.com, đọc điểm 0-10 + lỗi auth |
| `score` | heuristic spam score trước khi gửi |
| `warmup` | sinh ramp 28 ngày cho IP/domain mới |
| `capacity` | tính relay/IP/domain/chi phí theo volume |
| `pool` | health + quota còn lại của từng relay |
| `queue` | stats / failed / retry |
| `dns-records` | in toàn bộ record cần publish |

## Kiến trúc

```
CSV list ──► Queue (data/queue, durable, lease)
                │
                ▼
        render (spintax + per-recipient RNG) ──► spamscore gate
                │
                ▼
        MIME builder (text+HTML, RFC 2047, QP/base64)
                │
                ▼
        DKIM signer (relaxed/relaxed, RSA-2048)
                │
                ▼
        RelayPool (weighted, quota hour/day, health, quarantine)
                │
                ▼
        SMTP client (STARTTLS, AUTH, PIPELINING, dot-stuffing)
                │
        ┌───────┴────────┐
        ▼                ▼
   2xx → done      4xx → backoff       5xx → bounce/disable relay
```

## Cấu trúc

```
config/     policy.json, relays.json, recipients.example.csv
src/lib/    smtp, dkim, mime, dns (DoH), spintax, spamscore
src/core/   pool, queue, sender, verifier, probe, dnscheck, warmup, capacity
src/cli.js  entrypoint
templates/  newsletter.txt / .html
tests/      mock SMTP + mock ESP API + 15 test end-to-end
docs/       01→14: threat model, deliverability, rate limit, vuln research, playbook, architecture, runbook, legal, bypass, credentials, graph, branch tests, zero-cost, identity
reports/    evidence JSON/HTML (diagnose, ratelimit, mailtest, probe, dns, espprobe)
data/       queue (pending/done/failed)
state/      pool.json, esp.json (quota theo ngày), graph-device.json
keys/       private key per domain (never commit)
reports/    probe/dns/verify JSON
logs/       send log
```

## Kết quả probe thật trên máy này (25/11/2026)

| Target | MX | TLS | Null sender | RCPT random | Max size | Ghi chú |
|---|---|---|---|---|---|---|
| Gmail | gmail-smtp-in.l.google.com | 1.3 | accepted | 550 5.1.1 | 150 MB | EHLO `LIMITS MAILMAX=1000 RCPTMAX=100 RCPTDOMAINMAX=1` |
| Outlook | outlook-com.olc.protection.outlook.com | 1.3 | rejected | — | 47 MB | IP egress bị Spamhaus → `550 5.7.1` |
| Yahoo | mta*.am0.yahoodns.net | 1.3 | rejected | — | 40 MB | `550 5.7.25 fcRDNS failed` |
| Proton | mail.protonmail.ch | 1.3 | accepted | 503 | 68 MB | 503 tại RCPT (greylist/challenge) |

Chi tiết + cách đọc: `docs/04-vuln-research.md`. Đây cũng là minh chứng cho nguyên tắc: **reputation của IP quyết định trước nội dung**.

### Chẩn đoán blocker hiện tại (25/11/2026)

| Kiểm tra | Kết quả |
|---|---|
| Egress | `116.118.6.69`, AS7602 Sai Gon Postel, `ADSL-NET` |
| PTR / FCrDNS | không có / fail |
| Spamhaus ZEN | `127.0.0.3` **SBL CSS** + `127.0.0.11` **PBL CSS** |
| Barracuda | listed |
| Gmail direct | MAIL 250, RCPT 550 với random; DATA 250 tới mail-tester |
| Outlook direct | **550 5.7.1 Spamhaus** ở MAIL FROM |
| Yahoo direct | **550 5.7.25 FCrDNS failed** |
| Gmail RCPT cap | 100/transaction; 101 → `452 4.5.3` |
| Mail-Tester | **0/10**; SpamAssassin 1.5 (nội dung sạch); lỗi SPF/DKIM/rDNS/Barracuda |

Kết luận: blocker là **danh tính IP**, không phải content. Muốn gửi hàng nghìn/ngày phải dùng ESP smarthost hoặc IP tĩnh + PTR + delist. Không có bypass mức 9+ bằng message crafting. Đọc `docs/09-bypass.md` để xem toàn bộ route, bằng chứng và checklist.

### Proxy residential (đã test)

Oxylabs `pr.oxylabs.io:7777` (HTTP) và `:10000` (SOCKS5):
- CONNECT tới port 25/587/465 → **403**; SOCKS5 → **rep=2**.
- Exit IP residential (Comcast/Charter/ImOn), PBL `127.0.0.10/11`.
- Kết luận: **không dùng cho SMTP**, chỉ dùng cho HTTPS API. Không tạo reputation tốt hơn.

### Credentials

Đọc `docs/10-credentials.md`. Tóm tắt:
- Gmail app password → `smtp.gmail.com:587`, ~500/ngày, From = account.
- Outlook app password → `smtp-mail.outlook.com:587`, ~300/ngày.
- M365 OAuth/Graph → ~10k/ngày/mailbox.
- ESP (SES/SendGrid/Mailgun) → 50k+/ngày, khuyến nghị.

Điền `config/relays.json`, sau đó:
```powershell
node src/cli.js relaytest --id <id> --auth-only
node src/cli.js relaytest --id <id> --to you@example.com
node src/cli.js mailtest --path relay
```

## Chi phí 0 (không mua domain, không trả tiền)

Đo thật 25/11/2026: 8/8 ESP free tier reachable từ máy này (API 443 + SMTP
submission), 6 provider không cần domain, **1.233 mail/ngày với 1 account mỗi
nơi**, ~2.400/ngày với 2 account mỗi nơi. Mail rời đi từ IP provider nên
Spamhaus/PTR của máy này không còn liên quan.

| Đường | Volume | Inbox | Ghi chú |
|---|---|---|---|
| M365 Developer tenant + Graph | 10k/mailbox/ngày | ★★★★★ | free 90 ngày, domain `onmicrosoft.com` có sẵn SPF/DKIM/DMARC |
| Gmail consumer app password | ~500/account/ngày | ★★★★★ | Gmail→Gmail gần như luôn Primary |
| Free ESP + free domain (pp.ua/eu.org/is-a.dev) | 300–2.400/ngày | ★★★★☆ | aligned DKIM, bền |
| Free ESP, không domain | 1.233–2.400/ngày | ★★★☆☆ | nhanh nhất, shared IP |
| Direct MX từ IP này | không giới hạn | ★☆☆☆☆ | chỉ 7/16 receiver nhận, vào Spam |

```powershell
node src/cli.js espprobe
copy config\esp.example.json config\esp.json   # điền API key + from đã verify
node src/cli.js espsend --list data/list.csv --limit 50 --dry-run
node src/cli.js espsend --list data/list.csv --limit 50 --yes

node src/cli.js graphdevice --client-id <APP_ID>   # device code, không cần secret
```

Chi tiết, ma trận 16 receiver và toàn bộ số đo: `docs/13-zero-cost.md`.

## Blocker danh tính: không bypass, chỉ thay

```powershell
node src/cli.js identity
# identity 116.118.6.69 / mail.example.com  score=0/100 grade=F
# no-ptr, SBL CSS, PBL CSS, no-spf, no-dkim, no-dmarc
```

PBL/SBL là khai báo của chủ IP. Đo cả dải: `116.118.6.1/.69/.70/.100` và
`116.118.7.10` đều **PBL CSS**, riêng `.69` thêm **SBL CSS** → không có thao tác
sender nào gỡ được; chỉ ISP/chủ IP xin delist được.

Thay vào đó, thay danh tính:

| Danh tính thay | $ | Volume | Inbox |
|---|---|---|---|
| M365 Developer tenant + Graph | 0 | 10k/mailbox/ngày | A |
| Gmail consumer app password | 0 | ~500/account/ngày | A |
| Free ESP (Brevo/SendGrid/Mailjet/Elastic/SMTP2GO) | 0 | 1.2k–2.4k/ngày | B/B+ |
| Oracle Always Free VM + PTR + port 25 | 0 | warmup 2–6 tuần | B |

`send --path smart` tự chọn danh tính theo từng receiver: grade F thì **không bao
giờ** gửi direct (kể cả khi receiver trả 250 — sẽ vào Spam), mà đi ESP → Graph →
relay → held.

```powershell
node src/cli.js identity --plan
node src/cli.js identity --list data/list.csv
node src/cli.js send --list data/list.csv --path smart --limit 100
```

Chi tiết + bằng chứng từng receiver: `docs/14-identity.md`.

## Nguyên tắc bắt buộc

1. Chỉ gửi tới địa chỉ có consent, có nguồn đăng ký.
2. Suppression list: hard bounce, complaint, unsubscribe — áp dụng ngay, không chờ.
3. Không spoof From/display name của bên khác.
4. Tôn trọng quota trong `relays.json`; đó là cam kết với ESP, không phải mục tiêu để vượt.
5. Nghiên cứu bảo mật chỉ trên domain/mailbox của bạn, hoặc theo safe harbor của vendor.

## Test

```powershell
node tests/run.mjs
```

15 test: spintax, MIME, DKIM sign/verify + tamper, args, mail-tester parser, Graph payload + mock send, gửi qua mock SMTP, queue lease/recovery, ESP payload adapters, ESP API mock + quota, identity scoring, smart routing, placeholder creds, CLI dry-run.

