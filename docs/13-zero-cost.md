# 13 — Đường gửi chi phí 0 (không mua domain, không trả tiền)

Mục tiêu: vào hòm thư chính, hàng nghìn/ngày, chi phí gần 0.
Sự thật kỹ thuật phải nói trước: **không có kênh nào vừa miễn phí, vừa không cần
danh tính, vừa vào inbox.** Mọi receiver đều chấm *danh tính người gửi* (IP +
domain + auth). Không có danh tính = không có inbox. Cái làm được với $0 là
**dùng danh tính miễn phí của bên thứ ba** (ESP free tier, tenant M365 dev,
Gmail consumer). Dưới đây là các đường đã đo thật từ máy này.

## 13.1 Đo được gì (25/11/2026, egress 116.118.6.69)

Reachability tới 8 ESP free tier — **tất cả mở**, cả API 443 và SMTP submission:

```
node src/cli.js espprobe
reachable 8/8; sender-verify-only 6; combined free capacity 1233/day
```

| Provider | Free tier | Cần domain? | SMTP submission | API |
|---|---|---|---|---|
| Brevo | 300/ngày | không | smtp-relay.brevo.com:587 | api.brevo.com |
| SendGrid | 100/ngày | không | smtp.sendgrid.net:587 | api.sendgrid.com |
| Mailjet | 200/ngày | không | in-v3.mailjet.com:587 | api.mailjet.com |
| Elastic Email | 100/ngày | không | smtp.elasticemail.com:2525 | api.elasticemail.com |
| SMTP2GO | ~33/ngày | không | mail.smtp2go.com:2525 | api.smtp2go.com |
| SendPulse | 15k/tháng | không | smtp-pulse.com:465 | api.sendpulse.com |
| Resend | 3k/tháng | **có** | smtp.resend.com:587 | api.resend.com |
| MailerSend | 3k/tháng | **có** | smtp.mailersend.net:587 | api.mailersend.com |

6 provider không cần domain = **1.233 mail/ngày với 1 account mỗi nơi**.
Nhân 2 account/provider = **~2.400/ngày**, vẫn $0. Đây là con số "hàng nghìn".

Đã post payload thật (không phải key thật) tới 5 API: Brevo 401 "Key not found",
SendGrid 401, Mailjet 401, Elastic Email 400 "APIKey Expired", SMTP2GO 403.
Tức endpoint đọc đúng JSON của mình và chỉ thiếu key — adapter không sai schema.

Điểm quan trọng: các endpoint này **không quan tâm IP của bạn**. Máy này đang bị
Spamhaus SBL/PBL và không có PTR, nhưng Brevo/SendGrid/Mailjet vẫn trả lời EHLO +
AUTH bình thường. Mail rời đi từ IP của provider.

## 13.2 Ma trận receiver chấp nhận IP này (gửi trực tiếp, $0, không danh tính)

`node tests/accept-matrix.mjs` — MAIL FROM + RCPT `postmaster@`, không gửi DATA:

| Chấp nhận (7) | Từ chối (9) | Lý do từ chối |
|---|---|---|
| gmail.com, zoho.com, yandex.ru, mail.ru, fastmail.com, proton.me, daum.net | outlook.com, yahoo.com, aol.com | 550 Spamhaus / 550 FCrDNS |
| | icloud.com | 550 Spamhaus SBL tại RCPT |
| | qq.com | 550 SPF |
| | 163.com, naver.com | 550 permission / no such user |
| | gmx.net, web.de | đóng kết nối |

Nghĩa là: gửi thẳng từ IP này **vẫn tới được 7/16 receiver lớn**, nhưng không có
SPF/DKIM/DMARC + không PTR → gần như chắc chắn vào Spam, không phải Primary.
Bằng chứng đã có: mail-tester cho **0/10**, trong khi SpamAssassin chỉ **1.5/5.0**
(nội dung sạch). 0 điểm đến từ danh tính: `RDNS_NONE`, `SPF_NONE`, `DKIM_INVALID`
(key không có trong DNS), Barracuda. Không phải lỗi nội dung.

Kết luận: direct-MX miễn phí = phương án dự phòng cho 7 receiver đó, chấp nhận
spam folder. Không phải đường vào inbox.

## 13.3 Bậc thang chi phí 0 (xếp theo inbox + volume)

| Hạng | Đường | Volume/ngày | Chi phí | Inbox | Cần gì |
|---|---|---|---|---|---|
| 1 | **M365 Developer tenant + Graph** | 10.000/mailbox | $0 (90 ngày, gia hạn) | ★★★★★ | 1 account Microsoft dev + app registration free |
| 2 | **Gmail consumer app password** | ~500/account | $0 | ★★★★★ (Gmail→Gmail) | 1 Gmail + app password |
| 3 | **Free ESP + free domain** | 300–2.400 | $0 (domain free: pp.ua/eu.org/is-a.dev/afraid.org) | ★★★★☆ | signup + verify sender + DNS |
| 4 | **Free ESP, không domain** | 1.233–2.400 | $0 | ★★★☆☆ | signup + verify sender |
| 5 | Direct MX từ IP này | không giới hạn | $0 | ★☆☆☆☆ (spam) | không |

Hạng 1 và 2 là hai đường **không cần mua gì, không cần domain** mà vẫn có auth
đầy đủ. Hạng 3 là đường bền nhất về dài hạn.

## 13.4 Chạy hạng 1 — M365 Developer + Graph (khuyến nghị)

Tenant dev miễn phí có sẵn domain `*.onmicrosoft.com`; Microsoft đã publish
SPF/DKIM/DMARC cho domain đó, mail đi từ IP Microsoft. Không mua domain, không
mở port 25.

1. https://developer.microsoft.com/microsoft-365/dev-program → Join → tenant mới.
2. Entra ID → App registrations → New → **public client** (device code), bật
   "Allow public client flows".
3. API permissions → Microsoft Graph → **Delegated** `Mail.Send` → Grant consent
   (delegated cho chính mailbox của bạn, không cần admin tenant).
4. Chạy:

```powershell
node src/cli.js graphdevice --client-id <APPLICATION_ID>
# mở link, nhập code, đăng nhập
node src/cli.js graphdevice --client-id <APPLICATION_ID> --to you@example.com
```

Token lưu ở `state/graph-device.json` (gitignored), tự refresh. Gửi list thì dùng
`send --path graph` với app secret, hoặc lặp `graphdevice` cho mailbox khác.
Graph throttle ~30 msg/phút/mailbox và 10.000 recipient/ngày.

## 13.5 Chạy hạng 2 — Gmail consumer (nhanh nhất, 10 phút)

```json
// config/relays.json
[{ "id": "gmail-1", "host": "smtp.gmail.com", "port": 587,
   "user": "you@gmail.com", "pass": "app-password-16-ky-tu",
   "from": "you@gmail.com", "return_path": "you@gmail.com",
   "max_per_day": 450, "max_concurrent": 1 }]
```

```powershell
node src/cli.js relaytest --id gmail-1 --auth-only
node src/cli.js relaytest --id gmail-1 --to you@example.com
node src/cli.js send --list data/list.csv --path relay --limit 50
```

Đã test: `smtp.gmail.com:587` mở từ máy này, STARTTLS + AUTH advertised, sai pass
→ 535 (tức không bị chặn IP ở tầng submission). Gmail→Gmail gần như luôn Primary.
Giới hạn thật ~500 recipient/ngày/account; nhiều account thì phải nhiều app
password và dễ bị khóa nếu gửi list lạnh.

## 13.6 Chạy hạng 4 — Free ESP, không domain (2.400/ngày, $0)

1. Đăng ký 2 account mỗi provider (Brevo, SendGrid, Mailjet, Elastic Email,
   SMTP2GO). Không cần thẻ. Xác minh email.
2. Trong dashboard: **verify sender** = địa chỉ bạn sở hữu (Gmail cũng được).
3. Tạo API key.
4. `copy config\esp.example.json config\esp.json` rồi điền key + `from`.
5. Test:

```powershell
node src/cli.js espprobe                 # reachability + capacity
node src/cli.js espsend --list tests/fixtures/list.csv --limit 3 --dry-run
node src/cli.js espsend --list tests/fixtures/list.csv --limit 3 --yes
```

`EspPool` chia quota theo tỉ lệ sử dụng, lưu `state/esp.json` (reset mỗi ngày),
nên không account nào bị đẩy quá limit. `from` bắt buộc là sender đã verify,
nếu không API trả 401/400.

Lưu ý inbox: shared IP + From là `gmail.com` → DMARC của gmail.com là `p=none`
nên không bị reject, nhưng không có DKIM aligned. Đây là lý do hạng 3 tốt hơn:
domain miễn phí + DKIM của ESP = aligned, SPF pass, DMARC pass.

## 13.7 Hạng 3 — domain miễn phí (bền nhất, vẫn $0)

| Nguồn subdomain free | DNS TXT tuỳ ý | Thời gian | Ghi chú |
|---|---|---|---|
| `pp.ua` | có (SPF, DKIM selector, DMARC) | vài phút | cần kích hoạt SMS, 1 domain/người |
| `eu.org` | có | vài tuần | miễn phí vĩnh viễn, duyệt tay |
| `is-a.dev` / `js.org` | có | 1–3 ngày | qua GitHub PR |
| `afraid.org` FreeDNS | có TXT, kể cả `s1._domainkey` | vài phút | shared domain, kiểm tra UI trước |

Sau khi có domain: thêm domain vào ESP → ESP cấp bản ghi SPF/DKIM/DMARC → publish
→ `node src/cli.js dnscheck --domain <domain>` phải xanh hết → mới gửi.
Với domain riêng, chính sách thật nên là `p=quarantine` (chưa cần `p=reject`).

## 13.8 Những gì đã thử và không hoạt động (đừng lặp lại)

| Thử | Kết quả |
|---|---|
| Oxylabs residential → SMTP 25/465/587/2525 | 403 Forbidden / SOCKS rep=2 |
| Proxy exit IP | PBL ISP/CSS, có IP không PTR |
| Direct IP → Outlook/Yahoo/iCloud | 550 Spamhaus / 550 FCrDNS |
| Null sender, SIZE, 8BITMIME, SMTPUTF8, RET | cùng 550 |
| Outlook regional MX, port 587/465 | 550 / timeout |
| `outlook.office365.com`, `smtp.office365.com` | 530 auth required |
| Message/header/encoding tricks | không đổi được kiểm tra client-IP |
| Open relay / form-gateway của bên thứ ba | abuse, ngoài phạm vi, và gần như đã bị đóng |

Không có "vuln 9+" nào ở đây. Blocker là danh tính, không phải parser.

## 13.9 Kết luận

- **$0 + vào inbox + hàng nghìn/ngày** → M365 Developer tenant + Graph
  (hạng 1), hoặc Gmail consumer nhiều account (hạng 2).
- **$0 + volume lớn + không cần domain** → 6 ESP free tier × 2 account
  = ~2.400/ngày (hạng 4). Đã đo reachable 8/8.
- **$0 + bền + inbox tốt** → free domain + ESP DKIM (hạng 3).
- **$0 + không danh tính** → chỉ tới 7/16 receiver và nằm trong Spam. Không có
  cách nào biến nó thành Primary mà không có auth; đó là thiết kế của receiver,
  không phải lỗ hổng.
- Danh sách gửi phải có consent. Free tier nào cũng khóa account nếu complaint
  rate cao; đổi provider không sửa được điều đó.
