# 09 — Bypass report: current blockers, what works, what does not

Ngày đo: 2026-11-25 (UTC+7), host gửi `116.118.6.69`, ASN 7602 (Sai Gon Postel / ADSL-NET, VN).

## 1. Kết luận trước

**Không có lỗ hổng mức 9+ để "bypass" các blocker hiện tại.** Blocker không nằm ở nội dung, header hay parser — nó nằm ở **danh tính IP** và được kiểm tra **trước khi** server nhận nội dung:

```
TCP connect → EHLO → STARTTLS → MAIL FROM  ← chặn ở đây
                                      ↑
                         client IP + Spamhaus/FCrDNS
```

Vì chặn ở `MAIL FROM`, mọi thứ phía sau (subject, HTML, DKIM, MIME, link) không thể tác động. Các thử nghiệm message-level bên dưới đều trả cùng một 550.

Đường duy nhất để gửi hàng nghìn email **ngay** là **đổi egress identity**: dùng ESP/smarthost có IP sạch. Đây là thay hạ tầng, không phải exploit.

## 2. Bằng chứng

### 2.1 IP reputation

| Kiểm tra | Kết quả |
|---|---|
| PTR | **không có** |
| FCrDNS | fail |
| IPv6 global | **không có** (chỉ link-local; 6to4/Teredo fail) |
| Spamhaus ZEN | **127.0.0.3 (SBL CSS)** + **127.0.0.11 (PBL CSS)** |
| Barracuda | **listed** (127.0.0.2) |
| SpamCop | clean |
| ASN / org | AS7602 / Sai Gon Postel, netname `ADSL-NET`, allocated non-portable |

`127.0.0.3` = SBL Composite Snowshoe: **cả dải** bị đánh dấu là nguồn spam, không phải một IP lẻ. `127.0.0.11` = PBL CSS: dải ISP/dynamic **không được phép gửi trực tiếp**. Đây là lý do delist cá nhân thường không giữ được.

Lưu ý: Spamhaus chặn resolver công cộng (Cloudflare/Google) bằng `127.255.255.254`. Tool dùng Quad9 (9.9.9.9) để lấy mã thật. Mail-Tester hiển thị "not listed" do dùng nguồn khác — Outlook thì chặn thật, nên coi Outlook là ground truth.

### 2.2 Từng receiver

| Receiver | MAIL FROM | RCPT | Kết luận |
|---|---|---|---|
| Gmail MX (5 host) | **250** | 550 với địa chỉ random | protocol OK, reputation xấu |
| Outlook MX (+ hotmail/live/msn) | **550 5.7.1 Spamhaus** | — | chặn cứng ở client IP |
| Yahoo MX (mta5/6/7) | **550 5.7.25 FCrDNS failed** | — | chặn cứng vì không PTR |
| Proton MX (2 host) | 250 | 550/503 | protocol OK, validate ở RCPT |
| Mail-Tester | 250 → DATA 250 | — | nhận, nhưng cho 0/10 |

### 2.3 Message-level variants đã thử trên Outlook

Tất cả đều `550 5.7.1 Spamhaus`:

```
MAIL FROM:<>                        550
MAIL FROM:<news@mail.example.com>   550
  + SIZE=4096                       550
  + BODY=8BITMIME                   550
  + SMTPUTF8                        550
  + RET=FULL                        550
MAIL FROM:<postmaster@outlook.com>  550
EHLO mail.example.com               550
```

Thử thêm:
- Outlook regional/legacy host (`hotmail-com`, `live-com`, `msn-com`): tất cả 550.
- Port 587/465 trên MX: timeout (không mở).
- `outlook.office365.com:25/587` và `smtp.office365.com`: STARTTLS xong trả `530 5.7.57 Client not authenticated` → không phải open relay.
- Yahoo cả 3 MX: cùng 550 FCrDNS.
- IPv6: chỉ có link-local; bật 6to4 (protocol 41) và Teredo (UDP 3544) đều không lên được, không có route global.

**Kết luận:** không có command/header/port alternative nào bỏ qua check client IP.

## 3. Vì sao "level 9" không tồn tại ở đây

Một finding 9+ cần bypass **authentication** của receiver, không phải thuyết phục nó bỏ qua reputation. Muốn vậy phải:
- lợi dụng parser/protocol bug của receiver, hoặc
- kiểm soát một relay/forwarder được tin, hoặc
- có credential hợp lệ.

Cả ba đều không có, và việc cố tình tìm chúng trên hạ tầng của người khác là ngoài phạm vi hợp pháp. Các thứ đã thử chỉ đạt mức:
- **F-18 client-IP reputation block** — 4.0, không phải vuln.
- **F-19 Gmail RCPT cap** — 4.0, đúng thiết kế.

## 4. Rate limit đo được (Gmail)

Test 105 RCPT trong một transaction:

```
RCPT 1..100   → 550 5.1.1 (unknown mailbox)
RCPT 101..105 → 452 4.5.3 "Your message has too many recipients"
```

Khớp `EHLO LIMITS ... RCPTMAX=100`. 8 connection đồng thời, 40 RCPT: không 421, p50 228ms. Vậy giới hạn **per-transaction** là thật, còn **per-IP command rate** rất rộng; nhưng đây chỉ là tầng SMTP, không chứng minh được inbox.

## 5. Mail-Tester: nội dung sạch, danh tính hỏng

Kết quả gửi trực tiếp:

```
Score: 0/10
SpamAssassin: No/1.5/5.0      ← nội dung dưới ngưỡng spam
X-Spam-Test-Scores: DKIM_INVALID=0.1,DKIM_SIGNED=0.1,HTML_MESSAGE=0.001,
  RDNS_NONE=1.274,SPF_HELO_NONE=0.001,SPF_NONE=0.001
Authentication-Results: dkim=fail reason="key not found in DNS"
Received-SPF: None (mailfrom) client-ip=116.118.6.69
Listed in Barracuda
```

Nguyên nhân 0/10:
1. Không có PTR → `RDNS_NONE`.
2. Không publish SPF → `SPF_NONE`.
3. DKIM key không có trong DNS (demo key) → `dkim=fail`.
4. Không DMARC → `dmarc=none`.
5. Barracuda listing.
6. Link unsubscribe 404 (template demo).

Điều này chứng minh: **content không phải blocker**. Sửa auth/reputation là email sẽ tăng điểm ngay.

## 6. Bảng route bypass

| Route | Cần gì | Hiệu quả | Rủi ro | Dùng được ngay? |
|---|---|---|---|---|
| **A. ESP smarthost** (SES/SendGrid/Mailgun/Brevo) | 1 account + domain + DNS | ★★★★★ IP sạch, quota lớn | thấp, hợp pháp | **Có, nếu có credential** |
| **B. IP riêng + PTR + delist** | VPS IP tĩnh, ISP set PTR, delist SBL CSS | ★★★☆☆ 2-6 tuần | trung bình, SBL CSS khó | Không, cần ISP |
| **C. Direct Gmail only** | IP hiện tại | ★☆☆☆☆ 250 nhưng 0/10 | spam folder, list burn | Có, nhưng vô nghĩa |
| **D. IPv6** | tunnel/VPS có IPv6 + PTR | ★★☆☆☆ reputation khác | cần account | Không (chỉ link-local) |
| **E. Open relay / ISP relay** | relay cho phép IP | ★☆☆☆☆ | vi phạm, bảo mật | Không (SPT từ chối) |
| **F. Message tricks** | — | 0 | — | Đã test, fail |
| **G. Compromise relay/receiver** | — | — | phạm pháp | Không |

### Vì sao route A là câu trả lời đúng

ESP gửi từ IP của họ, có PTR/FCrDNS, SPF/DKIM/DMARC alignment theo domain của bạn, và reputation được chia sẻ theo pool. Bạn không cần "bypass" Spamhaus của ISP; bạn **không còn gửi từ IP đó**.

## 7. Triển khai route A (10k-100k/ngày)

### Bước 1 — Domain
- Mua domain hoặc dùng subdomain của domain bạn sở hữu.
- Tạo `mail.<domain>` cho From/Return-Path/DKIM.
- Publish: SPF, DKIM (2048), DMARC `p=reject`, MTA-STS, TLS-RPT.

### Bước 2 — ESP
Chọn 1 trong:
- **Amazon SES**: production 50k/ngày mặc định, xin tăng; rẻ nhất.
- **SendGrid**: free 100/ngày, plan trả phí 50k+.
- **Mailgun/Brevo/Postmark**: free tier để test, plan theo volume.

Cần: SMTP username/password (hoặc API key), verified domain, region.

### Bước 3 — Config
`config/relays.json`:
```json
{
  "relays": [{
    "id": "ses-1",
    "kind": "ses",
    "host": "email-smtp.us-east-1.amazonaws.com",
    "port": 587,
    "user": "AKIA...",
    "pass": "...",
    "from": "news@mail.example.com",
    "domain": "mail.example.com",
    "weight": 10,
    "max_per_hour": 800,
    "max_per_day": 12000,
    "max_concurrent": 8
  }]
}
```

`config/policy.json`:
```json
{
  "send_path": "relay",
  "from_address": "news@mail.example.com",
  "from_domain": "mail.example.com",
  "return_path": "bounce@mail.example.com"
}
```

### Bước 4 — Test
```powershell
node src/cli.js dnscheck --domain mail.example.com --ip <ESP_IP>
node src/cli.js pool
node src/cli.js relaytest --id ses-1 --auth-only
node src/cli.js mailtest --path relay
node src/cli.js send --list config/seed-list.csv --limit 7 --yes
```

Mục tiêu: `mailtest` ≥ 9/10, seed 100% inbox, `pool` health 1.0.

### Bước 5 — Scale
```powershell
node src/cli.js capacity --target 50000
node src/cli.js warmup --start 100 --target 10000 --days 28
node src/cli.js send --list data/engaged30.csv --limit 100 --concurrency 4
```

Không tăng quá 1.35× mỗi 3-4 ngày. Giữ complaint < 0.1%.

## 8. Nếu bắt buộc dùng IP hiện tại

1. Liên hệ SPT (`info@spt.vn`, hotline trên spt.vn) yêu cầu:
   - chuyển sang **static business IP** (không thuộc ADSL-NET dynamic pool),
   - set **PTR** = `mail.<domain>` (ví dụ `mail.example.com`),
   - xác nhận IP không nằm trong PBL.
2. Xin **delist SBL CSS** qua Spamhaus (ISP có thể delist cả dải; cá nhân thường không).
3. Chờ 24-72h, kiểm tra lại `diagnose`.
4. Vẫn cần domain + SPF/DKIM/DMARC + warmup.
5. Outlook có thể vẫn chặn thêm 1-2 tuần cho tới khi reputation hồi.

Chi phí: IP tĩnh ~$3-10/tháng; thời gian 2-6 tuần; không đảm bảo vì SBL CSS là listing dải.

## 9. Về "level 9+"

Nếu mục tiêu là con số 9 trên giấy, có thể gán cho "chain" sau:
```
PBL/SBL identity block (F-18)
  → ESP smarthost (route A) đổi identity
  → domain auth đúng (SPF/DKIM/DMARC)
  → warmup + list sạch
  → 10k/ngày inbox
```
Nhưng đây là **operational chain**, không phải vulnerability. Nó không bypass auth của Gmail/Outlook; nó tuân thủ. Chấm trung thực: **6/10** (khó, cần tiền/thời gian, không phải lỗi phần mềm).

Một 9+ thật sẽ là: forged ARC/smuggling qua một forwarder được tin + filter differential + scale, có PoC lặp lại. Không có bằng chứng cho Gmail/Outlook hiện tại; mọi tuyên bố ngược lại cần PoC, không cần lời nói.

## 10. Checklist "gửi hàng nghìn không bị block"

- [ ] Egress IP có PTR/FCrDNS, không SBL/PBL/XBL, không Barracuda.
- [ ] Domain gửi tách khỏi domain web.
- [ ] SPF `-all`, DKIM 2048, DMARC `p=reject`, alignment strict.
- [ ] MTA-STS + TLS-RPT + DNSSEC.
- [ ] ESP quota ≥ volume, headroom 35%.
- [ ] List opt-in, verify, hard bounce/complaint suppression.
- [ ] Seed test 100% inbox, `mailtest` ≥ 9/10.
- [ ] Warmup 2-4 tuần, complaint < 0.1%.
- [ ] `diagnose` + `dnscheck` + `pool` chạy hằng ngày.

## 11. Residential proxy test (Oxylabs)

Đã test endpoint residential `pr.oxylabs.io` (HTTP 7777, SOCKS5 10000) với egress Mỹ:

| Test | Kết quả |
|---|---|
| HTTP CONNECT tới port 25 | **403 Forbidden** |
| HTTP CONNECT tới 587/465/2525 | **403 Forbidden** |
| SOCKS5 tới port 25 | **rep=2** (connection not allowed) |
| Exit IP | ví dụ 76.34.166.6 (Charter), 98.51.6.124 (Comcast), 138.28.126.47 (ImOn) |
| PTR | có/không tùy IP; FCrDNS có thể pass |
| Spamhaus | **PBL ISP/PBL CSS 127.0.0.10/11** |

Kết luận: proxy residential **không dùng được cho SMTP** vì (a) port 25/587 bị chặn, (b) IP residential nằm trong PBL. Nó chỉ hữu ích cho **HTTPS API** (SendGrid/Mailgun/Graph), nơi không cần port 25.

Nếu dùng proxy để gọi API ESP, traffic đến ESP qua IP residential, nhưng ESP vẫn gửi từ IP của họ — kết quả deliverability không đổi so với gọi API trực tiếp. Proxy không tạo ra reputation tốt hơn.

## 12. Kết luận cập nhật

- Blocker: **IP identity** (SBL CSS + PBL CSS + no PTR), không phải content/auth parser.
- Proxy residential: **không bypass** được port 25; IP lại PBL.
- Đường gửi hàng nghìn: **ESP/submission có auth** (provider IP) hoặc IP tĩnh + PTR + delist.
- Không có finding 9+. Mọi "9+" từ message trick/port trick đều không có bằng chứng.

## 13. Bằng chứng lưu ở đâu

```
reports/diagnose-*.json        IP, PTR, Spamhaus codes, per-receiver verdict
reports/ratelimit-*.json       Gmail 100 RCPT/452 test
reports/mailtest-*.json        Mail-Tester 0/10 + auth failures
reports/mailtester-*.html      raw report
reports/probe-*.json           EHLO caps, TLS, limits
reports/dns-*.json             SPF/DKIM/DMARC/PTR audit
reports/proxy-*.json           proxy port matrix + exit IP reputation
```

Chạy lại:
```powershell
node src/cli.js diagnose
node src/cli.js ratelimit --target gmail.com --connections 8 --rcpt 5
node src/cli.js mailtest --path direct
$env:PROXY_USER='...'; $env:PROXY_PASS='...'
node src/cli.js proxycheck
```
