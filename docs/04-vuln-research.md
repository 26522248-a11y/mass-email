# 04 — Nghiên cứu lỗ hổng receiver: Gmail, Outlook, Yahoo, Proton

Mục tiêu của tài liệu: mô tả **bề mặt tấn công** của các hệ thống nhận mail, cách đo bằng tool trong repo, và trạng thái từng finding. Tất cả test chủ động chỉ trên domain/mailbox của bạn hoặc trong lab.

> "Level 9+" là điểm cho một **chain** có bằng chứng, không phải nhãn tự gắn. Phần 6 định nghĩa chain đó và vì sao các quan sát hiện tại chưa đạt.

**Báo cáo blocker thực tế của host hiện tại (SBL CSS + PBL CSS, Outlook/Yahoo 550, Gmail RCPT cap): `docs/09-bypass.md`.**

---

## 1. Bề mặt tấn công

```
┌──────────────────────── receiver ────────────────────────┐
│                                                          │
│  DNS          MX/SPF/DKIM/DMARC/MTA-STS/BIMI             │
│  TCP/TLS      banner, cert, STARTTLS, TLS version        │
│  SMTP         EHLO caps, SIZE, PIPELINING, CHUNKING      │
│               MAIL/RCPT semantics, null sender, UTF-8    │
│  DATA         line endings, dot-stuffing, 8BITMIME       │
│  MIME         boundary, nested multipart, encodings      │
│  Auth         SPF alignment, DKIM canonicalization, ARC  │
│  Policy       rate limits, reputation, tenant allow/block│
│  UI           display name, threading, tabs, warnings    │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

Mỗi tầng có một lớp lỗi khác nhau:
- **Protocol**: parsing sai → smuggling, command injection.
- **Auth**: canonicalization/alignment sai → spoof.
- **Policy**: quota/accounting sai → scale bất thường.
- **UI**: hiển thị gây nhầm → phishing (thường không phải lỗi server).

---

## 2. Methodology

### Phase 1 — Passive
`dnscheck`, `dig`/DoH, Postmaster Tools, SNDS, DNSBL. Không gửi gì.

### Phase 2 — Fingerprint
`probe` mở một SMTP session, EHLO, STARTTLS, thử MAIL/RCPT với địa chỉ random, đọc cap và timing. Không DATA.

### Phase 3 — Differential
So sánh response của:
- địa chỉ tồn tại (mailbox test của bạn) vs random;
- local-part có dấu chấm/plus vs không;
- case upper/lower;
- domain nhận khác nhau;
- IPv4 vs IPv6 (nếu có).
Ghi code + text + thời gian. Sai khác > 50ms hoặc text khác → oracle tiềm năng.

### Phase 4 — Lab
Dựng MTA trong VM (Postfix/Exim/Haraka) phiên bản cũ, test boundary/parser ở đó. Không test lên MX production.

### Phase 5 — Disclosure
Ghi evidence, CVSS, repro tối thiểu, gửi security@vendor, 90 ngày.

---

## 3. Kết quả quan sát (25/11/2026, IP 116.118.6.69)

### Gmail

```
banner : 220 mx.google.com ESMTP ...
EHLO   : 250-SIZE 157286400
         250-8BITMIME / STARTTLS / ENHANCEDSTATUSCODES
         250-PIPELINING / CHUNKING / SMTPUTF8
         250 LIMITS MAILMAX=1000 RCPTMAX=100 RCPTDOMAINMAX=1
TLS    : TLSv1.3, TLS_AES_256_GCM_SHA384
cert   : CN=mx.google.com, issuer Google Trust Services WE2
MAIL<> : 250 (null sender accepted)
MAIL   : 250
RCPT random : 550 5.1.1 NoSuchUser
RCPT 100    : 550; RCPT 101-105 : 452 4.5.3 "too many recipients" (đo 25/11/2026)
SIZE over   : 552 5.3.4 MaxSizeError
RCPT UTF-8  : 550 (không tồn tại, không phải lỗi UTF-8)
case upper  : 550 (cùng kết quả)
dot alias   : 550 (alias không tồn tại)
timing      : ~240ms/command
```

**Đọc:** Gmail validate recipient tại RCPT, trả 550 cho unknown → đây là **enumeration oracle** ở mức thấp (ai cũng biết địa chỉ Gmail có tồn tại hay không; rate limit bảo vệ). Null sender được chấp nhận là đúng RFC 5321 (bounce). `LIMITS` là thông tin vận hành hữu ích, không phải lỗi.

### Outlook

```
banner : 220 ...mail.protection.outlook.com Microsoft ESMTP ...
EHLO   : SIZE 49283072, PIPELINING, DSN, ENHANCEDSTATUSCODES,
         STARTTLS, 8BITMIME, BINARYMIME, CHUNKING, SMTPUTF8
TLS    : TLSv1.3
MAIL   : 550 5.7.1 Service unavailable, Client host blocked using Spamhaus
```

**Đọc:** IP egress của máy này đang bị Spamhaus → Outlook chặn ngay tại MAIL FROM và đóng session. Đây là **reputation enforcement**, không phải lỗi. Bài học: đổi IP/relay trước khi debug nội dung.

### Yahoo

```
MAIL : 550 5.7.25 Forward-confirmed reverse DNS failed
```

**Đọc:** Yahoo yêu cầu FCrDNS nghiêm ngặt. Không có PTR khớp → chặn. Đây là checklist item, không phải vuln.

### Proton

```
MAIL<> : 250 (accepted)
MAIL   : 250
RCPT   : 503 (greylist/challenge)
SIZE   : 71.5 MB
```

**Đọc:** 503 tại RCPT là chống abuse/greylisting, không phải mailbox invalid. Retry sau vài phút.

---

## 4. Findings register

| ID | Tên | Class | Severity | Status |
|---|---|---|---|---|
| F-01 | RCPT enumeration oracle | enumeration | 5.5 | OBSERVED (Gmail) |
| F-02 | SMTP smuggling boundary | protocol | 8.0 | THEORETICAL / patched ở MTA phổ biến |
| F-03 | ARC chain forgery | auth | 7.5 | THEORETICAL |
| F-04 | DKIM replay / `l=` truncation | auth | 5.0 | THEORETICAL |
| F-05 | MIME parser differential | parser | 6.5 | THEORETICAL |
| F-06 | DMARC weak/misaligned policy | config | 6.0 | COMMON |
| F-07 | SPF lookup exhaustion | DNS | 4.5 | THEORETICAL |
| F-08 | Display-name/IDN homoglyph | UI | 3.5 | OBSERVED industry-wide |
| F-09 | Thread injection (`In-Reply-To`) | UI/logic | 3.0 | OBSERVED behavior |
| F-10 | Dot/plus alias semantics | feature abuse | 2.0 | INFO |
| F-11 | Rate accounting gaps | policy | 4.0 | OBSERVED limits |
| F-12 | Null-sender acceptance | protocol | 2.0 | INFO (RFC-compliant) |
| F-13 | Header injection via folding | parser | 4.0 | PATCHED in modern stacks |
| F-14 | Tenant header trust | policy | 3.0 | THEORETICAL |
| F-15 | BIMI/VMC impersonation | UI | 2.5 | THEORETICAL |
| F-16 | Client-IP reputation hard block (Spamhaus/FCrDNS) | policy | 4.0 | OBSERVED |
| F-17 | Gmail RCPT cap 100/transaction | rate | 4.0 | OBSERVED |
| F-18 | Message-variant bypass of IP block | protocol | 2.0 | TESTED, FAILED |
| F-19 | Missing PTR/SPF/DKIM/DMARC on sender | config | 6.0 | OBSERVED |

---

## 5. Chi tiết từng finding

### F-01 — RCPT enumeration oracle (5.5, OBSERVED)

**Mô tả:** Gmail trả `550 5.1.1` cho local-part không tồn tại và `250` cho tồn tại. Kẻ tấn công có thể xác thực danh sách địa chỉ, đo tốc độ, phát hiện catch-all.

**Điều kiện:** kết nối port 25 từ IP không bị chặn; rate limit theo IP/ngày.

**Repro (chỉ với mailbox của bạn):**
```powershell
node src/cli.js verify --list tests/fixtures/list.csv --out reports/enum.json
```
So sánh `valid` / `invalid` / `unknown`, xem `timing`.

**Tác động:** list validation, targeted phishing, privacy (biết ai dùng Gmail). Không cho phép gửi thay người khác.

**Giảm thiểu (receiver):** trả cùng một response cho mọi RCPT, defer validation sang DATA/bounce, rate limit theo IP + ASN, tarpit.

**Trạng thái:** hành vi có chủ đích để chống backscatter; không phải lỗi bảo mật nghiêm trọng.

---

### F-02 — SMTP smuggling (8.0, THEORETICAL)

**Mô tả:** MTA không thống nhất cách nhận end-of-data:
- chuẩn: `<CRLF>.<CRLF>`
- một số nhận `<LF>.<LF>` hoặc `<CRLF>.<LF>`

Kẻ tấn công chèn chuỗi kết thúc "lạ" vào body; MTA trung gian thấy 1 message, receiver thấy 2 → message thứ hai có thể mang envelope/From khác.

**Phạm vi thật:** chủ yếu ở **MTA trung gian/outbound** (Postfix < 3.8.4, Exim, Sendmail cũ, một số appliance). Không có bằng chứng công khai rằng Gmail/Outlook inbound bị ảnh hưởng ở thời điểm này. Đừng gán CVE cho receiver khi chưa test.

**Test an toàn:** lab Postfix 3.7 + script gửi body chứa `\n.\n`; xem receiver log có 2 message không. Không gửi lên MX production.

**Tác động nếu có:** spoof From, bypass SPF/DKIM của message thứ hai, filter evasion.

**Fix:** chuẩn hóa line ending ở MTA, reject bare LF trong DATA, upgrade.

**Trạng thái:** đã vá ở đa số MTA; vẫn cần kiểm tra appliance cũ.

---

### F-03 — ARC chain forgery (7.5, THEORETICAL)

**Mô tả:** ARC cho phép forwarder thêm `ARC-Seal`/`ARC-Message-Signature` để chứng minh chain. Một số receiver tin ARC như tín hiệu auth khi forward. Nếu kẻ tấn công kiểm soát một forwarder hoặc lấy được key, có thể tạo chain "hợp lệ" cho message đã bị sửa.

**Điều kiện:** receiver có tin ARC; attacker có domain + key; chain không bị kiểm tra đầy đủ.

**Test:** dựng 2 MTA lab, forward qua một bên, sửa body, xem bên nhận có pass không. Không test trên người thật.

**Tác động:** auth pass cho nội dung sửa, phishing qua mailing list.

**Fix (receiver):** chỉ tin ARC khi `arc=pass` + DKIM/SPF gốc pass, giới hạn forwarder, log chain.

**Trạng thái:** thiết kế ARC không phải security boundary; nhiều receiver đã thận trọng.

---

### F-04 — DKIM replay / `l=` truncation (5.0)

**Mô tả:**
- DKIM không có expiry mặc định; message ký có thể replay nguyên vẹn.
- `l=` cho phép chỉ ký N byte đầu; phần thêm vào sau có thể không bị kiểm tra bởi verifier lỏng.

**Tác động:** replay một email hợp lệ với link đã thay (nếu link không nằm trong phần ký), hoặc thêm nội dung.

**Fix:** ký toàn bộ body (không `l=`), dùng `x=` expiry, link token ngắn hạn, receiver reject `l=` bất thường.

**Trạng thái:** lý thuyết; Gmail/Outlook hiện đại xử lý `l=` chặt hơn.

---

### F-05 — MIME parser differential (6.5, THEORETICAL)

**Mô tả:** hai parser (filter vs client) hiểu boundary/encoding khác nhau:
- boundary xuất hiện trong body;
- nested `multipart/mixed` không đóng;
- `Content-Transfer-Encoding` sai;
- encoded-word trong header bị decode khác;
- HTML comment / CSS `display:none` che text.

Kết quả: filter thấy nội dung vô hại, client hiển thị nội dung khác (hoặc ngược lại).

**Test:** gửi cùng một message tới 2 mailbox (Gmail + Outlook) của bạn, so sánh HTML/text hiển thị và "show original". Dùng `tests/` mock để tạo biến thể.

**Tác động:** filter evasion, phishing, tracking.

**Fix:** parser strict theo RFC, giới hạn nesting, reject boundary trùng, render theo cùng parser với filter.

**Trạng thái:** class lỗi còn tồn tại; không có PoC công khai ổn định cho Gmail/Outlook.

---

### F-06 — DMARC weak/misaligned (6.0, COMMON)

Các lỗi thấy ngoài thực tế:
- `p=none` ở org domain → không bảo vệ.
- thiếu `sp` + subdomain bị takeover.
- `adkim=r`/`aspf=r` → subdomain gửi thay được.
- `rua` trỏ ra ngoài không có authorization → mất report.
- chỉ publish DMARC cho `mail.` nhưng gửi từ `news.` → không áp dụng.

**Test:** `node src/cli.js dnscheck --domain <domain>`.

**Fix:** `p=reject; sp=reject; adkim=s; aspf=s; pct=100`, publish ở org domain, thêm `rua`.

---

### F-07 — SPF lookup exhaustion (4.5)

**Mô tả:** SPF vượt 10 DNS lookup → `permerror`; receiver có thể coi là fail. Kẻ tấn công kiểm soát một domain được `include:` có thể gây quá tải lookup (nếu domain đó có nhiều include), hoặc lợi dụng `exists:`/macro để tăng lookup.

**Tác động:** SPF fail → spam; DoS nhẹ cho domain nạn nhân.

**Test:** `dnscheck` đếm lookup; cố tình thêm include chain trong lab.

**Fix:** flatten SPF, giới hạn include, dùng `ip4/ip6` trực tiếp.

---

### F-08 — Display-name / IDN homoglyph (3.5)

**Mô tả:** `From: "PayPal Support" <attacker@evil.tld>` hiển thị tên giống thật; IDN homoglyph (`а` Cyrillic vs `a` Latin) trong domain.

**Tác động:** phishing, brand damage.

**Fix:** client hiển thị domain rõ, cảnh báo external sender, DMARC reject + BIMI để hiển thị logo.

**Trạng thái:** UI industry-wide; không phải lỗi server.

---

### F-09 — Thread injection (3.0)

**Mô tả:** set `In-Reply-To`/`References` tới Message-ID của thread có sẵn → client gộp vào thread, có thể bypass một số filter/attention.

**Test:** gửi 2 message tới mailbox của bạn, message 2 set References; quan sát Gmail/Outlook.

**Tác động:** social engineering, giảm cảnh giác.

**Fix:** client xác thực thread theo DKIM/From; không gộp nếu sender khác.

---

### F-10 — Dot/plus alias (2.0, INFO)

- Gmail: `a.b@gmail.com` = `ab@gmail.com`; `user+tag@gmail.com` = `user@gmail.com`.
- Outlook: `user+tag@outlook.com` (plus addressing).
- Không phải lỗ hổng; là feature. Dùng để test dedupe, chống bom list, hoặc đo hành vi.

**Lưu ý:** không dùng để "tạo vô hạn email" — mọi alias đều về cùng mailbox, vi phạm ToS nếu lạm dụng.

---

### F-11 — Rate accounting gaps (4.0, OBSERVED)

- Quota thường tính per-account, không per-IP; nhiều account cùng IP vẫn bị reputation chung.
- Gmail `RCPTDOMAINMAX=1` buộc tách transaction theo domain.
- Một số ESP tính quota theo "recipient" nhưng rate theo "message" → chênh lệch khi nhiều RCPT/message.
- Retry có thể bị tính quota 2 lần nếu không idempotent.

**Khai thác:** không phải để vượt quota, mà để **tối ưu** trong quota: gom RCPT cùng domain, tránh retry mù, theo dõi cả 2 đơn vị.

**Code:** `pool.js` đếm `sentHour/sentDay` theo message; `queue.js` idempotent theo job id.

---

### F-12 — Null sender (2.0, INFO, OBSERVED)

`MAIL FROM:<>` được Gmail/Proton chấp nhận — đúng RFC cho bounce. Rủi ro: nếu receiver forward bounce không kiểm tra, có thể backscatter. Không phải lỗi.

---

### F-13 — Header injection via folding (4.0, PATCHED)

CRLF trong header value → inject header. Các stack hiện đại chặn; nhưng template engine tự viết có thể bỏ sót.

**Code:** `mime.js` strip `[\r\n]` trong `encodeHeader`; `foldHeader` chỉ fold bằng space.

**Test:** thử subject chứa `\r\nBcc:` trên mock server → phải bị loại.

---

### F-14 — Tenant header trust (3.0, THEORETICAL)

Một số header `X-MS-Exchange-*` có thể ảnh hưởng routing/tenant nếu được tin từ nguồn ngoài. Modern Exchange strip header ngoài. Test trong lab Exchange, không gửi production.

---

### F-15 — BIMI/VMC impersonation (2.5)

BIMI cần VMC (Verified Mark Certificate) cấp cho domain; kẻ tấn công không thể giả logo nếu receiver kiểm tra VMC. Rủi ro ở client không validate hoặc cache logo theo display name.

**Fix:** DMARC reject + BIMI + VMC; client kiểm tra cert.

---

## 6. "Level 9+" trông như thế nào

Một chain đủ 9 phải có **4 mắt xích**, mỗi mắt có evidence:

```
(1) AUTH BYPASS      gửi được với From domain không sở hữu
(2) INBOX            filter pass, không bị spam folder
(3) SCALE            vượt quota/rate mà không bị chặn
(4) STEALTH          không bị DNSBL/report trong 72h
```

Ví dụ chain lý thuyết (không tuyên bố tồn tại):
```
F-02 (smuggling qua appliance cũ)
  + F-05 (MIME differential qua filter)
  + F-11 (quota accounting per-message)
  + domain/IP warm đủ mạnh
= 9
```

**Hiện trạng:** F-02 đã vá ở MTA phổ biến; F-05 không có PoC ổn định; F-11 chỉ là tối ưu. Do đó **không finding nào trong repo đạt 9**. Báo cáo trung thực là một phần của nghiên cứu nghiêm túc; đừng nâng điểm bằng suy đoán.

Nếu bạn tìm được chain thật:
- giữ PoC tối thiểu, không gửi tới người thật;
- báo vendor, xin safe harbor;
- công bố sau 90 ngày hoặc theo thỏa thuận;
- không bán cho spam operation.

---

## 7. Cách mở rộng harness

### Thêm test case MIME
```js
// tests/mime-cases.mjs
const cases = [
  { name: 'boundary-collision', raw: '...' },
  { name: 'nested-unclosed', raw: '...' },
  { name: 'encoded-word-split', raw: '...' },
];
```
Gửi lần lượt tới Gmail + Outlook của bạn, lưu `show original` và ảnh chụp, so sánh.

### Thêm SMTP command fuzz (lab only)
```js
for (const cmd of ['MAIL FROM:<>\r\n', 'MAIL FROM:<a@b>\n', 'RCPT TO:<a@b> SIZE=1']) {
  // gửi tới MTA trong VM, log response + connection state
}
```

### Đo timing oracle
```js
const t = []; for (let i=0;i<20;i++) t.push(await rcpt(random()));
// so sánh median valid vs invalid; > 50ms + p<0.05 → oracle
```

### Lab
Xem `research/README.md` và `research/hypotheses.md`.

---

## 8. Disclosure template

`research/disclosure-template.md` có mẫu email báo cáo: summary, impact, repro, evidence, suggested fix, timeline.

---

## 9. Kết luận

- Gmail/Outlook **không dễ** có lỗi auth bypass; reputation là hàng rào chính.
- Phần lớn "email vào spam" là lỗi cấu hình/consent, không phải lỗi provider.
- Giá trị thực của repo: đo được, sửa được, và chứng minh bằng số liệu.
- Finding 9+ nếu có sẽ đến từ **parser/protocol chain**, không từ content trick.
