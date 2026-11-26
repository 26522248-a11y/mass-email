# 12 — Branch test: nhánh nào gửi được thật

Mục tiêu: thử từng nhánh theo thứ tự hiệu quả, ghi lại cái gì chạy được, cái gì bị chặn, cần gì để chạy thật.

## 1. Bảng tổng hợp

| # | Nhánh | Kết quả test | Gửi thật? | Volume | Kết luận |
|---|---|---|---|---|---|
| 1 | **M365 Graph** | Payload + mock token/sendMail **202**; 2 test pass | Chưa (thiếu tenant/app) | 10k/mailbox/ngày | **Hiệu quả nhất**, cần `config/graph.json` |
| 2 | **Google Workspace SMTP** | `smtp.gmail.com:587` mở, STARTTLS, AUTH cơ chế đủ; sai pass → **535** (không phải IP block) | Chưa (thiếu app password/OAuth) | 2k/user/ngày | Rất tốt, cần credential |
| 3 | **Third-party SMTP qua auth** (Ethereal lab) | Tạo account test, gửi **3/3 → 250 Accepted**; MIME + DKIM + header OK | Có, nhưng Ethereal chỉ capture | test | Chứng minh engine + auth hoạt động |
| 4 | **ESP SMTP** (SendGrid/Mailgun/Brevo/SES) | Port 587 mở, AUTH advertised | Chưa (thiếu key) | 50k+/ngày | Tốt nhất cho volume lớn |
| 5 | **Gmail consumer app password** | Submission reachable; auth sai → 535 | Chưa | ~500/ngày | Chỉ test/Gmail-to-Gmail |
| 6 | **Outlook.com app password** | Submission reachable; auth sai → 535 | Chưa | ~300/ngày | Chỉ test |
| 7 | **Oxylabs residential proxy → SMTP** | 403 / SOCKS rep=2; exit IP PBL | Không | 0 | Bị chặn port + PBL |
| 8 | **Direct-to-MX từ IP hiện tại** | Gmail 250 nhưng Mail-Tester 0/10; Outlook/Yahoo 550 | Không | 0 | SBL CSS + PBL + no PTR |
| 9 | **Message/port tricks** | Tất cả 550/403 | Không | 0 | Không bypass check client IP |

## 2. Nhánh 1 — M365 Graph (khuyến nghị)

Đã implement:
- OAuth2 client credentials (`login.microsoftonline.com`).
- `POST /v1.0/users/{sender}/sendMail`.
- Header `List-Unsubscribe`, `List-Unsubscribe-Post`, `X-Entity-Ref-ID`.
- Retry 429 theo `Retry-After`, 401 refresh token, 5xx retry.

Test:
- Unit payload: pass.
- Mock token + sendMail: **202**, payload đúng.
- Chưa gửi thật vì không có tenant/client secret.

Cần:
```json
// config/graph.json
{
  "tenant_id": "...",
  "client_id": "...",
  "client_secret": "...",
  "sender": "news@yourdomain.com"
}
```
Permission `Mail.Send` (application) + admin consent.

## 3. Nhánh 2 — Google Workspace / Gmail

Test thực tế:
```
smtp.gmail.com:587
EHLO 250 → STARTTLS → AUTH LOGIN PLAIN XOAUTH2
AUTH sai → 535 (không bị chặn IP)
```
Vậy với app password đúng, Google sẽ nhận và gửi từ IP Google.

Volume:
- Gmail consumer: ~500 recipient/ngày.
- Workspace: ~2.000/user/ngày.
- From phải là account/alias; `Return-Path` nên là account.

## 4. Nhánh 3 — third-party SMTP có auth (Ethereal lab)

Đã tạo account test qua API (không dùng credential người thật), cấu hình relay tạm, gửi 3 message:

```
1 250 Accepted [STATUS=new MSGID=...]
2 250 Accepted [STATUS=new MSGID=...]
3 250 Accepted [STATUS=new MSGID=...]
```

Thời gian 2.3-3.9s/message (bao gồm TLS/auth). MIME 2.9KB, DKIM signature tạo đúng, `List-Unsubscribe` có mặt.

Ý nghĩa: engine + SMTP auth + MIME + queue hoạt động end-to-end. Ethereal **không giao tới Gmail/Outlook** (chỉ capture), nên không dùng cho production. Nhưng nó chứng minh nhánh "authenticated third-party SMTP" chạy được; thay host/user/pass bằng ESP thật là gửi thật.

## 5. Nhánh 4 — ESP

Đã kiểm tra reachability:
```
smtp.sendgrid.net:587        AUTH PLAIN LOGIN
smtp-relay.brevo.com:587     AUTH PLAIN LOGIN CRAM-MD5
smtp.mailgun.org:587         AUTH PLAIN LOGIN
email-smtp.us-east-1.amazonaws.com:587  AUTH PLAIN LOGIN
smtp.postmarkapp.com:587     AUTH ...
smtp.resend.com:587          AUTH PLAIN LOGIN
```
Chỉ thiếu credential. Đây là route tốt nhất cho 10k-50k/ngày.

## 6. Nhánh 5-6 — consumer mailboxes

- Gmail: submission mở, auth đúng → Google gửi. 500/ngày. Không đủ "hàng nghìn" trừ khi nhiều account (không khuyến nghị, vi phạm ToS bulk).
- Outlook: 300/ngày. Tương tự.
- Dùng để test nhanh hoặc gửi transactional volume nhỏ.

## 7. Nhánh 7-9 — đã fail

- Proxy: port 25/587/465 bị 403/rep=2; exit IP PBL.
- Direct: SBL CSS + PBL CSS + no PTR; Outlook/Yahoo 550.
- Message tricks: null sender, SIZE, 8BITMIME, SMTPUTF8, RET, regional MX, port 587/465 → 550/403.

## 8. Thứ tự thử đề xuất

1. **M365 Graph** — nếu có tenant. Volume cao nhất, inbox tốt nhất, không cần IP/domain mới.
2. **Google Workspace SMTP** — nếu có Workspace. 2k/user/ngày.
3. **ESP** — nếu có key. 50k+/ngày.
4. **Gmail/Outlook app password** — test nhanh, volume thấp.
5. **Ethereal** — chỉ lab, không delivery.

## 9. Lệnh test tương ứng

```powershell
# Graph
node src/cli.js graphtest --to you@example.com
node src/cli.js send --list data/list.csv --path graph --limit 100

# Gmail/Workspace/ESP
node src/cli.js relaytest --id <id> --auth-only
node src/cli.js relaytest --id <id> --to you@example.com
node src/cli.js mailtest --path relay

# Proxy/direct
node src/cli.js proxycheck
node src/cli.js diagnose
```

## 10. Kết luận

- Nhánh **hiệu quả nhất đã sẵn sàng về code** là M365 Graph; chỉ thiếu credential.
- Nhánh **đã chứng minh gửi được** trong lab là authenticated third-party SMTP (Ethereal 3/3).
- Nhánh **không cần credential** thì không có cách nào vào inbox hàng loạt: proxy/PBL/message tricks đều fail.
- Muốn "hàng nghìn vào hòm thư chính", chọn Graph hoặc ESP; consumer mailbox chỉ vài trăm/ngày.
