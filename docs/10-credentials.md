# 10 — Credentials: cách cấp quyền gửi và giới hạn thực tế

## 1. Nguyên tắc

- **Không paste mật khẩu vào chat.** Ghi trực tiếp vào `config/relays.json` trên máy này (file đã bị `.gitignore`), hoặc dùng biến môi trường.
- Mỗi credential chỉ dùng cho đúng mục đích; không chia sẻ ra ngoài.
- Bật 2FA và tạo **app password** riêng; thu hồi ngay khi xong.
- Không dùng credential của người khác.

## 2. Chọn loại credential

| Credential | Dùng được cho | Volume/ngày | Ghi chú |
|---|---|---|---|
| Gmail app password | `smtp.gmail.com:587` | ~500 | From phải là Gmail hoặc alias đã xác minh |
| Google Workspace app password/OAuth | `smtp.gmail.com:587` | ~2.000/user | admin có thể tắt app password |
| Outlook.com app password | `smtp-mail.outlook.com:587` | ~300 | From phải là account/alias |
| M365 OAuth (Graph/SMTP XOAUTH2) | `smtp.office365.com:587` hoặc Graph | ~10.000/mailbox | basic auth đã bị tắt |
| ESP SMTP (SES/SendGrid/Mailgun/Brevo) | host của ESP | 50k+ | tốt nhất cho bulk |
| ESP API key | HTTPS API | 50k+ | không cần SMTP, hợp với proxy |

**Điểm quan trọng:** khi gửi qua submission/ESP, receiver thấy **IP của provider**, không phải IP `116.118.6.69`. Vì vậy SBL/PBL của host hiện tại không còn là blocker. Đây là "bypass" hợp pháp duy nhất.

## 3. Gmail consumer

1. Bật 2-Step Verification.
2. Tạo App Password (16 ký tự), chọn "Mail".
3. Điền (bỏ khoảng trắng trong app password):
```json
{
  "id": "gmail-1",
  "kind": "gmail",
  "host": "smtp.gmail.com",
  "port": 587,
  "user": "you@gmail.com",
  "pass": "abcd efgh ijkl mnop",
  "from": "you@gmail.com",
  "domain": "gmail.com",
  "return_path": "you@gmail.com",
  "max_per_day": 450,
  "max_concurrent": 1
}
```
4. Test:
```powershell
node src/cli.js relaytest --id gmail-1 --auth-only
node src/cli.js relaytest --id gmail-1 --to your-other-mailbox@example.com
```

**Giới hạn:** ~500 recipient/ngày/account, 100 recipient/message; vượt → khóa tạm. Không dùng cho cold list. From khác Gmail sẽ bị reject/rewrite; muốn brand domain phải cấu hình "Send mail as" và xác minh SMTP của domain đó.

Engine tự bind `From` và `Return-Path` theo `relay.from` / `relay.return_path`, nên khi pool nhiều account Gmail mỗi message dùng đúng account đã chọn.

## 4. Outlook.com consumer

1. Bật 2FA, tạo app password.
2. `smtp-mail.outlook.com:587`, STARTTLS.
3. `from` = chính account hoặc alias.
4. Volume ~300/ngày.

Lưu ý: Microsoft có thể chặn đăng nhập SMTP từ IP lạ; nếu vậy dùng ứng dụng mail chính thức hoặc Graph.

## 5. Microsoft 365 (Graph hoặc XOAUTH2)

Basic auth đã bị tắt. Cần:
- Azure app registration, permission `Mail.Send` (application) + admin consent, hoặc delegated `SMTP.Send`.
- Tenant ID, client ID, client secret.
- Lấy access token:
```
POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
grant_type=client_credentials
scope=https://graph.microsoft.com/.default
```
- Gửi bằng Graph:
```
POST https://graph.microsoft.com/v1.0/users/{sender}/sendMail
Authorization: Bearer <token>
```
hoặc SMTP XOAUTH2:
```json
{"auth":"XOAUTH2","user":"sender@contoso.com","access_token":"..."}
```
Volume ~10.000 recipient/ngày/mailbox; throttle 30 msg/phút.

## 6. ESP (khuyến nghị cho hàng nghìn)

### Amazon SES
- Verify domain, production access.
- SMTP credential từ IAM.
- 50k/ngày mặc định, xin tăng.
- $0.10/1.000 email.

### SendGrid
- Verify domain (SPF/DKIM).
- API key hoặc SMTP key.
- 100/ngày free; plan trả phí 50k+.

### Mailgun / Brevo / Postmark
- Verify domain, lấy SMTP/API key.
- Free tier để test; plan theo volume.

Cấu hình mẫu:
```json
{
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
}
```

## 7. From / Return-Path / DKIM

- ESP: `From: news@mail.example.com`, DKIM `d=mail.example.com`, Return-Path do ESP quản lý (hoặc `bounce@mail.example.com` nếu ESP cho).
- Gmail/Outlook consumer: `From` = account; DKIM do provider ký (`d=gmail.com` / `d=outlook.com`), DMARC pass.
- Không trộn: From `@gmail.com` nhưng DKIM `d=mail.example.com` → alignment fail.

## 8. Test trước khi gửi hàng loạt

```powershell
# 1. AUTH
node src/cli.js relaytest --id <id> --auth-only

# 2. Một message thật tới mailbox của bạn
node src/cli.js relaytest --id <id> --to you@example.com

# 3. Mail-Tester qua relay
node src/cli.js mailtest --path relay

# 4. Seed test
node src/cli.js send --list config/seed-list.csv --limit 7 --path relay

# 5. Batch nhỏ
node src/cli.js send --list data/list.csv --limit 50 --path relay
```

Mục tiêu: auth OK, mailtest ≥ 9/10, seed 100% inbox, không 550/421.

## 9. Nếu chỉ có Gmail/Outlook consumer

- 1 account: ~300-500/ngày.
- 10 account: ~3.000-5.000/ngày, nhưng vận hành phức tạp và **vi phạm ToS nếu dùng cho bulk marketing**.
- Không nên. Dùng Workspace/M365 hoặc ESP.

## 10. Bảo mật credential

- `config/relays.json` quyền 600, không commit.
- Không log `AUTH` (code đã redact).
- Rotate app password sau chiến dịch.
- Tách credential theo stream (transactional vs marketing).
- Nếu lộ: thu hồi, kiểm tra log gửi, đổi mật khẩu.
