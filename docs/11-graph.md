# 11 — Microsoft 365 Graph: 10k/ngày, không cần IP sạch

Đây là cách gửi hàng nghìn email/ngày vào inbox chính mà **không cần** proxy, VPS, PTR, hay IP riêng: dùng mailbox Microsoft 365 của chính bạn, để Microsoft gửi từ hạ tầng của họ.

## 1. Vì sao hiệu quả

```
Bạn --HTTPS--> graph.microsoft.com --Microsoft IP--> Outlook/Gmail/Yahoo
```

- Không dùng port 25/587 → proxy chặn SMTP không ảnh hưởng.
- Receiver thấy IP Microsoft, reputation cao.
- SPF/DKIM/DMARC do tenant của bạn cấu hình; Microsoft ký.
- Giới hạn: **10.000 recipient/ngày/mailbox**, throttle ~30 message/phút.
- Một mailbox Business Basic ~$6/tháng.

Đây là route thực tế nhất cho "hàng nghìn/ngày, vào inbox chính" nếu bạn có M365.

## 2. Điều kiện

- Tenant Microsoft 365 + ít nhất 1 mailbox (sender).
- Quyền admin để tạo app registration và grant consent.
- Domain tenant đã có SPF/DKIM/DMARC (Microsoft tự tạo khi add domain; kiểm tra lại).

## 3. Tạo app (một lần)

### Azure Portal
1. Entra ID → App registrations → New registration.
2. API permissions → Microsoft Graph → **Application permissions** → `Mail.Send` → Grant admin consent.
3. Certificates & secrets → New client secret → copy value.
4. Ghi lại: Tenant ID, Client ID, Client Secret.

### Giới hạn mailbox được gửi (khuyến nghị)
Mặc định app `Mail.Send` có thể gửi thay **mọi mailbox** trong tenant. Giới hạn lại bằng ApplicationAccessPolicy:

```powershell
Connect-ExchangeOnline
New-ApplicationAccessPolicy -AppId <client-id> `
  -PolicyScopeGroupId <sender-group> `
  -AccessRight RestrictAccess `
  -Description "mass-email sender only"
```

## 4. Config

Copy `config/graph.example.json` → `config/graph.json` (đã gitignore):

```json
{
  "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "client_secret": "secret-value",
  "sender": "news@yourdomain.com"
}
```

## 5. Test

```powershell
node src/cli.js graphtest --to your-mailbox@example.com
```

Kỳ vọng:
```json
{ "status": "sent", "path": "graph", "code": 202 }
```

Nếu 401: token/sai secret. 403: thiếu `Mail.Send` hoặc admin consent. 404: sender mailbox không tồn tại.

## 6. Gửi

```powershell
node src/cli.js send --list data/list.csv --path graph --limit 100
```

Engine:
- render subject/HTML theo từng người,
- thêm `List-Unsubscribe`, `List-Unsubscribe-Post`, `X-Entity-Ref-ID`,
- POST `/v1.0/users/{sender}/sendMail`,
- retry 429 theo `Retry-After`, 5xx retry, 4xx bounce.

## 7. Giới hạn & pacing

| Giới hạn | Giá trị |
|---|---|
| Recipient/ngày/mailbox | ~10.000 |
| Message/phút | ~30 |
| Concurrent | 4-8 |
| Message size | 25 MB (Graph) |

Khuyến nghị:
- 1.000-2.000/ngày/mailbox trong 2 tuần đầu.
- Tăng 1.5× mỗi 3-4 ngày.
- Giữ 35% headroom.
- `429` → dừng 60s, không retry dồn.
- Nhiều mailbox → pool nhiều config? Hiện `graph.json` một sender; thêm nhiều sender bằng nhiều file hoặc mở rộng `senders: []`.

## 8. Hạn chế của Graph

- Body chỉ HTML (không multipart/alternative). Với marketing, thêm plain text bằng SMTP OAuth nếu cần.
- Không cho chỉnh `Return-Path`; Microsoft quản lý bounce.
- Custom headers bị giới hạn; `List-Unsubscribe` thường được giữ.
- App-only `Mail.Send` gửi thay mailbox; cần ApplicationAccessPolicy để giảm rủi ro.

## 9. Nếu không có M365

| Phương án | Volume | Ghi chú |
|---|---|---|
| Google Workspace SMTP (app password/OAuth) | ~2.000/user/ngày | $6/user; From = user/alias |
| Gmail consumer app password | ~500/ngày | chỉ test; ToS hạn chế bulk |
| Outlook.com app password | ~300/ngày | chỉ test |
| ESP (SES/SendGrid/Mailgun) | 50k+/ngày | cần domain + plan |
| Graph (M365) | 10k/mailbox/ngày | **khuyến nghị** |

## 10. Vẫn cần consent & nội dung

Graph không miễn nhiễm spam filter. Để vào Primary/Focused:
- List opt-in, không cold.
- Subject cá nhân, text ngắn, 1 link.
- Unsubscribe hoạt động.
- Complaint < 0.1%.
- Seed test trước khi scale.

Graph chỉ giải quyết bài toán **hạ tầng/reputation**, không giải quyết consent.
