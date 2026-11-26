# 06 — Kiến trúc & vận hành

## 1. Thành phần

```
┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│  CLI / cron  │   │  HTTP API    │   │  Webhook     │
└──────┬───────┘   └──────┬───────┘   └──────┬───────┘
       └──────────────────┼──────────────────┘
                          ▼
                 ┌─────────────────┐
                 │  Queue (disk)   │  data/queue/{pending,done,failed}
                 └────────┬────────┘
                          ▼
                 ┌─────────────────┐
                 │  Render + MIME  │  spintax, per-recipient RNG
                 └────────┬────────┘
                          ▼
                 ┌─────────────────┐
                 │  DKIM signer    │  keys/<domain>.json
                 └────────┬────────┘
                          ▼
                 ┌─────────────────┐
                 │  RelayPool      │  weight, quota, health
                 └────────┬────────┘
                          ▼
                 ┌─────────────────┐
                 │  SMTP client    │  STARTTLS, AUTH, pipelining
                 └────────┬────────┘
                          ▼
              ESP / Gmail / M365 / self-host MTA
```

## 2. Luồng một message

1. CLI đọc CSV → `Queue.addMany` (mỗi job 1 file JSON, id unique).
2. Worker `lease(1)` → job chuyển `leased`, có lease 10 phút (crash sẽ recover).
3. `renderJob`: chọn spintax theo seed `job.id + email` → text/html ổn định cho cùng người nhận.
4. `buildMessage`: header, MIME, Message-ID unique.
5. `spamscore`: nếu > `fail_over` → `held`, không gửi.
6. `signMessage`: DKIM relaxed/relaxed, header list cố định.
7. `RelayPool.pick`: weighted + quota + health; `RelayGuard.acquire` giới hạn concurrency.
8. SMTP: EHLO → STARTTLS → AUTH → MAIL → RCPT → DATA.
9. Phân loại: 2xx done, 4xx retry backoff, 5xx bounce/disable.
10. `Queue.complete/fail/retry`; log JSONL.

## 3. Triển khai

### Mức nhỏ (≤ 10k/ngày)
- 1 VPS 2 vCPU/2GB, Node 20+.
- 1 ESP (SES/SendGrid) + 1 domain + 1 mailbox.
- Chạy CLI bằng cron/Task Scheduler.
- Backup `data/queue` + `state/pool.json` hằng ngày.

### Mức vừa (≤ 200k/ngày)
- 1 VPS 4 vCPU/8GB hoặc 2 VPS (sender + queue).
- 3-5 relay/ESP, 3 domain, 4-8 IP warm.
- Queue trên disk; nếu > 50k file, chuyển SQLite/Postgres.
- Metrics: Prometheus node_exporter + log JSONL → Loki/ELK (hoặc đơn giản là file + script alert).
- Cron: `send` mỗi 5 phút, `pool` health check, `dnscheck` hằng ngày.

### Mức lớn (≥ 1M/ngày)
- Tách service: API enqueue, worker send, scheduler, reporting.
- Queue: Postgres/SQS/Redis Streams; job idempotent.
- Nhiều worker, mỗi worker 1 tập relay; shared state qua DB.
- MTA riêng (Postfix/Haraka) + IP pool + nhiều domain; hoặc 10+ ESP.
- Observability: per-relay/per-domain dashboards, alert.
- Secrets: Vault/KMS; DKIM key trong HSM nếu có.

## 4. Capacity

`node src/cli.js capacity --target 100000`:

```
relays 27, IPs 45, domains 14, ~1.74 msg/s
```

Diễn giải:
- 1.74 msg/s là nhịp gửi trung bình trong 16h; không phải burst.
- 27 relay account × 5k/ngày (đã gồm headroom 1.35).
- 45 IP × ~3k/ngày (an toàn cho IP warm).
- 14 domain × 10k/ngày.
- Chi phí $450-2.100/tháng tùy ESP/VPS.

Nếu dùng ESP lớn (SES), giảm IP/domain; nếu self-host, tăng IP/domain và chi phí vận hành.

## 5. Bảo mật

| Mối nguy | Kiểm soát |
|---|---|
| Lộ DKIM private key | file ACL 600, không commit, rotate 6-12 tháng, KMS/HSM |
| Lộ SMTP password | env/secret store, không log, rotate, quyền tối thiểu |
| Spam qua form signup (bom list) | double opt-in, CAPTCHA, rate limit theo IP |
| Gửi nhầm list | approval bước gửi, `--dry-run`, preview, suppression |
| Queue bị sửa | file permission, checksum, backup |
| Log chứa PII | mask email, retention 30-90 ngày |
| SSRF/XXE | không nhận HTML từ nguồn lạ; sanitize template |
| Supply chain | zero dependency (repo này), pin Node version |

### Rotate DKIM
1. Sinh key mới selector `s2`.
2. Publish TXT `s2._domainkey`.
3. Chờ TTL (≥ 1h).
4. Đổi `selector` trong `keys/<domain>.json`.
5. Giữ record `s1` thêm 7 ngày (message cũ).
6. Xóa `s1`.

## 6. Quan sát (observability)

Log JSONL mỗi message:
```json
{"ts":"...","email":"u@example.com","relay":"ses-1","status":"sent","code":250,"ms":312,"spam":0.8,"msgId":"..."}
```

Metrics cần có:
- sent/retry/bounce/held theo giờ, relay, domain.
- p50/p95 transaction ms.
- 421/451 rate theo relay.
- 550 5.7.1/5.7.26 rate theo domain.
- complaint (từ Postmaster/SNDS).
- queue depth, oldest pending age.

Alert:
- queue depth > 10k hoặc oldest > 2h.
- 421 > 2% trong 15 phút.
- 550 5.7.1 > 1%.
- DNSBL listing.
- relay health < 0.3.

## 7. Failure modes

| Failure | Dấu hiệu | Xử lý |
|---|---|---|
| Relay chết | connect timeout, health giảm | pool tự loại; thêm relay |
| Auth hết hạn | 535, disable relay | refresh token/app password |
| Queue đầy | pending tăng | thêm worker/relay, giảm volume |
| Disk đầy | write error | rotate log, archive done |
| IP vào DNSBL | 550 5.7.1 | dừng, delist, giảm volume |
| Domain bị chặn | 550 5.7.1 theo domain | tách stream, dùng domain khác |
| Template lỗi | build error, held | dry-run trước, test |
| Trùng message | Message-ID reuse | đảm bảo unique (code đã làm) |

## 8. Multi-domain strategy

- Mỗi domain: 1 subdomain gửi, 1 Return-Path, 1 DKIM selector.
- Không dùng cùng IP cho quá nhiều domain nếu có thể.
- Domain theo ngành/brand, không phải domain rác.
- Rotate khi reputation giảm, không phải khi bị chặn.
- Giữ domain cũ warm, đừng xóa ngay.

## 9. Nâng cấp queue

Khi > 50k job/ngày, file-per-job chậm. Chuyển sang SQLite:

```sql
CREATE TABLE jobs (
  id TEXT PRIMARY KEY, email TEXT NOT NULL, payload TEXT NOT NULL,
  status TEXT NOT NULL, attempts INTEGER DEFAULT 0,
  due_at INTEGER NOT NULL, lease_until INTEGER DEFAULT 0,
  result TEXT, created_at INTEGER NOT NULL
);
CREATE INDEX idx_jobs_due ON jobs(status, due_at);
```

Giữ nguyên interface `Queue` (add/lease/complete/retry/fail) để không đổi sender.

## 10. Roadmap hợp lý

1. Tuần 1: domain + DNS + DKIM + dnscheck A.
2. Tuần 2: 1 ESP + 100 seed + gửi 50/ngày.
3. Tuần 3-6: warmup, đo, tối ưu subject/segment.
4. Tháng 2: thêm relay/domain, queue SQLite nếu cần.
5. Tháng 3: dashboard, alert, tự động hóa report.
