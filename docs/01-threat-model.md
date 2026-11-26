# 01 — Threat model & thang điểm "level 9+"

## 1. Mục tiêu và phạm vi

**Trong phạm vi**
- Gửi email opt-in khối lượng lớn qua nhiều relay/ESP.
- Đo hành vi receiver ở lớp SMTP (capability, giới hạn, cách trả lỗi).
- Audit cấu hình domain gửi (SPF/DKIM/DMARC/PTR/MTA-STS/DNSSEC).
- Nghiên cứu lỗi cấu hình/protocol của receiver, có disclosure.

**Ngoài phạm vi**
- Spoof domain không thuộc sở hữu.
- Gửi tới list mua/ scrape không consent.
- Khai thác credential, account takeover, malware.
- Tấn công làm gián đoán dịch vụ của provider.
- Vượt quota bằng cách tạo account hàng loạt trái ToS.

## 2. Tài sản (assets)

| Asset | Mất gì nếu hỏng | Biện pháp |
|---|---|---|
| Domain reputation | cả domain/subdomain bị chặn | tách subdomain, giám sát DNSBL, rotate có kế hoạch |
| IP reputation | 550/421 hàng loạt | warmup, PTR/FCrDNS, giữ complaint < 0.1% |
| Relay credential | gửi rác bằng tiền bạn, account bị khóa | secret ngoài repo, quyền tối thiểu, rotate |
| Recipient trust | unsubscribe/complaint, mất list | segmentation, frequency cap, one-click |
| Dữ liệu cá nhân | phạt GDPR/nghị định 13 | consent log, retention, DPA |
| DKIM private key | giả mạo hoàn hảo | file ACL, HSM/KMS nếu lớn, rotate 6-12 tháng |

## 3. Actor

- **Sender**: bạn. Mục tiêu inbox + volume.
- **Recipient**: quyết định open/click/complaint. Engagement là tín hiệu mạnh nhất.
- **Receiver filter**: Gmail/Outlook/Yahoo. Chấm điểm auth + reputation + content + engagement.
- **ESP/relay**: chặn nếu vượt quota hoặc complaint cao.
- **Competitor/abuse desk**: report, khiến IP vào DNSBL.
- **Attacker**: lấy key/credential, lợi dụng form subscribe để bom list.

## 4. Rules of engagement cho nghiên cứu

1. Chỉ test trên domain, IP, mailbox do bạn kiểm soát; hoặc dùng tài khoản test của provider.
2. Không gửi message thật tới người lạ để "test filter".
3. `probe` chỉ thực hiện EHLO/MAIL/RCPT — không DATA vào mailbox người khác.
4. Không thử boundary smuggling lên MX production của provider. Dựng MTA lab (Postfix/Exim/Haraka) trong VM.
5. Mọi finding ghi rõ `OBSERVED` (có log) / `THEORETICAL` (suy luận từ spec) / `PATCHED`.
6. Disclosure: security@vendor, 90 ngày, không công bố PoC trước hạn.

## 5. Thang điểm

Dùng thang 1-10, không phải CVSS thuần. Mỗi mức = khả năng + tác động + độ khó phát hiện.

| Mức | Định nghĩa | Ví dụ |
|---|---|---|
| 1-2 | Info/low, không hành động được | banner lộ version, EHLO thiếu cap |
| 3-4 | Misconfig ảnh hưởng chính chủ | SPF `?all`, DMARC `p=none`, thiếu MTA-STS |
| 5-6 | Bypass một lớp, cần điều kiện | RCPT enumeration hàng loạt, null-sender bounce injection |
| 7-8 | Bypass auth/inbox ở quy mô vừa, khó phát hiện | ARC chain forgery qua forwarder, MIME differential qua filter |
| 9 | Chain hoàn chỉnh: auth pass + inbox + scale + stealth, không cần user click | spoof From qua receiver bug + vượt rate limit + không bị DNSBL |
| 10 | 9 + ảnh hưởng toàn provider, persistent, zero-interaction | lỗi protocol cho phép gửi thay bất kỳ domain |

**"Level 9+" không phải là một tool.** Nó là một finding chain có bằng chứng:
`auth bypass` → `inbox placement` → `volume` → `không bị phát hiện`. Nếu thiếu một mắt, điểm tụt xuống 7-8.

### Template chấm

```
ID:            F-xx
Title:         ...
Class:         enumeration | auth-bypass | parser | rate-limit | config
Status:        OBSERVED / THEORETICAL / PATCHED
Severity:      x/10
Precondition:  ...
Repro:         command / packet sequence
Evidence:      reports/..., log line, timestamp
Impact:        ...
Scale:         addresses/hour, domains affected
Detection:     receiver log? user report? none?
Fix (vendor):  ...
Workaround:    ...
Disclosure:    date, contact, deadline
```

## 6. Vì sao "gửi vô hạn, không rate limit" là bài toán hạ tầng, không phải exploit

Rate limit của Gmail/Outlook được enforce ở 3 tầng:
1. **Per-account** (SMTP AUTH): 500-2.000/ngày (consumer/Workspace).
2. **Per-IP/ASN**: reputation + volume pattern; vượt thì 421/550 tạm thời.
3. **Per-recipient-domain**: Gmail `RCPTDOMAINMAX=1`, `RCPTMAX=100` mỗi transaction (quan sát được).

Không có "unlimited" từ một identity. Công thức đúng:

```
capacity = Σ(relay quota) × headroom
         = số IP × reputation mỗi IP
         = số domain × volume an toàn mỗi domain
```

Muốn 1M/ngày: 20 domain × 50k, hoặc 10 IP warm × 100k, hoặc mix ESP + self-host. Xem `capacity` và `docs/03`.

## 7. Rủi ro pháp lý

- Mỹ: CAN-SPAM — unsubscribe trong 10 ngày làm việc, địa chỉ vật lý, không header giả.
- EU: GDPR — lawful basis, consent proof, right to erasure; ePrivacy cho marketing.
- Việt Nam: Nghị định 91/2020/NĐ-CP — consent trước, chống spam, opt-out; Nghị định 13/2023 về dữ liệu cá nhân.
- Provider AUP: vi phạm = khóa account + mất tiền, không chỉ bounce.

Chi tiết: `docs/08-legal.md`.
