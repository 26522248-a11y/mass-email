# 02 — Deliverability stack: authentication, reputation, content, engagement

Thứ tự ưu tiên khi email vào spam (thực nghiệm, không phải marketing):

```
1. Reputation IP/domain   ████████████████████  40%
2. Authentication/alignment ███████████████     28%
3. Engagement (open/click/reply) ██████████     20%
4. Content/format          ██████                8%
5. Infrastructure (PTR/TLS) ████                  4%
```

Nội dung đẹp không cứu được IP bẩn. IP sạch + auth đúng + list tốt thì nội dung bình thường vẫn vào inbox.

---

## 1. Bốn lớp bắt buộc

### Lớp 1 — Authentication

| Record | Name | Value mẫu | Ghi chú |
|---|---|---|---|
| SPF | `mail.example.com` | `v=spf1 ip4:203.0.113.10 ip4:203.0.113.11 -all` | chỉ IP thật sự gửi; `-all` |
| DKIM | `s1._domainkey.mail.example.com` | `v=DKIM1; k=rsa; p=MIIBIjAN...` | 2048-bit, selector `s1` |
| DMARC | `_dmarc.mail.example.com` | `v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com` | cả org domain cũng nên có |
| MX | `mail.example.com` | `10 inbound.example.com.` | cần cho bounce/feedback |
| PTR | reverse của IP | `mail.example.com.` | phải khớp EHLO |
| A | `mail.example.com` | IP gửi | FCrDNS: PTR → A → IP |
| MTA-STS | `_mta-sts.mail.example.com` | `v=STSv1; id=20261125T000000` | + file HTTPS `/.well-known/mta-sts.txt` |
| TLS-RPT | `_smtp._tls.mail.example.com` | `v=TLSRPTv1; rua=mailto:tlsrpt@example.com` | báo cáo TLS fail |
| BIMI (optional) | `default._bimi.mail.example.com` | `v=BIMI1; l=https://.../logo.svg; a=https://.../vmc.pem` | cần DMARC reject + VMC |

**Alignment** — điều quan trọng nhất:

```
From:        news@mail.example.com      ← domain người nhận thấy
Return-Path: bounce@mail.example.com    ← SPF check
DKIM d=:     mail.example.com           ← DKIM check
DMARC:       aligned nếu cả hai cùng org-domain example.com
```

Nếu `From: news@example.com` nhưng `DKIM d=mail.example.com` và `Return-Path: bounce@esp.com`:
- relaxed alignment (mặc định) vẫn pass nếu cùng `example.com`;
- strict (`adkim=s; aspf=s`) sẽ **fail** → dễ vào spam.

Khuyến nghị: dùng **cùng một subdomain** cho From, Return-Path, DKIM. Tách khỏi domain web (`example.com`) để sự cố gửi không kéo cả domain chính.

### Lớp 2 — Reputation

- IP mới: warmup 2-4 tuần, bắt đầu 50-100/ngày, tăng ~1.3-1.4× mỗi 3-4 ngày, có ngày nghỉ.
- Giữ complaint rate < **0.1%** (Gmail yêu cầu < 0.3%, nhưng 0.1% mới an toàn).
- Hard bounce < 2%; nếu > 5% dừng list, làm sạch.
- Đăng ký **Google Postmaster Tools** (domain + IP), **Microsoft SNDS/JMRP**, **Yahoo Sender Hub**.
- Kiểm tra DNSBL hằng ngày: Spamhaus ZEN, Barracuda, SpamCop. `dnscheck` làm việc này.
- Mỗi stream (transactional vs marketing) nên có subdomain/IP riêng. Khi marketing bị bẩn, transactional không chết.

### Lớp 3 — Engagement

Gmail/Outlook dùng tương tác để xếp hạng người gửi:
- Người mở/click thường xuyên → inbox tab chính.
- Không mở 90 ngày → giảm tần suất hoặc sunset.
- Reply là tín hiệu mạnh nhất; hỏi "reply để nhận..." trong welcome flow.

Segment tối thiểu:
```
active_30   → gửi hằng tuần
active_90   → 2 tuần/lần
inactive_180→ 1 lần/tháng, re-permission
inactive_365→ không gửi, chỉ win-back 1 lần
```

### Lớp 4 — Content

- `multipart/alternative` bắt buộc: text/plain + text/html, **không** image-only.
- Tỷ lệ text/html hợp lý, mỗi đoạn 2-4 câu, 1 CTA chính.
- Tổng message < **100 KB** (Gmail cắt tại 102KB; vượt dễ bị "clipped").
- Không đính kèm file ở marketing; host file và link.
- 1 link domain chính, vài link phụ; **không** URL shortener (bit.ly, t.co…) vì làm mất reputation domain và bị filter nghi ngờ.
- Không chữ trắng trên nền trắng, không hidden text, không `display:none` chứa keyword.
- Subject 35-55 ký tự, tránh ALL CAPS, `!!!`, `$$$`, "100% free".
- Preheader 40-90 ký tự, bổ sung subject, không lặp.
- Footer: địa chỉ vật lý (CAN-SPAM), lý do nhận, unsubscribe rõ.

`node src/cli.js score --text ... --html ... --subject ...` chấm heuristic trước khi gửi.

---

## 2. Header chuẩn

```
From: Brand <news@mail.example.com>
Reply-To: support@example.com
To: user@example.org
Subject: =?UTF-8?B?...?=
Date: ...
Message-ID: <...@mail.example.com>
MIME-Version: 1.0
List-Unsubscribe: <mailto:unsub@mail.example.com?subject=...>, <https://mail.example.com/u/token>
List-Unsubscribe-Post: List-Unsubscribe=One-Click
Feedback-ID: campaign:news:example        (Google)
X-Entity-Ref-ID: <random>                 (Gmail: tránh gộp thread; undocumented)
Precedence: bulk
Auto-Submitted: auto-generated
```

Quy tắc:
- `Message-ID` unique theo từng message, domain khớp From.
- Không tái sử dụng `Message-ID` (trùng → dedupe, mất mail).
- Không set `In-Reply-To`/`References` trừ khi thật sự reply trong thread; lạm dụng để "chui" vào thread là tín hiệu xấu và dễ bị coi là thread hijacking.
- `Sender:` chỉ dùng khi From là người khác; nếu không, bỏ.
- `Precedence: bulk` giúp một số filter phân loại đúng; không phải silver bullet.

Code: `src/lib/mime.js` build đúng các header trên; `policy.headers` bật/tắt.

---

## 3. Gmail tabs / Outlook Focused

| Tab/Folder | Tín hiệu |
|---|---|
| Gmail Primary | người gửi quen, reply, tương tác, transactional |
| Gmail Promotions | có ảnh, CTA, layout marketing, link nhiều |
| Gmail Updates | receipt, notification, không phải marketing thuần |
| Gmail Spam | auth fail, complaint cao, nội dung giống spam, list độc |
| Outlook Focused | người gửi trong contact/safe list, tương tác |
| Outlook Other | bulk, first contact, marketing |
| Outlook Junk | reputation, content, auth |

Không có cách "ép" Primary/Focused bền vững. Cách bền: khi user kéo mail ra khỏi Promotions/Other, Gmail/Outlook ghi nhận tín hiệu dương. Thiết kế email mời user làm việc đó trong welcome flow (không spam CTA).

---

## 4. Tracking domain & privacy

- Dùng subdomain riêng cho click: `go.example.com` (CNAME tới tracking service hoặc app của bạn).
- SPF cho domain tracking nếu nó gửi mail; nếu chỉ link thì không cần.
- Open pixel: Apple Mail Privacy Protection làm open rate sai lệch; đừng dùng open làm KPI duy nhất, dùng click/reply.
- Không nhúng token cá nhân vào URL công khai; dùng token opaque, hết hạn.
- Trang unsubscribe phải hoạt động **không cần login**, 1 click, xác nhận rõ.

---

## 5. Bulk sender rules (2024+)

Google/Yahoo (từ 02/2024), Microsoft (dần áp dụng):
- Bulk = > 5.000/ngày tới Gmail.
- Bắt buộc SPF **và** DKIM **và** DMARC (`p=none` tối thiểu).
- One-click unsubscribe (`List-Unsubscribe-Post`) cho marketing.
- Complaint rate < 0.3% (Gmail Postmaster); < 0.1% là mục tiêu.
- Xử lý unsubscribe trong 2 ngày.
- Microsoft: SNDS + JMRP, tuân thủ `p=reject` khi gửi qua Exchange Online.

Không đáp ứng → bị chặn ở cửa, không phải spam folder.

---

## 6. Seed testing

Trước mỗi campaign lớn:
1. Gửi tới **seed list** gồm Gmail/Outlook/Yahoo/Proton/iCloud (mailbox của bạn hoặc dịch vụ như GlockApps/Mail-Tester).
2. Kiểm tra: inbox/spam/promotions, SPF/DKIM/DMARC pass, DNSBL, link, rendering mobile.
3. Chỉ scale nếu 100% seed vào inbox và auth pass.
4. Lưu kết quả theo campaign để so sánh.

`verify` không thay thế seed test: nó chỉ xác thực địa chỉ, không đo inbox placement.

---

## 7. Bảng lỗi → cách sửa

| Triệu chứng | Nguyên nhân thường gặp | Sửa |
|---|---|---|
| 550 5.7.1 policy | IP/domain reputation, DNSBL | delist, giảm volume, xem Postmaster |
| 550 5.7.26 auth | SPF/DKIM fail, alignment | sửa DNS, ký đúng `d=` |
| 421 4.7.0 rate | vượt per-IP/account | giảm concurrency, thêm relay |
| Vào Promotions | layout marketing, thiếu engagement | bớt ảnh/CTA, segment, welcome flow |
| Vào Spam dù auth pass | complaint cao, list cũ, content | làm sạch list, re-permission |
| Clipped | HTML > 102KB | giảm inline CSS/ảnh base64 |
| Outlook Junk | first contact, SCL, thiếu SNDS | warmup, SNDS, tương tác |
| Yahoo 550 fcRDNS | PTR không khớp | sửa PTR/EHLO, chờ propagate |
| Bounce 5.1.1 | list cũ | verify trước gửi, loại hard bounce |

---

## 8. Checklist trước khi bấm gửi

- [ ] SPF `-all`, đúng IP, < 10 lookup
- [ ] DKIM 2048, selector active, ký mọi message
- [ ] DMARC `p=reject; sp=reject; adkim=s; aspf=s`, có `rua`
- [ ] From/Return-Path/DKIM cùng subdomain
- [ ] PTR = EHLO, FCrDNS OK
- [ ] MTA-STS enforce + TLS-RPT
- [ ] DNSBL sạch, Postmaster/SNDS đã đăng ký
- [ ] List đã verify, hard bounce đã loại, suppression đã áp
- [ ] Seed test 100% inbox
- [ ] `score` < 2.5, không có finding nặng
- [ ] Volume trong quota, có headroom 35%
- [ ] Unsubscribe 1-click hoạt động
- [ ] Log + queue + alert sẵn sàng
