# 05 — Inbox placement playbook

Mục tiêu: đưa email opt-in vào inbox, giữ ở đó, và biết ngay khi tụt.

## 1. KPI

| KPI | Mục tiêu | Đo ở đâu |
|---|---|---|
| Inbox rate (seed) | > 95% | seed test mỗi campaign |
| Spam complaint | < 0.1% (max 0.3%) | Postmaster Tools, SNDS |
| Hard bounce | < 2% | log SMTP 550 5.1.1 |
| Unsubscribe | < 0.5% | link tracking |
| Open (human) | tùy ngành, đừng tin tuyệt đối | pixel + click (Apple MPP) |
| Click | > 2% | tracking domain |
| Reply | > 0.1% | inbox reply |
| DNSBL | 0 listing | `dnscheck` hằng ngày |

## 2. 30 ngày đầu (warmup)

### Tuần 1
- Gửi 50-100/ngày/IP, chỉ tới **engaged 30 ngày**.
- 1 campaign/ngày, cùng giờ (ví dụ 9-11h sáng theo timezone người nhận).
- Theo dõi: 421/451, 550 5.7.1, complaint.
- Không đổi template/domain giữa tuần.

### Tuần 2
- 150-300/ngày/IP.
- Thêm segment active_90, vẫn 1 campaign/ngày.
- Bắt đầu A/B subject (2 biến thể, không đổi 5 thứ cùng lúc).

### Tuần 3
- 400-800/ngày/IP.
- Thêm welcome/transactional stream nếu có.
- Kiểm tra Gmail Promotions vs Primary; nếu vào Promotions, giảm ảnh/CTA, tăng text.

### Tuần 4
- 800-1.500/ngày/IP nếu complaint < 0.05%, bounce < 1%.
- Vẫn giữ 35% headroom so với quota.
- Đánh giá: seed 100% inbox? DNSBL sạch? Nếu không, lùi 1 tuần.

Công thức ramp: `volume(d) = start × growth^(d/3)`, growth 1.3-1.4, ngày nghỉ giảm 40%. Dùng `node src/cli.js warmup`.

## 3. Segmentation

```
engaged_30     mở/click trong 30 ngày        → 2-3 lần/tuần
engaged_90     mở/click 31-90 ngày           → 1 lần/tuần
lapsed_180     không tương tác 91-180 ngày   → 2 lần/tháng
inactive_365   > 365 ngày                    → 1 win-back, rồi suppress
```

Quy tắc:
- Không gửi promotional cho `inactive_365` quá 1 lần.
- Re-permission: email ngắn "bạn còn muốn nhận?" + 1 click yes/no.
- Nếu 30 ngày không mở → giảm tần suất trước khi bỏ.
- Transactional (receipt, password) tách hoàn toàn khỏi marketing.

## 4. Cadence

| Loại | Tần suất | Ghi chú |
|---|---|---|
| Welcome | ngay khi signup | 1-3 email, 7 ngày |
| Newsletter | 1-2/tuần | cùng ngày/giờ |
| Promo | ≤ 2/tuần | tránh dồn cuối tháng |
| Re-engagement | 1 lần/90 ngày | chỉ inactive |
| Transactional | realtime | không trộn promo |

Frequency cap: tối đa 4 marketing/tuần/người, bất kể số campaign.

## 5. Content checklist

- [ ] Subject 35-55 ký tự, không CAPS, không `!!!`, không "free 100%".
- [ ] Preheader bổ sung, không lặp subject.
- [ ] Text/plain thật (không chỉ "view in browser").
- [ ] 1 CTA chính, link rõ ràng, domain tracking riêng.
- [ ] HTML < 100 KB, ảnh host ngoài, có alt text.
- [ ] Không ảnh toàn bộ email.
- [ ] Footer: địa chỉ, lý do nhận, unsubscribe 1 click.
- [ ] Không link shortener.
- [ ] Không token dài/dấu hiệu tracking lộ trong URL.
- [ ] Test render Gmail/Outlook/Apple Mail/mobile.
- [ ] `score` < 2.5.

## 6. Seed test

Trước campaign:
1. Tạo seed list: 2 Gmail (1 Primary, 1 Promotions), 2 Outlook (Focused/Other), 1 Yahoo, 1 Proton, 1 iCloud.
2. Gửi bản test tới seed.
3. Ghi: inbox/spam/promotions, auth pass (show original), link, ảnh, mobile.
4. Nếu < 100% inbox → không scale; sửa và test lại.
5. Lưu kết quả theo campaign: `reports/seed-<date>.json`.

Công cụ: GlockApps, Mail-Tester, hoặc seed list tự dựng. Không dùng seed của người khác.

## 7. Giám sát

Hằng ngày:
- `node src/cli.js pool` → quota, health.
- `node src/cli.js dnscheck --domain ... --ip ...` → DNSBL, PTR.
- Postmaster Tools: reputation, spam rate, delivery errors.
- SNDS: complaint, trap hits.
- Log 550 5.7.1/5.7.26 theo domain.

Hằng tuần:
- Inbox rate theo provider (seed).
- Bounce/complaint theo segment.
- Unsubscribe theo campaign.
- So sánh subject/CTA.

Alert:
- complaint > 0.08% → dừng campaign, review list.
- 550 5.7.1 > 1% → dừng relay/domain.
- DNSBL listing → dừng gửi, delist.
- 421 > 2% → giảm concurrency 50%.

## 8. Khi tụt inbox

Thứ tự debug:

1. **Auth**: `dnscheck`, show original. SPF/DKIM/DMARC pass? alignment?
2. **Reputation**: DNSBL, Postmaster, SNDS. IP mới? domain mới?
3. **List**: bounce/complaint tăng? mua list? segmentation sai?
4. **Content**: thay đổi gì tuần này? ảnh, link, subject?
5. **Volume**: tăng đột ngột? sai giờ? nhiều campaign dồn?
6. **Infra**: PTR đổi? TLS lỗi? relay mới?

Fix theo thứ tự 1→6, không đổi nhiều thứ cùng lúc. Ghi lại thay đổi.

### Checklist recovery
- [ ] Dừng campaign 24-48h nếu complaint/DNSBL.
- [ ] Delist (Spamhaus, Barracuda, SpamCop).
- [ ] Gửi lại **chỉ engaged_30**, volume 30% bình thường.
- [ ] Theo dõi 72h; tăng dần nếu sạch.
- [ ] Không tạo domain/IP mới để "né" — reputation mới còn tệ hơn.
- [ ] Root cause: list? content? volume? auth?

## 9. Tabs & Focused

- Gmail Promotions: layout marketing (ảnh, CTA, nhiều link). Muốn Primary: text nhiều hơn, ít ảnh, 1 link, nội dung như thư cá nhân. Nhưng đừng giả làm transactional.
- Outlook Focused: người gửi lạ → Other. Cách bền: user thêm vào safe sender; welcome email hướng dẫn.
- Không có mẹo CSS/header nào đảm bảo tab; tương tác người dùng mới quyết định.

## 10. A/B test đúng

- Chỉ đổi 1 biến thể mỗi lần: subject, hoặc CTA, hoặc gửi giờ.
- Cùng segment, chia 50/50, đủ mẫu (≥ 1.000/tệp).
- Đo click/reply, không chỉ open.
- Đợi 48h trước kết luận.
- Lưu kết quả vào `reports/ab-<date>.json`.

## 11. Mapping code

| Việc | Lệnh/file |
|---|---|
| warmup plan | `node src/cli.js warmup --start 50 --target 5000` |
| gửi theo limit | `send --list ... --limit N` |
| score nội dung | `score --text ... --html ...` |
| seed test | gửi tới `config/seed-list.csv` |
| đo auth | `dnscheck`, show original |
| log | `logs/send.log`, `reports/` |
