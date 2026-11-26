# 08 — Pháp lý & compliance

Không phải tư vấn pháp lý. Kiểm tra với luật sư theo thị trường bạn gửi.

## 1. Nguyên tắc chung

1. **Consent trước**: chỉ gửi marketing tới người đã đồng ý rõ ràng.
2. **Mục đích rõ**: nói rõ sẽ nhận gì, tần suất.
3. **Opt-out dễ**: 1 click, không login, có hiệu lực ngay.
4. **Danh tính thật**: From, địa chỉ vật lý, link chính sách.
5. **Lưu bằng chứng consent**: thời gian, IP, nguồn, nội dung form.
6. **Tôn trọng provider AUP**: không mua list, không scrape, không spoof.

## 2. Hoa Kỳ — CAN-SPAM

Áp dụng cho email thương mại có yếu tố Mỹ:
- Không header giả, không subject gây hiểu lầm.
- Có địa chỉ vật lý của người gửi.
- Có cơ chế opt-out rõ ràng.
- Xử lý opt-out trong **10 ngày làm việc**.
- Không gửi lại sau khi opt-out.
- Trách nhiệm có thể mở rộng tới bên thuê gửi (affiliate).

## 3. EU — GDPR + ePrivacy

- **Lawful basis**: consent (marketing) hoặc legitimate interest (hẹp, có LIA).
- **Consent**: freely given, specific, informed, unambiguous; opt-in, không pre-ticked.
- **Right to erasure**: xóa khỏi list + suppression (giữ hash tối thiểu để không gửi lại).
- **Data minimization**: chỉ lưu email + tên cần thiết.
- **Retention**: định kỳ xóa inactive; ghi rõ trong privacy policy.
- **Processor**: DPA với ESP, kiểm tra data location.
- **ePrivacy**: cookie/tracking cần consent; open pixel và click tracking có thể được coi là tracking.

## 4. Việt Nam

- **Nghị định 91/2020/NĐ-CP** về chống spam tin nhắn, email, cuộc gọi:
  - phải có consent trước khi gửi email quảng cáo;
  - phải có cơ chế từ chối (opt-out) trong mỗi email;
  - không gửi ngoài giờ cho phép nếu không có thỏa thuận;
  - nhãn/chủ đề rõ ràng.
- **Nghị định 13/2023/NĐ-CP** về bảo vệ dữ liệu cá nhân:
  - consent cho xử lý dữ liệu;
  - thông báo mục đích, loại dữ liệu;
  - quyền truy cập, xóa, hạn chế;
  - biện pháp bảo mật, thông báo vi phạm.
- **Luật An toàn thông tin mạng**, **Luật Viễn thông**: quy định gửi tin điện tử.

Thực hành:
- Lưu consent log (timestamp, IP, source URL, nội dung checkbox).
- Opt-out xử lý ngay, đồng bộ suppression.
- Không dùng list mua/ trao đổi.
- Có đầu mối xử lý yêu cầu dữ liệu.

## 5. Provider AUP (tóm tắt)

Hầu hết ESP cấm:
- purchased/rented lists;
- scraping;
- spoofing;
- adult/gambling/crypto tùy chính sách;
- gửi tới người chưa consent;
- vượt quota, tạo nhiều account để né.

Hậu quả: khóa account, mất prepaid, báo cáo, có thể chặn domain vĩnh viễn. Không có "kỹ thuật" nào bền hơn tuân thủ.

## 6. Suppression list

Bắt buộc lưu:
- hard bounce (550 5.1.1, 5.1.10…);
- complaint (qua FBL/Postmaster/SNDS);
- unsubscribe (email + timestamp + source);
- global opt-out (không chỉ campaign).

Nguyên tắc:
- Suppression là **toàn cục**, không phải per-campaign.
- Không xóa suppression khi import list mới.
- Có thể lưu hash thay vì email thô nếu cần privacy.

## 7. Double opt-in

Khuyến nghị cho mọi list mới:
1. Form → gửi email xác nhận.
2. User click link có token hết hạn.
3. Ghi consent (timestamp, IP, source).
4. Chỉ gửi marketing sau bước 3.

Lợi ích: giảm spam trap, giảm complaint, tăng engagement, bằng chứng pháp lý.

## 8. Unsubscribe

- `List-Unsubscribe` + `List-Unsubscribe-Post` (RFC 8058).
- Trang unsubscribe: 1 click, không login, không hỏi lý do bắt buộc.
- Xác nhận rõ, không dark pattern.
- Xử lý trong 24h (Gmail yêu cầu ≤ 2 ngày).
- Suppression sync ngay, kể cả queue đang chờ.

## 9. Record keeping

Tối thiểu:
- consent: email hash, timestamp, IP, source, form version;
- gửi: campaign, segment, template version, relay, message-id;
- opt-out: timestamp, channel, source;
- complaint/bounce: timestamp, code, relay.

Retention: 24-36 tháng hoặc theo luật; log gửi 90 ngày là đủ vận hành, nhưng consent lâu hơn.

## 10. Checklist

- [ ] Consent proof cho từng list.
- [ ] Double opt-in cho list mới.
- [ ] Privacy policy + link trong footer.
- [ ] Địa chỉ vật lý trong footer.
- [ ] Unsubscribe 1 click hoạt động.
- [ ] Suppression toàn cục.
- [ ] DPA với ESP.
- [ ] Data retention + deletion process.
- [ ] Không mua list, không scrape.
- [ ] Tuân thủ quota/AUP.
