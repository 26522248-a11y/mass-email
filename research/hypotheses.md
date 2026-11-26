# Hypothesis log

| ID | Giả thuyết | Test | Kết quả | Status |
|---|---|---|---|---|
| H-01 | Gmail trả response khác nhau cho RCPT tồn tại/không tồn tại | `verify` trên mailbox test + random | 550 vs 250, timing same | OBSERVED |
| H-02 | Gmail chấp nhận `MAIL FROM:<>` | `probe` | 250 | OBSERVED |
| H-03 | Outlook đóng session sau MAIL FROM bị chặn | `probe` | 550 rồi close | OBSERVED |
| H-04 | Yahoo yêu cầu FCrDNS | `probe` từ IP không PTR | 550 5.7.25 | OBSERVED |
| H-05 | RCPT uppercase khác lowercase | `probe` | cùng 550 | NO DIFF |
| H-06 | Gmail dot alias thay đổi deliverability | gửi tới `a.b@` vs `ab@` mailbox của bạn | cùng inbox | INFO |
| H-07 | `In-Reply-To` làm message vào thread | gửi 2 message mailbox test | có thread | OBSERVED |
| H-08 | MIME boundary trùng body gây parser diff | lab + 2 mailbox | chưa kết luận | TODO |
| H-09 | ARC chain giả được chấp nhận | 2 MTA lab | chưa test | TODO |
| H-10 | `l=` cho phép thêm body | lab verifier | chưa test | TODO |
| H-11 | Retry bị tính quota 2 lần | log ESP | cần đối chiếu | TODO |
| H-12 | Nhiều RCPT cùng domain tăng throughput | Gmail RCPTDOMAINMAX=1 | không được, phải tách | OBSERVED |
| H-13 | Outlook nhận 8BITMIME/BINARYMIME | `probe` | advertised | OBSERVED |
| H-14 | SMTPUTF8 RCPT bị reject khác | `probe` | 550 giống | NO DIFF |

## Ghi chú

- H-08/H-09/H-10 cần lab; không test lên MX production.
- H-11 ảnh hưởng trực tiếp chi phí; đo bằng log ESP (delivered vs accepted).
- Mọi kết quả phải kèm `reports/*.json` hoặc log.
