# Research workspace

Nơi ghi hypothesis, lab và disclosure. Không chứa credential thật, không chứa list người thật.

## Quy tắc

1. Chỉ test trên domain/IP/mailbox của bạn hoặc lab VM.
2. Không gửi DATA tới mailbox không thuộc sở hữu.
3. Không scan port 25 của provider với volume lớn; 1 connection/phút là đủ.
4. Lưu evidence: timestamp, IP nguồn, command, response, ảnh.
5. Finding phải có status `OBSERVED` / `THEORETICAL` / `PATCHED`.

## Lab MTA

```bash
# Postfix cũ (mục đích test smuggling) - chạy trong VM cô lập
docker run -d --name pf-lab -p 2525:25 \
  -e SMTPD_BANNER="lab" \
  boky/postfix:3.7.4
```

Gửi thử:

```powershell
# terminal khác
$sw = [System.Net.Sockets.TcpClient]::new('127.0.0.1',2525)
$ns = $sw.GetStream(); $rd = [IO.StreamReader]::new($ns); $wr = [IO.StreamWriter]::new($ns)
$wr.NewLine = "`r`n"; $wr.AutoFlush = $true
$rd.ReadLine()
$wr.WriteLine("EHLO lab"); 1..5 | % { $rd.ReadLine() }
$wr.WriteLine("MAIL FROM:<a@lab.test>"); $rd.ReadLine()
$wr.WriteLine("RCPT TO:<b@lab.test>"); $rd.ReadLine()
$wr.WriteLine("DATA"); $rd.ReadLine()
$wr.WriteLine("Subject: one"); $wr.WriteLine(""); $wr.WriteLine("body"); $wr.WriteLine(".")
$wr.WriteLine("QUIT")
```

Sau đó thử biến thể kết thúc bằng `\n.\n` thay vì `\r\n.\r\n` và xem log/queue có 1 hay 2 message.

## Hypothesis log

Xem `hypotheses.md`. Mỗi dòng: ID, giả thuyết, cách test, kết quả, status.

## Disclosure

Xem `disclosure-template.md`. Gửi tới security@vendor, không đăng PoC trước 90 ngày.
