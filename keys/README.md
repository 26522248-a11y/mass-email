# keys/

`<domain>.json` chứa private key DKIM + selector. **Không commit, không chia sẻ.**

File trong repo này (`mail.example.com.json`) chỉ là **demo** — regenerate trước khi dùng thật:

```powershell
node src/cli.js keys --domain mail.example.com --selector s1
```

Quyền file (Windows ACL / Linux chmod 600):

```powershell
icacls keys\mail.example.com.json /inheritance:r /grant:r "$env:USERNAME:(R,W)"
```

Rotate 6-12 tháng: sinh selector mới (`s2`), publish DNS, chờ TTL, đổi selector, giữ `s1` thêm 7 ngày.
