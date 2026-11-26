import { SmtpClient } from '../src/lib/smtp.js';
import { resolveMx } from '../src/lib/dns.js';
const domains = ['gmail.com','outlook.com','yahoo.com','icloud.com','aol.com','zoho.com','yandex.ru','mail.ru','gmx.net','web.de','fastmail.com','proton.me','qq.com','163.com','naver.com','daum.net'];
const rows = [];
for (const d of domains) {
  let mx = [];
  try { mx = await resolveMx(d); } catch { /* */ }
  if (!mx.length) { rows.push({ d, mx: 'none' }); continue; }
  const host = mx.sort((a,b)=>a.priority-b.priority)[0].exchange;
  const c = new SmtpClient({ host, port: 25, timeout: 9000 });
  const rec = { d, mx: host };
  try {
    await c.connect();
    await c.greet('mail.' + d);
    const mf = await c.mailFrom('postmaster@' + d);
    rec.mailFrom = mf.code;
    rec.mfText = mf.text.replace(/\s+/g,' ').slice(0, 90);
    if ([250,251].includes(mf.code)) {
      const rc = await c.rcptTo('postmaster@' + d);
      rec.rcpt = rc.code;
      rec.rcText = rc.text.replace(/\s+/g,' ').slice(0, 90);
    }
  } catch (e) { rec.error = e.code || e.message; }
  finally { try { await c.quit(); } catch { /* */ } }
  rows.push(rec); console.log(JSON.stringify(rec));
}
console.log('ACCEPTED:', rows.filter(r => r.rcpt === 250).map(r => r.d).join(','));
