import { resolveMx } from '../lib/dns.js';
import { SmtpClient } from '../lib/smtp.js';
import { randomLocal } from '../lib/util.js';

/**
 * SMTP command-rate probe: how many connections/RCPT a receiver tolerates from
 * this egress IP before 421/450/451 or connection resets. Does NOT send DATA
 * and does not touch real mailboxes (random local parts only).
 */
export async function probeRateLimit({ policy, domain = 'gmail.com', connections = 10, rcptPerConn = 5, concurrency = 2, timeout = 12000 }) {
  const mx = await resolveMx(domain);
  if (!mx.length) throw new Error(`no MX for ${domain}`);
  const host = mx[0].exchange;
  const report = {
    domain, host, startedAt: new Date().toISOString(),
    connectionsRequested: connections, rcptPerConn,
    results: [], summary: {},
  };

  const jobs = Array.from({ length: connections }, (_, i) => i);
  const workers = Array.from({ length: Math.max(1, Math.min(concurrency, connections)) }, async () => {
    while (jobs.length) {
      const idx = jobs.shift();
      const row = { connection: idx, rcpt: [], error: null, openedAt: Date.now() };
      const c = new SmtpClient({ host, port: 25, timeout, log: () => {} });
      try {
        await c.connect();
        await c.greet(policy.helo_host || 'probe.local');
        if (c.supports('STARTTLS')) { try { await c.starttls(policy.helo_host || 'probe.local'); } catch { /* plaintext */ } }
        const mf = await c.mailFrom(policy.from_address || 'probe@example.com');
        row.mail = { code: mf.code, ms: Date.now() - row.openedAt };
        if (mf.code === 250) {
          for (let i = 0; i < rcptPerConn; i++) {
            const t = Date.now();
            const r = await c.rcptTo(`${randomLocal(16)}@${domain}`);
            row.rcpt.push({ code: r.code, ms: Date.now() - t, text: r.text.slice(0, 120) });
            if (r.code === 421 || r.code === 450 || r.code === 451 || r.code === 452) break;
          }
        }
        await c.quit();
      } catch (err) {
        row.error = err.code || err.message;
        row.closed = true;
        c.destroy();
      }
      row.totalMs = Date.now() - row.openedAt;
      report.results.push(row);
    }
  });
  await Promise.all(workers);

  const allRcpt = report.results.flatMap((r) => r.rcpt);
  const codes = {};
  for (const r of allRcpt) codes[r.code] = (codes[r.code] || 0) + 1;
  const ms = allRcpt.map((r) => r.ms).sort((a, b) => a - b);
  const q = (p) => ms.length ? ms[Math.min(ms.length - 1, Math.floor(ms.length * p))] : null;
  report.summary = {
    connectionsOpened: report.results.filter((r) => r.mail).length,
    connectionsClosedEarly: report.results.filter((r) => r.closed).length,
    totalRcpt: allRcpt.length,
    codes,
    p50ms: q(0.5), p95ms: q(0.95),
    throttled: Object.keys(codes).some((c) => ['421', '450', '451', '452'].includes(c)),
    blockedAtMail: report.results.filter((r) => r.mail && r.mail.code >= 500).length,
    maxRcptInOneConnection: Math.max(0, ...report.results.map((r) => r.rcpt.length)),
  };
  report.finishedAt = new Date().toISOString();
  return report;
}
