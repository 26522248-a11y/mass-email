import { SmtpClient } from '../lib/smtp.js';
import { resolveMx } from '../lib/dns.js';
import { normalizeEmail, isValidEmail, randomLocal, sleep, clamp } from '../lib/util.js';

export const DISPOSABLE = new Set([
  'mailinator.com', 'guerrillamail.com', '10minutemail.com', 'tempmail.com', 'temp-mail.org',
  'throwawaymail.com', 'yopmail.com', 'sharklasers.com', 'getnada.com', 'dispostable.com',
  'trashmail.com', 'maildrop.cc', 'mintemail.com', 'mytemp.email', 'spamgourmet.com',
]);

export const ROLE = new Set(['admin', 'info', 'support', 'sales', 'contact', 'hello', 'billing', 'postmaster', 'abuse', 'webmaster', 'noreply', 'no-reply']);

const FREE = new Set(['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'yahoo.com', 'ymail.com', 'aol.com', 'icloud.com', 'me.com', 'proton.me', 'protonmail.com', 'gmx.com', 'mail.com', 'zoho.com', 'yandex.com']);

export function classifyAddress(email) {
  const [local, domain] = normalizeEmail(email).split('@');
  return {
    email: normalizeEmail(email),
    domain,
    local,
    validSyntax: isValidEmail(email),
    disposable: DISPOSABLE.has(domain),
    role: ROLE.has(local),
    free: FREE.has(domain),
    plusAlias: local.includes('+'),
    dotAlias: local.includes('.'),
  };
}

async function rcpt(host, email, policy, timeout) {
  const client = new SmtpClient({ host, port: 25, timeout });
  const out = { host, code: 0, reply: '', greylisted: false };
  try {
    await client.connect();
    await client.greet(policy.helo_host || 'verify.local');
    if (client.supports('STARTTLS')) { try { await client.starttls(policy.helo_host || 'verify.local'); } catch { /* plaintext probe */ } }
    const mf = await client.mailFrom(policy.mail_from || 'verify@example.com');
    if (![250, 251].includes(mf.code)) { out.code = mf.code; out.reply = mf.text; return out; }
    const r = await client.rcptTo(email);
    out.code = r.code;
    out.reply = r.text;
    out.greylisted = /grey|gray|defer|try again/i.test(r.text);
    await client.quit();
  } catch (err) {
    out.code = err.code || -1;
    out.reply = err.message;
    out.error = err.code || err.name;
    client.destroy();
  }
  return out;
}

/**
 * Verify one address without sending DATA. `mode=direct` needs outbound port 25.
 * Returns valid | invalid | risky | unknown.
 */
export async function verifyEmail(email, policy, { timeout = 15000, catchAllProbes = 2 } = {}) {
  const info = classifyAddress(email);
  if (!info.validSyntax) return { ...info, status: 'invalid', reason: 'syntax' };

  const mx = await resolveMx(info.domain);
  if (!mx.length || !mx[0].exchange) return { ...info, status: 'invalid', reason: 'no-mx' };
  const hosts = mx.slice(0, 2).map((m) => m.exchange);

  const primary = await rcpt(hosts[0], info.email, policy, timeout);
  if (primary.code === 250 || primary.code === 251) {
    let catchAll = false;
    if (catchAllProbes > 0) {
      for (let i = 0; i < catchAllProbes; i++) {
        const probe = await rcpt(hosts[0], `${randomLocal(14)}@${info.domain}`, policy, timeout);
        if (probe.code === 250 || probe.code === 251) { catchAll = true; break; }
        if (probe.code === -1) break;
      }
    }
    const flags = [info.disposable && 'disposable', info.role && 'role', catchAll && 'catch-all'].filter(Boolean);
    return {
      ...info, status: catchAll ? 'risky' : 'valid', catchAll, flags,
      reason: catchAll ? 'domain accepts all recipients' : 'rcpt accepted', code: primary.code, reply: primary.reply,
    };
  }
  if (primary.greylisted || (primary.code >= 400 && primary.code < 500)) {
    return { ...info, status: 'unknown', reason: 'greylisted/4xx', code: primary.code, reply: primary.reply };
  }
  if (primary.code >= 500) {
    return { ...info, status: 'invalid', reason: primary.reply || 'rejected', code: primary.code, reply: primary.reply };
  }
  // Try backup MX on connection failure
  if (hosts[1]) {
    const backup = await rcpt(hosts[1], info.email, policy, timeout);
    if (backup.code === 250 || backup.code === 251) return { ...info, status: 'valid', reason: 'backup-mx accepted' };
  }
  return { ...info, status: 'unknown', reason: primary.error || primary.reply || 'unreachable' };
}

export async function verifyBatch(rows, policy, { concurrency = 8, onResult } = {}) {
  const queue = [...rows];
  const results = [];
  const workers = Array.from({ length: Math.max(1, concurrency) }, async () => {
    while (queue.length) {
      const row = queue.shift();
      if (!row) break;
      const res = await verifyEmail(row.email, policy, { catchAllProbes: policy.catch_all_probes ?? 2 });
      results.push({ ...row, ...res });
      onResult?.(results.at(-1));
      await sleep(80 + Math.random() * 120);
    }
  });
  await Promise.all(workers);
  return results;
}

export function verificationSummary(results) {
  const summary = { total: results.length, valid: 0, invalid: 0, risky: 0, unknown: 0, disposable: 0, role: 0, catchAll: 0 };
  for (const r of results) {
    summary[r.status] = (summary[r.status] || 0) + 1;
    if (r.disposable) summary.disposable += 1;
    if (r.role) summary.role += 1;
    if (r.catchAll) summary.catchAll += 1;
  }
  summary.deliverableRate = summary.total ? clamp((summary.valid / summary.total) * 100, 0, 100).toFixed(1) + '%' : '0%';
  return summary;
}
