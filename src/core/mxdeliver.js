import { resolveMx } from '../lib/dns.js';
import { prepareMessage } from './sender.js';
import { transact, SmtpError } from '../lib/smtp.js';

/**
 * Direct-to-MX delivery: no ESP, no credentials, connect to the recipient's MX
 * and speak SMTP. Works only when your egress IP has PTR + is not blocklisted;
 * used here to measure exactly which receivers accept this host.
 */
export async function sendDirectJob({ job, policy, templates, keys, logger, timeout = 20000 }) {
  const prep = prepareMessage({ job, policy, templates, keys });
  if (!prep.raw) return prep;
  const { raw, messageId, spam } = prep;

  const domain = job.email.split('@').pop().toLowerCase();
  const mx = await resolveMx(domain);
  if (!mx.length) return { status: 'bounced', reason: 'no MX', messageId, spam, path: 'direct' };

  const helo = policy.helo_host || policy.from_domain;
  const envelopeFrom = policy.direct_envelope_from || policy.from_address || `news@${policy.from_domain}`;
  const started = Date.now();
  let lastErr = null;

  for (const record of mx.slice(0, 2)) {
    const host = record.exchange;
    let client;
    try {
      const t = await transact({
        host, port: 25, secure: false, starttls: true,
        heloHost: helo, servername: host, timeout, log: (line) => logger?.info(`direct=${host} ${line}`),
      });
      client = t.client;
      try {
        const mf = await client.mailFrom(envelopeFrom);
        if (![250, 251].includes(mf.code)) throw new SmtpError('MAIL FROM rejected', mf.code, mf.text);
        const rcpt = await client.rcptTo(job.email);
        if (![250, 251].includes(rcpt.code)) {
          if (rcpt.code >= 500) {
            return { status: 'bounced', reason: rcpt.text, code: rcpt.code, messageId, spam, path: 'direct', host };
          }
          throw new SmtpError('RCPT retry', rcpt.code, rcpt.text);
        }
        const accepted = await client.data(raw);
        return {
          status: 'sent', path: 'direct', host, messageId, code: accepted.code,
          reply: accepted.text, ms: Date.now() - started, spam, size: raw.length,
        };
      } finally {
        await client.quit();
      }
    } catch (err) {
      lastErr = err;
      client?.destroy();
      const code = err.code || 0;
      if (code >= 500 && code < 600) {
        return { status: 'bounced', reason: err.message, code, messageId, spam, path: 'direct', host };
      }
      // connection/TLS/timeout: try the next MX, then retry later
    }
  }

  return {
    status: 'retry',
    reason: lastErr?.message || 'all MX failed',
    code: lastErr?.code || 0,
    retrySeconds: 300,
    messageId,
    spam,
    path: 'direct',
  };
}

export function isDirectDomain(domain, directDomains) {
  return directDomains.includes(domain.toLowerCase());
}
