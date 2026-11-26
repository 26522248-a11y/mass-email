import fs from 'node:fs';
import path from 'node:path';
import { buildMessage, render, rngFor, htmlFromText } from '../lib/mime.js';
import { signMessage } from '../lib/dkim.js';
import { transact, SmtpError } from '../lib/smtp.js';
import { scoreMessage } from '../lib/spamscore.js';
import { readJson, tokenizeUrl, sleep } from '../lib/util.js';

export function loadKeys(keysDir) {
  const keys = {};
  if (!fs.existsSync(keysDir)) return keys;
  for (const file of fs.readdirSync(keysDir)) {
    if (!file.endsWith('.json')) continue;
    const data = readJson(path.join(keysDir, file));
    if (data?.privateKey && data?.selector) keys[file.replace(/\.json$/, '')] = data;
  }
  return keys;
}

export function loadTemplates(policy, root, textFile, htmlFile) {
  const text = fs.readFileSync(textFile, 'utf8');
  const html = htmlFile ? fs.readFileSync(htmlFile, 'utf8') : null;
  return { text, html, policy, root };
}

function unsubscribeFor(policy, row) {
  return tokenizeUrl(policy.unsubscribe_url, row);
}

export function renderJob({ job, policy, templates }) {
  const rng = rngFor(job.id + job.email);
  const row = { ...policy, ...job.row };
  if (policy.unsubscribe_url) row.unsubscribe = unsubscribeFor(policy, row);
  row.url = row.url || policy.link_url || 'https://example.com';
  const subject = render(policy.subject, row, rng);
  const text = render(templates.text, row, rng);
  const html = templates.html ? render(templates.html, row, rng) : null;
  return { row, subject, text, html };
}

/**
 * Render + build + DKIM-sign one job. Shared by relay and direct-MX paths.
 * Returns { status:'held'|'failed', ... } when the message must not be sent,
 * otherwise { raw, messageId, spam, size, envelopeFrom, fromDomain }.
 */
export function prepareMessage({ job, policy, templates, keys }) {
  const rendered = renderJob({ job, policy, templates });
  const { row, subject, text, html } = rendered;

  const spam = scoreMessage({ subject, text, html, hasUnsubscribe: Boolean(row.unsubscribe) });
  if (policy.spamscore && spam.score > policy.spamscore.fail_over) {
    return { status: 'held', reason: `spamscore ${spam.score}`, spam };
  }

  const fromDomain = (row.from_address || policy.from_address || `news@${policy.from_domain}`).split('@').pop().toLowerCase();
  const key = keys[fromDomain];
  const policyHeaders = row.headers && !Array.isArray(row.headers)
    ? Object.entries(row.headers).filter(([, v]) => v).map(([k, v]) => [k, String(v)])
    : (row.headers || []);

  let message;
  try {
    message = buildMessage({
      row, subject, text, html, policy,
      fromName: policy.from_name || '',
      from: job.from || policy.from_address || `news@${fromDomain}`,
      replyTo: policy.reply_to,
      unsubscribeMailto: policy.unsubscribe_mailto,
      token: row.token || row.email,
      domain: fromDomain,
      extraHeaders: policyHeaders,
    });
  } catch (err) {
    return { status: 'failed', reason: `build: ${err.message}`, spam };
  }

  let raw = message.raw;
  if (key && policy.sign !== false) {
    const dkim = signMessage({
      rawHeaders: message.headers, body: message.body,
      domain: fromDomain, selector: key.selector, privateKey: key.privateKey,
    });
    raw = dkim + '\r\n' + raw;
  }

  const envelopeFrom = job.return_path || policy.return_path || `bounce@${policy.return_path_domain || fromDomain}`;
  return { raw, messageId: message.messageId, spam, size: raw.length, envelopeFrom, fromDomain, row };
}

/**
 * Send one job through a relay pool. Returns classification without throwing.
 */
export async function sendJob({ job, pool, guard, policy, templates, keys, logger, dryRun = false, timeout = 25000, relayId = null }) {
  if (dryRun) {
    const prep = prepareMessage({ job, policy, templates, keys });
    if (!prep.raw) return prep;
    return { status: 'dry', messageId: prep.messageId, spam: prep.spam, size: prep.size, relayId: 'dry-run' };
  }

  let relay = null;
  if (relayId) {
    const forced = pool.get(relayId);
    if (!forced || !guard.acquire(forced.id)) return { status: 'retry', reason: `relay ${relayId} unavailable`, retrySeconds: 60 };
    relay = forced;
  } else {
    for (let i = 0; i < 50; i++) {
      const candidate = pool.pick();
      if (!candidate) return { status: 'retry', reason: 'no relay available', retrySeconds: 120 };
      if (guard.acquire(candidate.id)) { relay = candidate; break; }
      await sleep(100);
    }
  }
  if (!relay) return { status: 'retry', reason: 'all relays saturated', retrySeconds: 30 };

  // Bind From to the chosen relay: Gmail/Outlook submission requires the
  // authenticated account (or a verified alias) in From.
  const boundJob = { ...job, from: job.from || relay.from || policy.from_address };
  const prep = prepareMessage({ job: boundJob, policy, templates, keys });
  if (!prep.raw) { guard.release(relay.id); return prep; }
  const { raw, messageId, spam } = prep;
  // Some providers (Gmail/Outlook consumer) only accept an envelope sender
  // that belongs to the authenticated account.
  const envelopeFrom = job.return_path || relay.return_path || policy.return_path || prep.envelopeFrom;

  const started = Date.now();
  try {
    const { client } = await transact({
      host: relay.host, port: relay.port, secure: Boolean(relay.secure), starttls: relay.starttls !== false,
      user: relay.user, pass: relay.access_token || relay.pass, authMethod: relay.auth,
      heloHost: relay.helo_host || policy.helo_host || policy.from_domain,
      servername: relay.tls_servername || relay.host,
      timeout,
      log: (line) => logger?.info(`relay=${relay.id} ${line}`),
    });
    try {
      pool.markUsed(relay.id);
      const mf = await client.mailFrom(envelopeFrom, relay.mail_params || []);
      if (![250, 251].includes(mf.code)) throw new SmtpError('MAIL FROM rejected', mf.code, mf.text);
      const rcpt = await client.rcptTo(job.email, relay.rcpt_params || []);
      if (![250, 251].includes(rcpt.code)) {
        if (rcpt.code >= 500) {
          pool.recordSuccess(relay.id);
          return { status: 'bounced', reason: rcpt.text, code: rcpt.code, relayId: relay.id, spam, messageId };
        }
        throw new SmtpError('RCPT retry', rcpt.code, rcpt.text);
      }
      const accepted = await client.data(raw);
      pool.recordSuccess(relay.id);
      return {
        status: 'sent', relayId: relay.id, messageId, code: accepted.code,
        reply: accepted.text, ms: Date.now() - started, spam, size: raw.length,
      };
    } finally {
      await client.quit();
    }
  } catch (err) {
    const code = err.code || 0;
    if (code === 421 || code === 450 || code === 451 || code === 452 || /throttl|rate|too many|try again|temporar/i.test(err.message || '')) {
      pool.recordThrottle(relay.id, policy.retry?.throttle_cooldown_seconds || 900);
      return { status: 'retry', reason: err.message, code, relayId: relay.id, retrySeconds: 90, spam };
    }
    if (/auth|535|534|530/i.test(`${code} ${err.message}`)) {
      pool.recordFailure(relay.id, { permanent: true, auth: true });
      return { status: 'retry', reason: `auth: ${err.message}`, code, relayId: relay.id, retrySeconds: 300, spam };
    }
    if (code >= 500) {
      pool.recordFailure(relay.id, { permanent: true });
      return { status: 'bounced', reason: err.message, code, relayId: relay.id, spam };
    }
    pool.recordFailure(relay.id);
    return { status: 'retry', reason: err.message, code, relayId: relay.id, retrySeconds: 60, spam };
  } finally {
    guard.release(relay.id);
  }
}

export function templateHtmlOrNull(htmlPath) {
  if (!htmlPath) return null;
  return fs.readFileSync(htmlPath, 'utf8');
}

export { htmlFromText };

