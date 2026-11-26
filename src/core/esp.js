import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { randomHex } from '../lib/util.js';
import { renderJob } from './sender.js';
import { htmlFromText } from '../lib/mime.js';

/**
 * Free-tier ESP adapters. The point is to send from provider infrastructure
 * over HTTPS (443), which never touches port 25/587 and therefore ignores the
 * local egress IP reputation that blocks direct-to-MX.
 *
 * Every provider below has a permanent free plan that does NOT require a paid
 * domain: a single verified sender address is enough for the "sender verify"
 * ones. Limits are the vendor's published free tier; re-check at signup.
 */
export const PROVIDERS = [
  {
    id: 'brevo', name: 'Brevo (ex-Sendinblue)', free: '300/day, unlimited contacts, forever',
    signup: 'email only, no card', requires: 'verified sender email', domain_required: false,
    smtp: { host: 'smtp-relay.brevo.com', port: 587 },
    api: { url: 'https://api.brevo.com/v3/smtp/email', auth: 'api-key' },
    daily_limit: 300, docs: 'https://developers.brevo.com/reference/sendtransacemail',
  },
  {
    id: 'sendgrid', name: 'Twilio SendGrid', free: '100/day, forever',
    signup: 'email + phone, no card', requires: 'Single Sender Verification', domain_required: false,
    smtp: { host: 'smtp.sendgrid.net', port: 587 },
    api: { url: 'https://api.sendgrid.com/v3/mail/send', auth: 'bearer' },
    daily_limit: 100, docs: 'https://www.twilio.com/docs/sendgrid/api-reference/mail-send/mail-send',
  },
  {
    id: 'mailjet', name: 'Mailjet (Sinch)', free: '200/day, 6,000/month',
    signup: 'email + phone, no card', requires: 'validated sender email', domain_required: false,
    smtp: { host: 'in-v3.mailjet.com', port: 587 },
    api: { url: 'https://api.mailjet.com/v3.1/send', auth: 'basic' },
    daily_limit: 200, docs: 'https://dev.mailjet.com/email/guides/send-api-v31/',
  },
  {
    id: 'elasticemail', name: 'Elastic Email', free: '100/day',
    signup: 'email, no card', requires: 'verified sender email', domain_required: false,
    smtp: { host: 'smtp.elasticemail.com', port: 2525 },
    api: { url: 'https://api.elasticemail.com/v4/emails', auth: 'x-api-key' },
    daily_limit: 100, docs: 'https://elasticemail.com/developers/api-documentation/web-api-v4',
  },
  {
    id: 'smtp2go', name: 'SMTP2GO', free: '1,000/month (~33/day)',
    signup: 'email, no card', requires: 'verified sender email', domain_required: false,
    smtp: { host: 'mail.smtp2go.com', port: 2525 },
    api: { url: 'https://api.smtp2go.com/v3/email/send', auth: 'x-api-key' },
    daily_limit: 33, docs: 'https://apidoc.smtp2go.com/documentation/#/POST/email/send',
  },
  {
    id: 'sendpulse', name: 'SendPulse', free: '15,000/month on free plan',
    signup: 'email, moderation', requires: 'verified sender + moderation', domain_required: false,
    smtp: { host: 'smtp-pulse.com', port: 465, secure: true },
    api: { url: 'https://api.sendpulse.com/smtp/emails', auth: 'oauth' },
    daily_limit: 500, docs: 'https://sendpulse.com/integrations/api/smtp',
  },
  {
    id: 'resend', name: 'Resend', free: '3,000/month',
    signup: 'email or GitHub, no card', requires: 'own domain (sandbox sends only to you)', domain_required: true,
    smtp: { host: 'smtp.resend.com', port: 587 },
    api: { url: 'https://api.resend.com/emails', auth: 'bearer' },
    daily_limit: 100, docs: 'https://resend.com/docs/api-reference/emails/send-email',
  },
  {
    id: 'mailersend', name: 'MailerSend', free: '3,000/month (trial domain)',
    signup: 'email, no card', requires: 'own domain for production', domain_required: true,
    smtp: { host: 'smtp.mailersend.net', port: 587 },
    api: { url: 'https://api.mailersend.com/v1/email', auth: 'bearer' },
    daily_limit: 100, docs: 'https://developers.mailersend.com/api/v1/email.html',
  },
];

export function getProvider(id) {
  const p = PROVIDERS.find((x) => x.id === id);
  if (!p) throw new Error(`unknown provider ${id}; one of ${PROVIDERS.map((x) => x.id).join(', ')}`);
  return p;
}

function unsubHeaders(policy, row) {
  const headers = {};
  const mailto = policy.unsubscribe_mailto
    ? `<mailto:${policy.unsubscribe_mailto}?subject=unsub-${encodeURIComponent(row.token || row.email)}>`
    : '';
  const url = row.unsubscribe ? `<${row.unsubscribe}>` : '';
  const combined = [mailto, url].filter(Boolean).join(', ');
  if (combined) headers['List-Unsubscribe'] = combined;
  if (policy.one_click_unsubscribe && combined) headers['List-Unsubscribe-Post'] = 'List-Unsubscribe=One-Click';
  if (policy.headers?.['X-Entity-Ref-ID']) headers['X-Entity-Ref-ID'] = randomHex(16);
  if (policy.headers?.['Feedback-ID']) headers['Feedback-ID'] = String(policy.headers['Feedback-ID']);
  return headers;
}

/** Build the provider-specific JSON body plus the HTTP request envelope. */
export function buildEspRequest({ provider, job, policy, templates, cfg }) {
  const p = typeof provider === 'string' ? getProvider(provider) : provider;
  const sender = cfg.from || policy.from_address;
  if (!sender) throw new Error('sender address missing (cfg.from or policy.from_address)');
  const { row, subject, text, html } = renderJob({ job, policy, templates });
  const body = html || htmlFromText(text);
  const name = cfg.name || policy.from_name || '';
  const headers = unsubHeaders(policy, row);
  const replyTo = cfg.reply_to || policy.reply_to || undefined;

  const envelope = (json) => ({
    provider: p.id,
    url: cfg.url || p.api.url,
    json,
    headers: buildAuthHeaders(p, cfg),
  });

  switch (p.id) {
    case 'brevo':
      return envelope({
        sender: { email: sender, name },
        to: [{ email: job.email }],
        subject,
        htmlContent: body,
        textContent: text,
        headers,
        replyTo: replyTo ? { email: replyTo } : undefined,
      });
    case 'sendgrid':
      return envelope({
        personalizations: [{ to: [{ email: job.email }] }],
        from: { email: sender, name },
        reply_to: replyTo ? { email: replyTo } : undefined,
        subject,
        content: [
          { type: 'text/plain', value: text },
          { type: 'text/html', value: body },
        ],
        headers,
      });
    case 'mailjet':
      return envelope({
        Messages: [{
          From: { Email: sender, Name: name },
          To: [{ Email: job.email }],
          ReplyTo: replyTo ? { Email: replyTo } : undefined,
          Subject: subject,
          TextPart: text,
          HTMLPart: body,
          Headers: headers,
        }],
      });
    case 'elasticemail':
      return envelope({
        Recipients: [{ Email: job.email }],
        Content: {
          From: name ? `${name} <${sender}>` : sender,
          Subject: subject,
          Body: [
            { ContentType: 'HTML', Content: body, Charset: 'utf-8' },
            { ContentType: 'PlainText', Content: text, Charset: 'utf-8' },
          ],
        },
        Headers: headers,
      });
    case 'smtp2go':
      return envelope({
        sender,
        to: [job.email],
        subject,
        text_body: text,
        html_body: body,
        custom_headers: Object.entries(headers).map(([header, value]) => ({ header, value })),
      });
    case 'sendpulse':
      return envelope({
        email: {
          html: Buffer.from(body).toString('base64'),
          text: Buffer.from(text).toString('base64'),
          subject,
          from: { name, email: sender },
          to: [{ name: row.name || '', email: job.email }],
        },
      });
    case 'resend':
      return envelope({ from: name ? `${name} <${sender}>` : sender, to: [job.email], subject, html: body, text, headers });
    case 'mailersend':
      return envelope({
        from: { email: sender, name },
        to: [{ email: job.email }],
        reply_to: replyTo ? { email: replyTo } : undefined,
        subject,
        html: body,
        text,
        headers: Object.entries(headers).map(([n, v]) => ({ name: n, value: v })),
      });
    default:
      throw new Error(`no payload adapter for ${p.id}`);
  }
}

export function buildAuthHeaders(provider, cfg) {
  const h = { 'content-type': 'application/json' };
  switch (provider.api.auth) {
    case 'api-key': h['api-key'] = cfg.api_key; break;
    case 'bearer': h.authorization = `Bearer ${cfg.api_key}`; break;
    case 'x-api-key':
      h[provider.id === 'smtp2go' ? 'X-Smtp2go-Api-Key' : 'X-ElasticEmail-ApiKey'] = cfg.api_key;
      break;
    case 'basic': h.authorization = 'Basic ' + Buffer.from(`${cfg.api_key}:${cfg.secret}`).toString('base64'); break;
    case 'oauth': h.authorization = `Bearer ${cfg.access_token || ''}`; break;
    default: throw new Error(`unknown auth ${provider.api.auth}`);
  }
  return h;
}

const tokenCache = new Map();

async function sendpulseToken(cfg, timeout) {
  const key = cfg.client_id || cfg.api_key;
  const hit = tokenCache.get(key);
  if (hit && hit.expires > Date.now() + 60_000) return hit.token;
  const res = await fetch('https://api.sendpulse.com/oauth/access_token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ grant_type: 'client_credentials', client_id: cfg.api_key, client_secret: cfg.secret }),
    signal: AbortSignal.timeout(timeout),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok || !json.access_token) throw new Error(`sendpulse token ${res.status}: ${json.message || json.error || 'failed'}`);
  tokenCache.set(key, { token: json.access_token, expires: Date.now() + (json.expires_in || 3600) * 1000 });
  return json.access_token;
}

/** Send one job through one free-tier account. Never throws. */
export async function sendEspJob({ job, policy, templates, cfg, timeout = 25000 }) {
  const provider = getProvider(cfg.provider);
  let req;
  try {
    req = buildEspRequest({ provider, job, policy, templates, cfg });
  } catch (err) {
    return { status: 'failed', path: `esp:${provider.id}`, reason: err.message };
  }

  if (provider.api.auth === 'oauth') {
    try { cfg = { ...cfg, access_token: await sendpulseToken(cfg, timeout) }; }
    catch (err) { return { status: 'retry', path: `esp:${provider.id}`, reason: err.message, retrySeconds: 120 }; }
    req.headers = buildAuthHeaders(provider, cfg);
  }

  const started = Date.now();
  for (let attempt = 0; attempt < 2; attempt++) {
    let res;
    try {
      res = await fetch(req.url, {
        method: 'POST',
        headers: req.headers,
        body: JSON.stringify(req.json),
        signal: AbortSignal.timeout(timeout),
      });
    } catch (err) {
      return { status: 'retry', path: `esp:${provider.id}`, reason: err.name === 'TimeoutError' ? 'api timeout' : err.message, retrySeconds: 60 };
    }
    const text = await res.text().catch(() => '');
    if (res.ok) {
      let messageId = null;
      try { const j = JSON.parse(text); messageId = j.messageId || j.message_id || j.data?.email_id || j.data?.messages?.[0]?.id || null; } catch { /* non-json ok */ }
      return { status: 'sent', path: `esp:${provider.id}`, code: res.status, ms: Date.now() - started, messageId, sender: cfg.from };
    }
    if (res.status === 401 && provider.api.auth === 'oauth' && attempt === 0) {
      tokenCache.delete(cfg.client_id || cfg.api_key);
      cfg = { ...cfg, access_token: await sendpulseToken(cfg, timeout) };
      req.headers = buildAuthHeaders(provider, cfg);
      continue;
    }
    if (res.status === 429) {
      const retry = Number(res.headers.get('retry-after')) || 60;
      return { status: 'retry', path: `esp:${provider.id}`, code: 429, reason: 'provider throttle', retrySeconds: retry };
    }
    if (res.status >= 500) return { status: 'retry', path: `esp:${provider.id}`, code: res.status, reason: text.slice(0, 200), retrySeconds: 90 };
    if (res.status === 401 || res.status === 403) return { status: 'failed', path: `esp:${provider.id}`, code: res.status, reason: `auth/kyc: ${text.slice(0, 200)}` };
    return { status: 'bounced', path: `esp:${provider.id}`, code: res.status, reason: text.slice(0, 300) };
  }
  return { status: 'retry', path: `esp:${provider.id}`, reason: 'retry exhausted', retrySeconds: 60 };
}

/* ------------------------------- account pool ------------------------------ */

export class EspPool {
  constructor({ accounts = [], stateFile }) {
    this.accounts = accounts;
    this.stateFile = stateFile;
    this.state = { day: today(), sent: {}, ...readState(stateFile) };
    if (this.state.day !== today()) { this.state = { day: today(), sent: {} }; }
    this.save();
  }

  save() {
    if (!this.stateFile) return;
    try { fsWrite(this.stateFile, this.state); } catch { /* ignore */ }
  }

  remaining(account) {
    const used = this.state.sent[account.id] || 0;
    const limit = Number(account.daily_limit) || 50;
    return Math.max(0, limit - used);
  }

  /** Least-used account first, so free quotas drain evenly. */
  pick(providerId = null) {
    const candidates = this.accounts.filter((a) => (!providerId || a.provider === providerId) && this.remaining(a) > 0);
    if (!candidates.length) return null;
    candidates.sort((a, b) => {
      const ua = (this.state.sent[a.id] || 0) / (Number(a.daily_limit) || 50);
      const ub = (this.state.sent[b.id] || 0) / (Number(b.daily_limit) || 50);
      return ua - ub;
    });
    return candidates[0];
  }

  markSent(account) {
    if (this.state.day !== today()) this.state = { day: today(), sent: {} };
    this.state.sent[account.id] = (this.state.sent[account.id] || 0) + 1;
    this.save();
  }

  stats() {
    return this.accounts.map((a) => ({
      id: a.id,
      provider: a.provider,
      from: a.from,
      used: this.state.sent[a.id] || 0,
      limit: Number(a.daily_limit) || 50,
      remaining: this.remaining(a),
    }));
  }
}

function today() { return new Date().toISOString().slice(0, 10); }

function readState(file) {
  if (!file) return {};
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return {}; }
}

function fsWrite(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n');
}

/* --------------------------------- probing -------------------------------- */

function tcpOpen(host, port, timeout = 8000) {
  return new Promise((resolve) => {
    const s = net.connect(port, host);
    let done = false;
    const end = (r) => { if (done) return; done = true; s.destroy(); resolve(r); };
    s.setTimeout(timeout, () => end({ ok: false, error: 'timeout' }));
    s.on('error', (e) => end({ ok: false, error: e.code || e.message }));
    s.on('connect', () => end({ ok: true }));
  });
}

function smtpCaps(host, port, timeout = 9000) {
  return new Promise((resolve) => {
    const s = net.connect(port, host);
    let buf = '';
    let stage = 0;
    let done = false;
    const end = (r) => { if (done) return; done = true; s.destroy(); resolve(r); };
    s.setTimeout(timeout, () => end({ ok: false, error: 'timeout' }));
    s.on('error', (e) => end({ ok: false, error: e.code || e.message }));
    s.on('connect', () => {});
    s.on('data', (d) => {
      buf += d.toString();
      if (stage === 0 && /^220[ -]/.test(buf)) { stage = 1; buf = ''; s.write('EHLO probe.local\r\n'); return; }
      if (stage === 1) {
        const lines = buf.split('\r\n').filter((l) => /^\d{3}[ -]/.test(l));
        if (!lines.length) return;
        const last = lines[lines.length - 1];
        if (last[3] !== ' ') return;
        const caps = lines.map((l) => l.slice(4)).filter(Boolean);
        end({ ok: true, caps: caps.slice(0, 12), auth: caps.some((c) => /^AUTH\b/i.test(c)), tls: caps.includes('STARTTLS') });
      }
    });
  });
}

/**
 * Live reachability of a provider: HTTPS API port + SMTP submission port.
 * Nothing here needs a key. A 401/403 from the API means "reachable, needs auth".
 */
export async function probeProvider(provider, timeout = 9000) {
  const p = typeof provider === 'string' ? getProvider(provider) : provider;
  const apiHost = new URL(p.api.url).hostname;
  const [api, smtp, tlsProbe] = await Promise.all([
    tcpOpen(apiHost, 443, timeout),
    tcpOpen(p.smtp.host, p.smtp.port, timeout),
    smtpCaps(p.smtp.host, p.smtp.port, timeout + 3000),
  ]);
  return {
    id: p.id,
    name: p.name,
    free: p.free,
    requires: p.requires,
    domain_required: p.domain_required,
    api: { host: apiHost, reachable: api.ok, error: api.error || null },
    smtp: { host: p.smtp.host, port: p.smtp.port, reachable: smtp.ok, error: smtp.error || null, auth: tlsProbe.auth || false, starttls: tlsProbe.tls || false, caps: tlsProbe.caps || [] },
  };
}

export async function probeAll(timeout = 9000) {
  const out = [];
  for (const p of PROVIDERS) out.push(await probeProvider(p, timeout));
  return out;
}

export function espSummary(rows) {
  const usable = rows.filter((r) => r.api.reachable && r.smtp.reachable);
  return {
    providers: rows.length,
    reachable: usable.length,
    sender_verify_only: usable.filter((r) => !r.domain_required).length,
    combined_daily_capacity: usable.filter((r) => !r.domain_required).reduce((n, r) => n + (getProvider(r.id).daily_limit || 0), 0),
  };
}
