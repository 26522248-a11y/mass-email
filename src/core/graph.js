import { randomHex } from '../lib/util.js';
import { renderJob } from './sender.js';
import { htmlFromText } from '../lib/mime.js';

/**
 * Microsoft 365 Graph sendMail. Uses application permissions
 * (Mail.Send) and a tenant app registration. Messages leave from Microsoft's
 * infrastructure, so local IP reputation is irrelevant.
 *
 * Required app permission: Mail.Send (application) + admin consent.
 * The sender mailbox must exist and the app must be allowed to SendAs it
 * (ApplicationAccessPolicy or tenant-wide consent).
 */
const tokenCache = new Map();

export async function graphToken(cfg) {
  const key = `${cfg.tenant_id}:${cfg.client_id}`;
  const hit = tokenCache.get(key);
  if (hit && hit.expires > Date.now() + 60_000) return hit.token;

  const url = cfg.token_url || process.env.GRAPH_TOKEN_URL || `https://login.microsoftonline.com/${cfg.tenant_id}/oauth2/v2.0/token`;
  const body = new URLSearchParams({
    client_id: cfg.client_id,
    client_secret: cfg.client_secret,
    scope: 'https://graph.microsoft.com/.default',
    grant_type: 'client_credentials',
  });
  const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body, signal: AbortSignal.timeout(20000) });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`graph token ${res.status}: ${json.error_description || json.error || 'failed'}`);
  tokenCache.set(key, { token: json.access_token, expires: Date.now() + (json.expires_in || 3600) * 1000 });
  return json.access_token;
}

export function buildGraphPayload({ job, policy, templates, sender }) {
  const { row, subject, text, html } = renderJob({ job, policy, templates });
  const body = html || htmlFromText(text);
  const headers = [];
  const unsubMail = policy.unsubscribe_mailto
    ? `<mailto:${policy.unsubscribe_mailto}?subject=unsub-${encodeURIComponent(row.token || row.email)}>`
    : '';
  const unsubUrl = row.unsubscribe ? `<${row.unsubscribe}>` : '';
  const unsub = [unsubMail, unsubUrl].filter(Boolean).join(', ');
  if (unsub) headers.push({ name: 'List-Unsubscribe', value: unsub });
  if (policy.one_click_unsubscribe && unsub) headers.push({ name: 'List-Unsubscribe-Post', value: 'List-Unsubscribe=One-Click' });
  if (policy.headers?.['X-Entity-Ref-ID']) headers.push({ name: 'X-Entity-Ref-ID', value: randomHex(16) });
  if (policy.headers?.['Feedback-ID']) headers.push({ name: 'Feedback-ID', value: String(policy.headers['Feedback-ID']) });

  return {
    message: {
      subject,
      body: { contentType: 'HTML', content: body },
      toRecipients: [{ emailAddress: { address: job.email } }],
      from: { emailAddress: { address: sender, name: policy.from_name || undefined } },
      replyTo: policy.reply_to ? [{ emailAddress: { address: policy.reply_to } }] : undefined,
      internetMessageHeaders: headers.length ? headers : undefined,
    },
    saveToSentItems: false,
  };
}

export async function sendGraphJob({ job, policy, templates, cfg, timeout = 25000 }) {
  const sender = cfg.sender || policy.from_address;
  if (!sender) return { status: 'failed', reason: 'graph sender missing', path: 'graph' };
  const payload = buildGraphPayload({ job, policy, templates, sender });
  const base = cfg.base_url || process.env.GRAPH_BASE_URL || 'https://graph.microsoft.com';
  const url = `${base}/v1.0/users/${encodeURIComponent(sender)}/sendMail`;

  let token;
  try { token = await graphToken(cfg); }
  catch (err) { return { status: 'retry', reason: err.message, retrySeconds: 300, path: 'graph' }; }

  const started = Date.now();
  for (let attempt = 0; attempt < 2; attempt++) {
    const res = await fetch(url, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(timeout),
    });
    if (res.status === 202 || res.status === 200) {
      return { status: 'sent', path: 'graph', code: res.status, ms: Date.now() - started, messageId: null, sender };
    }
    const text = await res.text().catch(() => '');
    if (res.status === 401 && attempt === 0) {
      tokenCache.delete(`${cfg.tenant_id}:${cfg.client_id}`);
      token = await graphToken(cfg);
      continue;
    }
    if (res.status === 429) {
      const retry = Number(res.headers.get('retry-after')) || 60;
      return { status: 'retry', path: 'graph', code: 429, reason: 'throttled', retrySeconds: retry };
    }
    if (res.status >= 500) return { status: 'retry', path: 'graph', code: res.status, reason: text.slice(0, 200), retrySeconds: 120 };
    return { status: 'bounced', path: 'graph', code: res.status, reason: text.slice(0, 300) };
  }
  return { status: 'retry', path: 'graph', reason: 'graph retry exhausted', retrySeconds: 120 };
}
