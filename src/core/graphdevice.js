import fs from 'node:fs';
import path from 'node:path';
import { buildGraphPayload } from './graph.js';

/**
 * Microsoft Graph without an app secret: OAuth 2.0 device code flow against a
 * public client app registration, then POST /me/sendMail.
 *
 * Why this matters for a zero-budget setup: an M365 Developer tenant is free,
 * its default *.onmicrosoft.com domain already has SPF/DKIM/DMARC managed by
 * Microsoft, and messages leave from Microsoft IPs. No domain purchase, no
 * SMTP port, no local IP reputation involved.
 *
 * You still need one free app registration (Entra ID -> App registrations ->
 * public client, delegated Mail.Send). No admin consent is required for a
 * delegated Mail.Send on your own mailbox.
 */
const DEFAULT_SCOPE = 'https://graph.microsoft.com/Mail.Send offline_access openid profile';

export async function deviceCodeStart({ clientId, tenant = 'common', scope = DEFAULT_SCOPE, timeout = 20000 }) {
  const url = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/devicecode`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: clientId, scope }),
    signal: AbortSignal.timeout(timeout),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`devicecode ${res.status}: ${json.error_description || json.error || 'failed'}`);
  return json;
}

export async function deviceCodePoll({ clientId, tenant = 'common', deviceCode, interval = 5, expiresIn = 900, timeout = 20000 }) {
  const url = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`;
  const deadline = Date.now() + expiresIn * 1000;
  let wait = interval;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, wait * 1000));
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        client_id: clientId,
        device_code: deviceCode,
      }),
      signal: AbortSignal.timeout(timeout),
    });
    const json = await res.json().catch(() => ({}));
    if (res.ok && json.access_token) return json;
    if (json.error === 'authorization_pending') continue;
    if (json.error === 'slow_down') { wait += 5; continue; }
    if (json.error === 'expired_token') throw new Error('device code expired; run again');
    if (json.error === 'authorization_declined') throw new Error('sign-in declined');
    throw new Error(`token ${res.status}: ${json.error_description || json.error || 'failed'}`);
  }
  throw new Error('device code expired before approval');
}

export function saveToken(file, token, extra = {}) {
  const expiresAt = Date.now() + (Number(token.expires_in) || 3600) * 1000;
  const value = { ...extra, access_token: token.access_token, refresh_token: token.refresh_token || extra.refresh_token || null, expires_at: expiresAt };
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n');
  return value;
}

export function loadToken(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}

export async function refreshToken({ clientId, tenant = 'common', refresh, scope = DEFAULT_SCOPE, timeout = 20000 }) {
  if (!refresh) throw new Error('no refresh_token; run graphdevice again');
  const url = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'refresh_token', client_id: clientId, refresh_token: refresh, scope }),
    signal: AbortSignal.timeout(timeout),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok || !json.access_token) throw new Error(`refresh ${res.status}: ${json.error_description || json.error || 'failed'}`);
  return json;
}

export async function graphMe(token, { base = 'https://graph.microsoft.com', timeout = 20000 } = {}) {
  const res = await fetch(`${base}/v1.0/me?$select=mail,userPrincipalName`, {
    headers: { authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(timeout),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`me ${res.status}: ${json.error?.message || 'failed'}`);
  return json.mail || json.userPrincipalName;
}

export async function sendGraphMeJob({ job, policy, templates, token, sender, base = 'https://graph.microsoft.com', timeout = 25000 }) {
  const payload = buildGraphPayload({ job, policy, templates, sender });
  const res = await fetch(`${base}/v1.0/me/sendMail`, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(timeout),
  });
  if (res.status === 202 || res.status === 200) return { status: 'sent', path: 'graph-device', code: res.status, sender };
  const text = await res.text().catch(() => '');
  if (res.status === 429) return { status: 'retry', path: 'graph-device', code: 429, reason: 'throttled', retrySeconds: Number(res.headers.get('retry-after')) || 60 };
  if (res.status === 401) return { status: 'retry', path: 'graph-device', code: 401, reason: 'token expired', retrySeconds: 1 };
  if (res.status >= 500) return { status: 'retry', path: 'graph-device', code: res.status, reason: text.slice(0, 200), retrySeconds: 90 };
  return { status: 'bounced', path: 'graph-device', code: res.status, reason: text.slice(0, 300) };
}
