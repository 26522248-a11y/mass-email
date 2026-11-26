import crypto from 'node:crypto';
import { escapeHtml, randomHex } from './util.js';

/** Deterministic RNG so one recipient renders the same variants in text and HTML. */
export function rngFor(seed) {
  let state = crypto.createHash('sha256').update(String(seed)).digest().readUInt32LE(0) || 1;
  return () => {
    state ^= state << 13; state >>>= 0;
    state ^= state >> 17;
    state ^= state << 5; state >>>= 0;
    return state / 0xffffffff;
  };
}

export function expandSpintax(input, rng) {
  let out = String(input);
  // innermost first, supports nesting
  for (let guard = 0; guard < 20 && /\{[^{}]*\|[^{}]*\}/.test(out); guard++) {
    out = out.replace(/\{([^{}]*)\}/g, (whole, group) => {
      const options = group.split('|');
      if (options.length === 1) return whole;
      return options[Math.floor(rng() * options.length)];
    });
  }
  return out;
}

export function render(template, row, rng) {
  const ctx = {
    name: row.name || row.email.split('@')[0],
    email: row.email,
    domain: row.email.split('@')[1] || '',
    token: row.token || row.email,
    brand: row.brand || 'Your Brand',
    greeting: 'Hi',
    url: row.url || 'https://example.com',
    unsubscribe: row.unsubscribe || 'https://example.com/u/' + encodeURIComponent(row.token || row.email),
    subject: row.subject || '',
    ...row,
  };
  const replaced = String(template).replace(/\{\{(\w+)\}\}/g, (whole, key) => (ctx[key] ?? whole));
  return expandSpintax(replaced, rng);
}

export function qpEncode(text) {
  const bytes = Buffer.from(text, 'utf8');
  let out = '';
  let lineLen = 0;
  for (const byte of bytes) {
    let piece;
    if (byte === 0x0a) { out += '\r\n'; lineLen = 0; continue; }
    if (byte === 0x0d) continue;
    if (byte === 0x3d || byte > 126 || (byte < 32 && byte !== 9)) {
      piece = '=' + byte.toString(16).toUpperCase().padStart(2, '0');
    } else if (byte === 0x20) {
      piece = ' ';
    } else {
      piece = String.fromCharCode(byte);
    }
    if (lineLen + piece.length > 74) { out += '=\r\n'; lineLen = 0; }
    if (piece === ' ' && lineLen + 1 > 74) { out += '=\r\n'; lineLen = 0; }
    out += piece;
    lineLen += piece.length;
  }
  return out;
}

export function base64Wrap(text) {
  return Buffer.from(text, 'utf8').toString('base64').replace(/.{1,76}/g, '$&\r\n').trimEnd();
}

export function encodeHeader(value) {
  const s = String(value).replace(/[\r\n]+/g, ' ').trim();
  if (/^[\x20-\x7e]*$/.test(s)) return s;
  return `=?UTF-8?B?${Buffer.from(s, 'utf8').toString('base64')}?=`;
}

export function foldHeader(name, value, limit = 78) {
  const full = `${name}: ${value}`;
  if (full.length <= limit) return full;
  const words = full.split(' ');
  const lines = [];
  let cur = '';
  for (const w of words) {
    if (cur && (cur + ' ' + w).length > limit) {
      lines.push(cur);
      cur = ' ' + w;
    } else cur = cur ? cur + ' ' + w : w;
  }
  if (cur) lines.push(cur);
  return lines.join('\r\n');
}

export function rfc2822Date(d = new Date()) {
  return d.toUTCString().replace(/GMT$/, '+0000');
}

/**
 * Build a complete RFC 5322 message. `policy` controls optional flags.
 * Returns { raw, headers, body, messageId }.
 */
export function buildMessage({ row, subject, text, html, policy, fromName, from, replyTo, unsubscribeMailto, token, domain, extraHeaders = [] }) {
  const headers = [];
  const add = (name, value) => headers.push([name, value]);

  add('From', `${encodeHeader(fromName)} <${from}>`);
  add('To', row.email);
  add('Subject', encodeHeader(subject));
  add('Date', rfc2822Date());
  const messageId = `<${Date.now().toString(36)}.${randomHex(10)}@${domain}>`;
  add('Message-ID', messageId);
  add('MIME-Version', '1.0');
  for (const [name, value] of extraHeaders) add(name, value);

  if (replyTo) add('Reply-To', replyTo);

  const unsubMail = unsubscribeMailto
    ? `<mailto:${unsubscribeMailto}?subject=unsub-${encodeURIComponent(token)}>`
    : '';
  const unsubUrl = row.unsubscribe ? `<${row.unsubscribe}>` : '';
  if (unsubMail || unsubUrl) add('List-Unsubscribe', [unsubMail, unsubUrl].filter(Boolean).join(', '));
  if (policy.one_click_unsubscribe) add('List-Unsubscribe-Post', 'List-Unsubscribe=One-Click');

  if (policy.headers?.['X-Entity-Ref-ID']) add('X-Entity-Ref-ID', randomHex(16));
  if (policy.headers?.['Feedback-ID']) add('Feedback-ID', policy.headers['Feedback-ID']);
  if (policy.headers?.Precedence) add('Precedence', policy.headers.Precedence);
  if (policy.headers?.['Auto-Submitted']) add('Auto-Submitted', policy.headers['Auto-Submitted']);

  const hasHtml = Boolean(html);
  let body;
  if (hasHtml) {
    const boundary = `----=_Part_${randomHex(12)}`;
    add('Content-Type', `multipart/alternative; boundary="${boundary}"`);
    body = [
      `--${boundary}`,
      'Content-Type: text/plain; charset="UTF-8"',
      'Content-Transfer-Encoding: quoted-printable',
      '',
      qpEncode(text),
      `--${boundary}`,
      'Content-Type: text/html; charset="UTF-8"',
      'Content-Transfer-Encoding: base64',
      '',
      base64Wrap(html),
      `--${boundary}--`,
      '',
    ].join('\r\n');
  } else {
    add('Content-Type', 'text/plain; charset="UTF-8"');
    add('Content-Transfer-Encoding', 'quoted-printable');
    body = qpEncode(text) + '\r\n';
  }

  const raw = headers.map(([n, v]) => foldHeader(n, v)).join('\r\n') + '\r\n\r\n' + body;
  return { raw, headers, body, messageId };
}

export function htmlFromText(text) {
  const paragraphs = text.split(/\r?\n\r?\n/).map((p) => `<p style="margin:0 0 16px">${escapeHtml(p).replace(/\r?\n/g, '<br>')}</p>`);
  return `<!doctype html><html><body style="font:16px/1.5 -apple-system,Segoe UI,Arial,sans-serif;color:#111;max-width:600px;margin:auto;padding:16px">${paragraphs.join('\n')}</body></html>`;
}
