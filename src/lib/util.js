import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..', '..');

export function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

export function readJson(file, fallback = null) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}

export function writeJson(file, value) {
  ensureDir(path.dirname(file));
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2) + '\n');
  fs.renameSync(tmp, file);
}

export function appendJsonl(file, value) {
  ensureDir(path.dirname(file));
  fs.appendFileSync(file, JSON.stringify(value) + '\n');
}

export function readJsonl(file, limit = Infinity) {
  let raw = '';
  try { raw = fs.readFileSync(file, 'utf8'); } catch { return []; }
  const out = [];
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue;
    try { out.push(JSON.parse(line)); } catch { /* skip torn line */ }
    if (out.length >= limit) break;
  }
  return out;
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function randInt(min, max) {
  return crypto.randomInt(min, max + 1);
}

export function randomHex(bytes = 8) {
  return crypto.randomBytes(bytes).toString('hex');
}

export function randomLocal(len = 12) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let s = '';
  const bytes = crypto.randomBytes(len);
  for (let i = 0; i < len; i++) s += alphabet[bytes[i] % alphabet.length];
  return s;
}

export function normalizeEmail(email) {
  return String(email || '').trim().replace(/^<|>$/g, '').toLowerCase();
}

export function isValidEmail(email) {
  return /^[a-z0-9!#$%&'*+/=?^_`{|}~.-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(email);
}

export function parseCsv(text) {
  const lines = text.split(/\r?\n/).filter((l) => l.trim() && !l.startsWith('#'));
  if (!lines.length) return [];
  const delim = lines[0].includes(';') ? ';' : ',';
  const split = (line) => {
    const out = [];
    let cur = '';
    let quoted = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        if (quoted && line[i + 1] === '"') { cur += '"'; i++; } else quoted = !quoted;
      } else if (ch === delim && !quoted) { out.push(cur); cur = ''; } else cur += ch;
    }
    out.push(cur);
    return out.map((s) => s.trim());
  };
  const header = split(lines[0]).map((h) => h.toLowerCase());
  const emailIdx = header.indexOf('email');
  return lines.slice(1).map((line) => {
    const cells = split(line);
    const row = {};
    header.forEach((h, i) => { row[h] = cells[i] ?? ''; });
    if (emailIdx >= 0) row.email = cells[emailIdx];
    return row;
  }).filter((r) => isValidEmail(normalizeEmail(r.email)));
}

export function expandPath(p) {
  return path.isAbsolute(p) ? p : path.join(ROOT, p);
}

export function makeLogger(file) {
  ensureDir(path.dirname(file));
  const stream = fs.createWriteStream(file, { flags: 'a' });
  const emit = (level, msg, extra) => {
    const line = `[${new Date().toISOString()}] ${level.toUpperCase()} ${msg}${extra ? ' ' + JSON.stringify(extra) : ''}`;
    stream.write(line + '\n');
    if (process.env.VERBOSE) console.log(line);
  };
  return {
    info: (m, e) => emit('info', m, e),
    warn: (m, e) => emit('warn', m, e),
    error: (m, e) => emit('error', m, e),
    close: () => stream.end(),
  };
}

export function clamp(n, min, max) { return Math.min(max, Math.max(min, n)); }

export function tokenizeUrl(template, row) {
  return template
    .replaceAll('{{token}}', encodeURIComponent(row.token || row.email))
    .replaceAll('{{email}}', encodeURIComponent(row.email))
    .replaceAll('{token}', encodeURIComponent(row.token || row.email))
    .replaceAll('{email}', encodeURIComponent(row.email));
}

export function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
