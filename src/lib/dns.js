import dns from 'node:dns/promises';

/**
 * DNS over HTTPS resolver with cache. DoH is used instead of UDP 53 because
 * many VPS/hosting networks block or poison outbound port 53.
 */
const ENDPOINTS = [
  'https://cloudflare-dns.com/dns-query',
  'https://dns.google/resolve',
];

const cache = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000;

async function doh(name, type) {
  const key = `${type}:${name}`;
  const hit = cache.get(key);
  if (hit && hit.expires > Date.now()) return hit.data;

  let lastErr;
  for (const base of ENDPOINTS) {
    try {
      const url = new URL(base);
      url.searchParams.set('name', name);
      url.searchParams.set('type', type);
      const res = await fetch(url, {
        headers: { accept: 'application/dns-json' },
        signal: AbortSignal.timeout(8000),
      });
      if (!res.ok) throw new Error(`DoH ${res.status}`);
      const data = await res.json();
      cache.set(key, { data, expires: Date.now() + CACHE_TTL_MS });
      return data;
    } catch (err) { lastErr = err; }
  }
  throw lastErr;
}

function answers(data, type) {
  return (data.Answer || []).filter((a) => !type || a.type === type).map((a) => a.data);
}

export async function resolveMx(domain) {
  try {
    const data = await doh(domain, 'MX');
    const rows = (data.Answer || [])
      .filter((a) => a.type === 15)
      .map((a) => {
        const [prio, host] = String(a.data).trim().split(/\s+/);
        return { priority: Number(prio), exchange: host.replace(/\.$/, '') };
      })
      .filter((m) => m.exchange && m.exchange !== '.')
      .sort((a, b) => a.priority - b.priority);
    if (rows.length) return rows;
  } catch { /* fall through to system resolver */ }
  try {
    const rows = await dns.resolveMx(domain);
    return rows
      .map((r) => ({ priority: r.priority, exchange: String(r.exchange || '').replace(/\.$/, '') }))
      .filter((r) => r.exchange && r.exchange !== '.')
      .sort((a, b) => a.priority - b.priority);
  } catch {
    return [];
  }
}

export async function resolveTxt(name) {
  try {
    const data = await doh(name, 'TXT');
    return (data.Answer || []).filter((a) => a.type === 16).map((a) => String(a.data).replace(/^"|"$/g, '').replace(/" "/g, ''));
  } catch {
    try { return (await dns.resolveTxt(name)).map((chunks) => chunks.join('')); } catch { return []; }
  }
}

export async function resolveCname(name) {
  try {
    const data = await doh(name, 'CNAME');
    return (data.Answer || []).filter((a) => a.type === 5).map((a) => String(a.data).replace(/\.$/, ''));
  } catch { return []; }
}

export async function resolvePtr(ip) {
  const rev = ip.split('.').reverse().join('.') + '.in-addr.arpa';
  try {
    const data = await doh(rev, 'PTR');
    return (data.Answer || []).filter((a) => a.type === 12).map((a) => String(a.data).replace(/\.$/, ''));
  } catch { return []; }
}

export async function resolveA(name) {
  try {
    const data = await doh(name, 'A');
    return (data.Answer || []).filter((a) => a.type === 1).map((a) => a.data);
  } catch { return []; }
}

export async function dnssecAd(name, type = 'A') {
  try {
    const data = await doh(name, type);
    return Boolean(data.AD);
  } catch { return false; }
}

export async function dmarcRecord(domain) {
  const rows = await resolveTxt(`_dmarc.${domain}`);
  return rows.find((r) => /^v=DMARC1\b/i.test(r)) || null;
}

export async function spfRecord(domain) {
  const rows = await resolveTxt(domain);
  return rows.find((r) => /^v=spf1\b/i.test(r)) || null;
}

export async function dkimRecord(selector, domain) {
  const rows = await resolveTxt(`${selector}._domainkey.${domain}`);
  return rows.find((r) => /v=DKIM1/i.test(r)) || null;
}

export function parseSpf(record) {
  if (!record) return { all: null, includes: [], lookups: [], mechanisms: [] };
  const parts = record.split(/\s+/).slice(1);
  const includes = parts.filter((p) => p.startsWith('include:')).map((p) => p.slice(8));
  const lookups = parts.filter((p) => /^(include:|a$|a:|mx$|mx:|ptr|exists:|redirect=)/.test(p));
  return {
    all: parts.find((p) => /^[+~-]?all$/.test(p)) || null,
    includes,
    lookups,
    mechanisms: parts,
  };
}

export function dmarcParse(record) {
  const out = { raw: record, p: null, sp: null, pct: 100, rua: [], adkim: 'r', aspf: 'r' };
  if (!record) return out;
  for (const part of record.split(';').map((s) => s.trim()).filter(Boolean)) {
    const [k, v = ''] = part.split('=');
    const key = k.trim().toLowerCase();
    if (key === 'p') out.p = v.trim().toLowerCase();
    else if (key === 'sp') out.sp = v.trim().toLowerCase();
    else if (key === 'pct') out.pct = Number(v) || 100;
    else if (key === 'rua') out.rua = v.split(',').map((s) => s.trim());
    else if (key === 'adkim') out.adkim = v.trim().toLowerCase();
    else if (key === 'aspf') out.aspf = v.trim().toLowerCase();
  }
  return out;
}
