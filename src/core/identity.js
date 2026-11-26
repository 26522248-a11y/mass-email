import { resolvePtr, resolveA, resolveMx, spfRecord, dmarcRecord, dkimRecord, dmarcParse } from '../lib/dns.js';
import { spamhausLookup, spamhausAdvice } from '../lib/spamhaus.js';
import { SmtpClient } from '../lib/smtp.js';

/**
 * Identity = (client IP, PTR/FCrDNS, domain auth). Receivers gate on it before
 * they read content. This module measures that identity, projects it onto the
 * receivers that matter, and lists what can replace it at zero cost.
 *
 * There is no "bypass": SBL/PBL are declarations by the IP owner. What works is
 * substituting a different identity (ESP, M365, Gmail) or obtaining a static IP
 * with PTR. This module makes that explicit instead of guessing.
 */
export const KEY_RECEIVERS = ['gmail.com', 'outlook.com', 'yahoo.com', 'icloud.com', 'zoho.com', 'yandex.ru', 'mail.ru', 'proton.me'];

export function scoreIdentity(facts) {
  const blockers = [];
  const fixes = [];
  let score = 100;

  if (!facts.ptr?.length) {
    score -= 25;
    blockers.push({ id: 'no-ptr', severity: 'high', detail: `${facts.ip} has no PTR` });
    fixes.push({ for: 'no-ptr', cost: '$0 only with a provider that sets rDNS', action: 'Move the send origin to a free-tier cloud IP where you control rDNS (Oracle Always Free), or send through an ESP/M365 so the provider IP carries the PTR.' });
  } else if (!facts.fcrdns) {
    score -= 20;
    blockers.push({ id: 'fcrdns', severity: 'high', detail: `PTR ${facts.ptr[0]} does not resolve back to ${facts.ip}` });
    fixes.push({ for: 'fcrdns', cost: '$0 with provider rDNS', action: 'Make A/AAAA of the PTR name point back to the IP (forward-confirmed rDNS).' });
  }

  const lists = facts.spamhaus?.lists || [];
  if (lists.some((l) => l.list.startsWith('SBL'))) {
    score -= 35;
    blockers.push({ id: 'spamhaus-sbl', severity: 'critical', detail: lists.filter((l) => l.list.startsWith('SBL')).map((l) => `${l.list}: ${l.meaning}`).join('; ') });
    fixes.push({ for: 'spamhaus-sbl', cost: '$0 but not self-service', action: 'SBL removal must be requested by the IP owner/ISP at https://check.spamhaus.org/; you cannot delist an IP you do not control.' });
  }
  if (lists.some((l) => l.list.startsWith('PBL'))) {
    score -= 25;
    blockers.push({ id: 'spamhaus-pbl', severity: 'high', detail: lists.filter((l) => l.list.startsWith('PBL')).map((l) => `${l.list}: ${l.meaning}`).join('; ') });
    fixes.push({ for: 'spamhaus-pbl', cost: '$0 but ISP-only', action: 'PBL CSS is the ISP declaring the range dynamic. Only the ISP can remove it (business static IP). Until then this IP will be refused by Outlook/iCloud/Yahoo.' });
  }

  if (!facts.spf) {
    score -= 15;
    blockers.push({ id: 'no-spf', severity: 'critical', detail: 'sender domain has no SPF' });
    fixes.push({ for: 'no-spf', cost: '$0 with a free subdomain', action: 'Publish v=spf1 include:<esp> -all on a domain you control (pp.ua / eu.org / is-a.dev are free) or let the ESP sign its shared domain.' });
  } else if (facts.spfAll && facts.spfAll !== '-all') {
    score -= 5;
    blockers.push({ id: 'spf-soft', severity: 'medium', detail: `SPF ends with ${facts.spfAll}` });
  }

  if (!facts.dkimBits) {
    score -= 15;
    blockers.push({ id: 'no-dkim', severity: 'critical', detail: 'no DKIM selector published' });
    fixes.push({ for: 'no-dkim', cost: '$0', action: 'Publish <selector>._domainkey TXT (node src/cli.js keys) or enable DKIM in the ESP dashboard.' });
  } else if (facts.dkimBits < 2048) {
    score -= 5;
    blockers.push({ id: 'dkim-weak', severity: 'medium', detail: `${facts.dkimBits}-bit key` });
  }

  if (!facts.dmarc) {
    score -= 10;
    blockers.push({ id: 'no-dmarc', severity: 'high', detail: 'no DMARC record' });
    fixes.push({ for: 'no-dmarc', cost: '$0', action: 'Publish v=DMARC1; p=quarantine; rua=mailto:dmarc@domain.' });
  } else if (facts.dmarcPolicy === 'none') {
    score -= 5;
    blockers.push({ id: 'dmarc-none', severity: 'low', detail: 'p=none (monitor only)' });
  }

  score = Math.max(0, Math.min(100, score));
  const grade = score >= 85 ? 'A' : score >= 70 ? 'B' : score >= 50 ? 'C' : 'F';
  return { score, grade, blockers, fixes };
}

export async function probeReceiver(domain, { from, helo, timeout = 9000 }) {
  const mx = await resolveMx(domain).catch(() => []);
  if (!mx.length) return { domain, verdict: 'no-mx' };
  const host = mx.sort((a, b) => a.priority - b.priority)[0].exchange;
  const c = new SmtpClient({ host, port: 25, timeout });
  const out = { domain, mx: host };
  try {
    await c.connect();
    await c.greet(helo);
    const mf = await c.mailFrom(from);
    out.mailFrom = { code: mf.code, reply: mf.text.replace(/\s+/g, ' ').slice(0, 140) };
    if (mf.code === 250 || mf.code === 251) {
      const rc = await c.rcptTo(`postmaster@${domain}`);
      out.rcpt = { code: rc.code, reply: rc.text.replace(/\s+/g, ' ').slice(0, 140) };
      out.verdict = rc.code === 250 ? 'accepted' : /spamhaus|blacklist|rbl|blocked/i.test(rc.text) ? 'ip-blocked' : 'rcpt-rejected';
    } else {
      out.verdict = /spamhaus|blacklist|rbl|blocked using/i.test(mf.text) ? 'ip-blocked'
        : /fcrdns|reverse|ptr/i.test(mf.text) ? 'ip-blocked'
          : /spf/i.test(mf.text) ? 'sender-auth'
            : 'mail-from-rejected';
    }
  } catch (err) {
    out.verdict = 'connection-failed';
    out.error = err.code || err.message;
  } finally {
    try { await c.quit(); } catch { /* ignore */ }
  }
  return out;
}

export async function checkIdentity({ ip, domain, helo, from, receivers = KEY_RECEIVERS, probe = true, timeout = 9000 }) {
  const [ptr, sh] = await Promise.all([resolvePtr(ip), spamhausLookup(ip)]);
  const fcrdns = ptr.length ? (await resolveA(ptr[0])).includes(ip) : false;
  const spf = domain ? await spfRecord(domain).catch(() => null) : null;
  const spfAll = spf ? (/([~+\-?]all)\b/i.exec(spf)?.[1] || null) : null;
  let dkimBits = 0;
  if (domain) {
    for (const sel of ['s1', 'default', 'mail', 'dkim']) {
      const rec = await dkimRecord(sel, domain).catch(() => null);
      if (rec && /p=[A-Za-z0-9+/=]{40,}/.test(rec)) { dkimBits = 2048; break; }
    }
  }
  const dmarc = domain ? await dmarcRecord(domain).catch(() => null) : null;
  const dmarcPolicy = dmarc ? dmarcParse(dmarc).p : null;

  const facts = { ip, ptr, fcrdns, spamhaus: sh, domain, spf, spfAll, dkimBits, dmarc, dmarcPolicy };
  const scored = scoreIdentity(facts);

  const projected = [];
  if (probe) {
    const queue = [...receivers];
    const workers = Array.from({ length: Math.min(5, queue.length) }, async () => {
      while (queue.length) {
        const r = queue.shift();
        projected.push(await probeReceiver(r, { from: from || `postmaster@${domain || 'probe.local'}`, helo: helo || domain || ip, timeout }));
      }
    });
    await Promise.all(workers);
    projected.sort((a, b) => receivers.indexOf(a.domain) - receivers.indexOf(b.domain));
  }

  return {
    checkedAt: new Date().toISOString(),
    facts,
    ...scored,
    advice: sh.listed ? spamhausAdvice(sh) : [],
    projected,
    accepted: projected.filter((p) => p.verdict === 'accepted').map((p) => p.domain),
    blocked: projected.filter((p) => p.verdict === 'ip-blocked').map((p) => p.domain),
  };
}

/**
 * Zero/near-zero cost identities, ordered by inbox outcome. Volume is per
 * mailbox/account; stacking accounts multiplies it.
 */
export function identityLadder() {
  return [
    {
      rank: 1, id: 'm365-dev-graph', name: 'M365 Developer tenant + Graph', cost: '$0 (dev tenant, 90d renewable)',
      volume: '10,000 recipients/day/mailbox', inbox: 'A', setup: '10 min',
      identity: 'Microsoft IP + *.onmicrosoft.com with Microsoft-managed SPF/DKIM/DMARC',
      steps: ['developer.microsoft.com/microsoft-365/dev-program', 'Entra -> App registration (public client)', 'delegated Mail.Send', 'node src/cli.js graphdevice --client-id <id>'],
    },
    {
      rank: 2, id: 'gmail-consumer', name: 'Gmail consumer app password', cost: '$0',
      volume: '~500 recipients/day/account', inbox: 'A (Gmail->Gmail)', setup: '5 min',
      identity: 'Google IP + gmail.com DKIM',
      steps: ['2FA on account', 'app password', 'config/relays.json -> smtp.gmail.com:587'],
    },
    {
      rank: 3, id: 'free-domain-esp', name: 'Free subdomain + free ESP DKIM', cost: '$0',
      volume: '300-2,400/day', inbox: 'B+', setup: '1h (domain approval may take days)',
      identity: 'shared ESP IP + your aligned DKIM/SPF/DMARC',
      steps: ['pp.ua / eu.org / is-a.dev / afraid.org', 'add domain to Brevo/SendGrid/Mailjet', 'publish SPF+DKIM+DMARC', 'node src/cli.js dnscheck --domain <d>'],
    },
    {
      rank: 4, id: 'free-esp', name: 'Free ESP without a domain', cost: '$0',
      volume: '1,233-2,400/day', inbox: 'B', setup: '15 min',
      identity: 'shared ESP IP, verified sender, no aligned DKIM',
      steps: ['signup 2 accounts per provider', 'verify sender', 'config/esp.json', 'node src/cli.js espprobe && espsend'],
    },
    {
      rank: 5, id: 'cloud-static-ip', name: 'Free-tier cloud VM with rDNS + port 25', cost: '$0 (Oracle Always Free)',
      volume: 'own IP, warmup 2-6 weeks', inbox: 'B after warmup', setup: '1-3 days',
      identity: 'your own static IP with PTR, full SPF/DKIM/DMARC',
      steps: ['Oracle Cloud Always Free VM', 'reserve public IPv4 + set rDNS', 'request port 25 unblock', 'publish A/PTR/SPF/DKIM/DMARC', 'warmup'],
    },
    {
      rank: 6, id: 'direct-current-ip', name: 'Current dynamic IP (no identity)', cost: '$0',
      volume: 'unlimited', inbox: 'F (spam folder / refused)', setup: 'none',
      identity: 'none: no PTR, PBL CSS, SBL CSS',
      steps: ['only 7/16 receivers accept; Outlook/Yahoo/iCloud refuse at MAIL FROM'],
    },
  ];
}

export function inventory({ relays = [], esp = [], graph = null, device = null, directReady = false } = {}) {
  const rows = [];
  rows.push({ id: 'direct', kind: 'direct-to-MX', ready: directReady, note: directReady ? 'receiver accepts this IP' : 'egress IP blocked for some receivers' });
  for (const r of relays) rows.push({ id: r.id, kind: `smtp:${r.host}`, ready: looksReal(r.user) && looksReal(r.pass || r.access_token), note: r.from || '' });
  for (const a of esp) rows.push({ id: a.id, kind: `esp:${a.provider}`, ready: looksReal(a.api_key), note: a.from || '' });
  if (graph) rows.push({ id: 'graph-app', kind: 'graph:client-credentials', ready: looksReal(graph.tenant_id) && looksReal(graph.client_id) && looksReal(graph.client_secret), note: graph.sender || '' });
  if (device) rows.push({ id: 'graph-device', kind: 'graph:device-code', ready: Boolean(device.refresh_token && device.expires_at > Date.now()), note: '' });
  return rows;
}

/**
 * Placeholder-aware credential check, so an example config does not look like
 * a ready identity in `identity` output or smart routing.
 */
export function isRealSecret(v) {
  if (!v || typeof v !== 'string' || v.length < 6) return false;
  if (/\.\.\./.test(v)) return false;
  return !/replace|changeme|your[_-]|example\.com|xxxx|placeholder|password|^<.*>$/i.test(v);
}

function looksReal(v) { return isRealSecret(v); }

/**
 * Pick the identity that the receiver will actually accept. Raises the alarm
 * instead of sending direct into a blocked receiver when nothing else exists.
 */
export function choosePath({ verdict, grade, hasEsp = false, hasGraph = false, hasRelay = false, allowDirect = true }) {
  const directOk = allowDirect && grade !== 'F' && verdict === 'accepted';
  if (directOk) return 'direct';
  if (hasEsp) return 'esp';
  if (hasGraph) return 'graph';
  if (hasRelay) return 'relay';
  if (allowDirect && verdict === 'accepted') return 'direct';
  return 'none';
}
