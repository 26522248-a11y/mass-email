import os from 'node:os';
import { resolvePtr, resolveA, resolveMx } from '../lib/dns.js';
import { spamhausLookup, spamhausAdvice } from '../lib/spamhaus.js';
import { SmtpClient } from '../lib/smtp.js';
import { randomLocal } from '../lib/util.js';

export async function egressInfo() {  for (const url of ['https://ifconfig.co/json', 'https://ipinfo.io/json']) {
    try {
      const r = await fetch(url, { headers: { accept: 'application/json', 'user-agent': 'mass-email/1.0' }, signal: AbortSignal.timeout(10000) });
      if (!r.ok) continue;
      const j = await r.json();
      if (j.ip) return { ip: j.ip, country: j.country, org: j.org || j.asn_org || '', city: j.city || '', asn: j.asn || '' };
    } catch { /* next */ }
  }
  return null;
}

function globalIpv6() {
  const out = [];
  for (const list of Object.values(os.networkInterfaces())) {
    for (const a of list || []) {
      if (a.family === 'IPv6' && !a.internal && !a.address.startsWith('fe80')) out.push(a.address);
    }
  }
  return out;
}

async function port25(host, timeout) {
  const c = new SmtpClient({ host, port: 25, timeout, log: () => {} });
  try {
    await c.connect();
    const banner = await c.readReply();
    c.destroy();
    return { reachable: true, banner: banner.text };
  } catch (err) {
    c.destroy();
    return { reachable: false, error: err.code || err.message };
  }
}

async function targetTest(domain, policy, timeout) {
  const mx = await resolveMx(domain);
  if (!mx.length) return { domain, mx: [], accepted: false, error: 'no MX' };
  const host = mx[0].exchange;
  const c = new SmtpClient({ host, port: 25, timeout, log: () => {} });
  const out = { domain, mx: host, helo: policy.helo_host || policy.from_domain, mailFrom: policy.from_address, checks: {} };
  try {
    await c.connect();
    const g = await c.greet(policy.helo_host || policy.from_domain);
    out.banner = g.banner.text;
    if (c.supports('STARTTLS')) { try { await c.starttls(policy.helo_host || policy.from_domain); } catch (e) { out.checks.tls = e.message; } }
    out.tls = Boolean(c.socket?.encrypted);
    const mf = await c.mailFrom(policy.from_address || policy.from_domain);
    out.checks.mail = { code: mf.code, reply: mf.text };
    if (mf.code < 400) {
      const rc = await c.rcptTo(`${randomLocal(14)}@${domain}`);
      out.checks.rcptRandom = { code: rc.code, reply: rc.text };
    }
    await c.quit();
  } catch (err) {
    out.error = err.message;
    out.checks.closed = true;
    c.destroy();
  }
  out.accepted = out.checks.mail?.code === 250;
  return out;
}

export async function diagnoseEgress({ policy, timeout = 12000 } = {}) {
  const report = { checkedAt: new Date().toISOString(), targets: {}, blockers: [], score: 100 };
  const info = await egressInfo();
  if (!info) throw new Error('cannot determine egress IP (network blocked?)');
  report.ip = info;
  const ip = info.ip;

  const [ptr, sh] = await Promise.all([resolvePtr(ip), spamhausLookup(ip)]);
  const fcrdns = ptr.length ? (await resolveA(ptr[0])).includes(ip) : false;
  report.ptr = { names: ptr, fcrdns };
  report.spamhaus = sh;
  report.ipv6 = globalIpv6();
  report.port25 = {
    gmail: await port25('gmail-smtp-in.l.google.com', timeout),
    outlook: await port25('outlook-com.olc.protection.outlook.com', timeout),
  };

  for (const t of ['gmail.com', 'outlook.com', 'yahoo.com', 'proton.me']) {
    report.targets[t] = await targetTest(t, policy, timeout);
  }

  if (!ptr.length) { report.blockers.push({ id: 'no-ptr', severity: 'high', detail: `${ip} has no PTR; Yahoo and many filters reject or downrank.` }); report.score -= 20; }
  else if (!fcrdns) { report.blockers.push({ id: 'fcrdns', severity: 'high', detail: `PTR ${ptr[0]} does not resolve back to ${ip}.` }); report.score -= 20; }
  if (sh.listed) {
    for (const l of sh.lists) report.blockers.push({ id: `spamhaus-${l.list}`, severity: l.list.startsWith('PBL') ? 'high' : 'critical', detail: `${l.list}: ${l.meaning}` });
    report.score -= sh.lists.some((l) => l.list.startsWith('SBL')) ? 35 : 20;
    report.advice = spamhausAdvice(sh);
  } else if (sh.listed === null) {
    report.blockers.push({ id: 'spamhaus-unknown', severity: 'info', detail: `Spamhaus check inconclusive: ${sh.reason}` });
  }
  if (!report.ipv6.length) report.blockers.push({ id: 'no-ipv6', severity: 'low', detail: 'No global IPv6; cannot use a separate IPv6 reputation path.' });

  for (const [domain, t] of Object.entries(report.targets)) {
    const mail = t.checks.mail?.code;
    if (mail === 250) {
      report.targets[domain].verdict = 'protocol-ok';
      if (sh.listed) report.targets[domain].verdict = 'protocol-ok/reputation-bad';
    } else if (mail >= 500) {
      report.targets[domain].verdict = 'blocked-at-mail-from';
      report.blockers.push({ id: `direct-${domain.split('.')[0]}`, severity: 'high', detail: `${domain}: MAIL FROM ${mail} — ${String(t.checks.mail.reply).slice(0, 160)}` });
    } else {
      report.targets[domain].verdict = t.error ? `error:${t.error}` : 'unknown';
    }
  }

  const blocked = Object.values(report.targets).filter((t) => t.verdict === 'blocked-at-mail-from').map((t) => t.domain);
  report.route = {
    directGmail: report.targets['gmail.com']?.verdict || 'unknown',
    directOutlook: report.targets['outlook.com']?.verdict || 'unknown',
    directYahoo: report.targets['yahoo.com']?.verdict || 'unknown',
    blocked,
    recommended: blocked.length
      ? 'Use an authenticated ESP/smarthost for blocked receivers; fix PTR + delist + DKIM/DMARC only for the direct stream.'
      : 'Direct delivery may work at protocol level, but reputation and content still decide inbox placement.',
  };
  report.score = Math.max(0, report.score);
  report.grade = report.score >= 80 ? 'A' : report.score >= 60 ? 'B' : report.score >= 40 ? 'C' : 'F';
  return report;
}

export function diagnoseSummary(r) {
  return {
    ip: r.ip?.ip, org: r.ip?.org, ptr: r.ptr?.names?.[0] || '(none)', fcrdns: r.ptr?.fcrdns,
    spamhaus: r.spamhaus?.lists?.map((l) => l.list).join('+') || (r.spamhaus?.listed === false ? 'clean' : 'unknown'),
    ipv6: r.ipv6?.length || 0, score: r.score, grade: r.grade,
    gmail: r.targets?.['gmail.com']?.verdict,
    outlook: r.targets?.['outlook.com']?.verdict,
    yahoo: r.targets?.['yahoo.com']?.verdict,
  };
}
