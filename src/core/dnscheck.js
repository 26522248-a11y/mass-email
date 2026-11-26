import { resolveMx, resolveTxt, resolveA, resolvePtr, dmarcRecord, spfRecord, dkimRecord, dnssecAd, parseSpf, dmarcParse } from '../lib/dns.js';
import { spamhausLookup, spamhausAdvice } from '../lib/spamhaus.js';
import { writeJson } from '../lib/util.js';

const MAX_LOOKUPS = 10;

/** Recursively count SPF DNS lookups and void lookups. */
async function analyzeSpf(record, domain, seen = new Set(), depth = 0) {
  const result = { lookups: 0, voidLookups: 0, includes: [], redirects: [], errors: [] };
  if (!record || depth > 6) return result;
  if (seen.has(domain)) { result.errors.push(`include loop at ${domain}`); return result; }
  seen.add(domain);
  const parsed = parseSpf(record);
  result.lookups += parsed.lookups.length;
  result.includes.push(...parsed.includes);
  for (const inc of parsed.includes) {
    if (result.lookups > MAX_LOOKUPS + 5) break;
    const sub = (await resolveTxt(inc)).find((r) => /^v=spf1\b/i.test(r));
    if (!sub) { result.errors.push(`include ${inc} has no SPF record (void lookup)`); result.voidLookups += 1; continue; }
    const nested = await analyzeSpf(sub, inc, seen, depth + 1);
    for (const k of ['lookups', 'voidLookups']) result[k] += nested[k];
    result.includes.push(...nested.includes);
    result.errors.push(...nested.errors);
  }
  const redirect = parsed.mechanisms.find((m) => m.startsWith('redirect='))?.slice(9);
  if (redirect) {
    result.redirects.push(redirect);
    const sub = (await resolveTxt(redirect)).find((r) => /^v=spf1\b/i.test(r));
    if (!sub) result.errors.push(`redirect ${redirect} missing (void)`);
    else {
      const nested = await analyzeSpf(sub, redirect, seen, depth + 1);
      for (const k of ['lookups', 'voidLookups']) result[k] += nested[k];
      result.errors.push(...nested.errors);
    }
  }
  return result;
}

function keyBits(record) {
  const m = /p=([A-Za-z0-9+/=]+)/.exec(record || '');
  if (!m) return 0;
  try { return Buffer.from(m[1], 'base64').length * 8; } catch { return 0; }
}

async function blacklist(ip) {
  const rev = ip.split('.').reverse().join('.');
  const zones = ['bl.spamcop.net', 'dnsbl.sorbs.net', 'b.barracudacentral.org'];
  const listed = [];
  await Promise.all(zones.map(async (zone) => {
    const hits = await resolveA(`${rev}.${zone}`);
    if (hits.length) listed.push({ zone, hits });
  }));
  return listed;
}

export async function dnscheck(domain, policy, { selectors = [], ips = [] } = {}) {
  const report = {
    domain, checkedAt: new Date().toISOString(), checks: {}, grade: 'F', score: 0, findings: [], fixes: [],
  };
  const add = (id, status, severity, detail, fix) => {
    report.checks[id] = { status, severity, detail };
    if (severity) report.findings.push({ id, severity, detail });
    if (fix && status !== 'pass') report.fixes.push({ id, fix });
  };

  const mx = await resolveMx(domain);
  add('mx', mx.length ? 'pass' : 'fail', mx.length ? null : 'high', mx.length ? mx.map((m) => `${m.priority} ${m.exchange}`).join(', ') : 'no MX', 'Publish MX records at the sending subdomain.');
  if (mx.length) report.score += 10;

  const spf = await spfRecord(domain);
  const spfAnalysis = await analyzeSpf(spf, domain);
  report.spf = { record: spf, ...spfAnalysis };
  if (!spf) {
    add('spf', 'fail', 'critical', 'no SPF record', 'Publish v=spf1 with only your sending IPs and -all.');
  } else {
    const all = spfAnalysis ? parseSpf(spf).all : null;
    const allStatus = all === '-all' ? 'pass' : all ? 'warn' : 'fail';
    add('spf', allStatus, allStatus === 'pass' ? null : 'high', `all=${all || 'missing'}`, 'End with -all (hard fail) once every sender is listed.');
    if (allStatus === 'pass') report.score += 10;
    if (spfAnalysis.lookups > MAX_LOOKUPS) {
      add('spf_lookups', 'fail', 'high', `${spfAnalysis.lookups} DNS lookups (>10)`, 'Consolidate includes; flatten static SPF.');
    } else {
      add('spf_lookups', 'pass', null, `${spfAnalysis.lookups} lookups`);
      report.score += 5;
    }
    if (spfAnalysis.voidLookups > 2) add('spf_void', 'warn', 'medium', `${spfAnalysis.voidLookups} void lookups`, 'Remove dead includes; RFC 7208 allows max 2 void lookups.');
    if (/[?]all/.test(spf)) add('spf_neutral', 'warn', 'medium', '?all is neutral', 'Use -all.');
  }

  const dmarcDirect = await dmarcRecord(domain);
  const orgDomain = domain.split('.').slice(-2).join('.');
  const dmarc = dmarcDirect || (orgDomain !== domain ? await dmarcRecord(orgDomain) : null);
  const dmarcInherited = !dmarcDirect && Boolean(dmarc);
  const dm = dmarcParse(dmarc);
  report.checks.dmarc = { status: dmarc ? 'pass' : 'fail', record: dmarc, inheritedFrom: dmarcInherited ? orgDomain : null };
  if (!dmarc) {
    add('dmarc', 'fail', 'critical', 'no DMARC record', 'Publish v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:dmarc@domain; pct=100.');
  } else {
    report.score += 10;
    if (dm.p === 'reject') report.score += 10;
    else add('dmarc_p', 'warn', 'high', `p=${dm.p}`, 'Move to p=reject after a 2-4 week p=none observation window.');
    if (!dm.sp && dm.p !== 'reject') add('dmarc_sp', 'warn', 'medium', 'no sp= (subdomains inherit weaker policy)', 'Set sp=reject.');
    if (dm.pct < 100) add('dmarc_pct', 'warn', 'medium', `pct=${dm.pct}`, 'Set pct=100.');
    if (!dm.rua.length) add('dmarc_rua', 'warn', 'low', 'no rua reporting', 'Add rua= to a mailbox you read.');
    if (dm.adkim !== 's') add('dmarc_adkim', 'warn', 'medium', 'adkim=r (relaxed)', 'Set adkim=s for strict alignment.');
    if (dm.aspf !== 's') add('dmarc_aspf', 'warn', 'medium', 'aspf=r (relaxed)', 'Set aspf=s.');
  }

  const allSelectors = [...new Set([...selectors, policy.dkim_selector || 's1'])];
  let dkimGood = 0;
  for (const sel of allSelectors) {
    const rec = await dkimRecord(sel, domain);
    if (!rec) { add(`dkim_${sel}`, 'fail', 'critical', `selector ${sel} missing`, `Publish ${sel}._domainkey.${domain} and sign with it.`); continue; }
    const bits = keyBits(rec);
    if (!/p=[A-Za-z0-9+/=]{40,}/.test(rec)) {
      add(`dkim_${sel}`, 'warn', 'medium', `selector ${sel} present but key is empty/revoked`, 'Publish a real 2048-bit p= value or remove the record.');
      continue;
    }
    report.checks[`dkim_${sel}`] = { status: 'pass', bits };
    if (bits >= 2048) dkimGood += 1;
    else add(`dkim_bits_${sel}`, 'warn', 'high', `${bits}-bit key (use 2048+)`, 'Rotate to RSA-2048 or ed25519.');
  }
  if (dkimGood) report.score += 15;

  const mtaSts = (await resolveTxt(`_mta-sts.${domain}`)).find((r) => /^v=STSv1/i.test(r));
  add('mta_sts', mtaSts ? 'pass' : 'warn', mtaSts ? null : 'low', mtaSts || 'no MTA-STS TXT', 'Publish _mta-sts TXT and https://mta-sts.domain/.well-known/mta-sts.txt (mode: enforce).');
  if (mtaSts) report.score += 5;

  const tlsRpt = (await resolveTxt(`_smtp._tls.${domain}`)).find((r) => /^v=TLSRPTv1/i.test(r));
  add('tls_rpt', tlsRpt ? 'pass' : 'warn', tlsRpt ? null : 'low', tlsRpt || 'no TLS-RPT', 'Publish v=TLSRPTv1; rua=mailto:tlsrpt@domain.');
  if (tlsRpt) report.score += 3;

  const bimi = (await resolveTxt(`default._bimi.${domain}`)).find((r) => /^v=BIMI1/i.test(r));
  add('bimi', bimi ? 'pass' : 'info', bimi ? null : 'info', bimi ? 'BIMI present' : 'no BIMI (needs logo SVG + VMC)', 'Optional: DMARC reject + VMC + SVG Tiny PS.');
  if (bimi) report.score += 3;

  const ipList = [...new Set(ips.length ? ips : (policy.sending_ips || []))];
  if (!ipList.length) {
    add('ip_checks', 'info', 'info', 'no sending IP supplied (use --ip / policy.sending_ips)', 'Run dnscheck with the real egress IPs to test PTR/FCrDNS/DNSBL.');
  }
  for (const ip of ipList.slice(0, 8)) {
    const ptr = await resolvePtr(ip);
    const fcrdns = ptr.length ? (await resolveA(ptr[0])).includes(ip) : false;
    const bl = await blacklist(ip);
    const sh = await spamhausLookup(ip);
    report.checks[`ip_${ip}`] = { ptr, fcrdns, blacklists: bl, spamhaus: sh };
    if (!ptr.length) add(`ptr_${ip}`, 'fail', 'high', `${ip} has no PTR`, 'Set matching forward and reverse DNS (PTR = EHLO/from host).');
    else if (!fcrdns) add(`fcrdns_${ip}`, 'fail', 'high', `PTR ${ptr[0]} does not resolve back to ${ip}`, 'Fix forward-confirmed reverse DNS.');
    else { add(`fcrdns_${ip}`, 'pass', null, `${ip} -> ${ptr[0]}`); report.score += 5; }
    if (bl.length) add(`dnsbl_${ip}`, 'warn', 'medium', `listed: ${bl.map((b) => b.zone).join(', ')}`, 'Request delisting; check sending volume.');
    if (sh.listed) {
      add(`spamhaus_${ip}`, 'fail', 'high', `Spamhaus ${sh.lists.map((l) => `${l.list} (${l.meaning})`).join('; ')}`, spamhausAdvice(sh).join(' '));
    } else if (sh.listed === null) {
      add(`spamhaus_${ip}`, 'info', 'info', `Spamhaus check inconclusive: ${sh.reason}`, 'Retry with a resolver allowed by Spamhaus (the tool uses 9.9.9.9).');
    } else {
      add(`spamhaus_${ip}`, 'pass', null, 'not listed on Spamhaus ZEN');
      report.score += 10;
    }
  }

  const dnssec = await dnssecAd(domain);
  add('dnssec', dnssec ? 'pass' : 'warn', dnssec ? null : 'low', dnssec ? 'AD set' : 'no DNSSEC', 'Enable DNSSEC at the registrar; protects SPF/DKIM/DMARC lookups.');
  if (dnssec) report.score += 5;

  const critical = report.findings.filter((f) => f.severity === 'critical').length;
  const high = report.findings.filter((f) => f.severity === 'high').length;
  report.grade = critical ? 'F' : high > 2 ? 'D' : high ? 'C' : report.score >= 85 ? 'A' : report.score >= 70 ? 'B' : 'C';
  report.summary = { score: report.score, critical, high };
  return report;
}

export async function dnscheckMany(domains, policy, outFile, opts = {}) {
  const reports = [];
  for (const d of domains) reports.push(await dnscheck(d, policy, opts));
  if (outFile) writeJson(outFile, { generatedAt: new Date().toISOString(), reports });
  return reports;
}
