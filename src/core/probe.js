/**
 * Receiver fingerprint / vulnerability probe.
 * Runs the same HELO/MAIL/RCPT/DATA dance a real MTA would and records quirks:
 * capability matrix, TLS cert, null-sender handling, SIZE enforcement, UTF-8,
 * response timing differences, recipient case folding and dot/plus addressing.
 */
import { SmtpClient } from '../lib/smtp.js';
import { resolveMx, dkimRecord, dmarcRecord, spfRecord, dnssecAd } from '../lib/dns.js';
import { randomLocal, normalizeEmail } from '../lib/util.js';

export const TARGETS = {
  gmail: 'gmail.com',
  outlook: 'outlook.com',
  yahoo: 'yahoo.com',
  proton: 'proton.me',
  icloud: 'icloud.com',
  gmx: 'gmx.com',
};

const INTERESTING_CAPS = ['SIZE', '8BITMIME', 'SMTPUTF8', 'PIPELINING', 'CHUNKING', 'STARTTLS', 'DSN', 'ENHANCEDSTATUSCODES', 'AUTH', 'BINARYMIME', 'REQUIRETLS', 'MTA-STS', 'DELIVERBY'];

function timed() { const t = process.hrtime.bigint(); return () => Number(process.hrtime.bigint() - t) / 1e6; }

async function probeOversize(host, policy, timeout, advertised) {
  const client = new SmtpClient({ host, port: 25, timeout, log: () => {} });
  try {
    await client.connect();
    await client.greet(policy.helo_host || 'probe.local');
    if (client.supports('STARTTLS')) { try { await client.starttls(policy.helo_host || 'probe.local'); } catch { /* ignore */ } }
    const reply = await client.mailFrom(policy.mail_from || 'probe@example.com', [`SIZE=${Math.max(advertised + 1, 104857600)}`]);
    await client.quit();
    return { code: reply.code, reply: reply.text };
  } catch (err) {
    client.destroy();
    return { code: 0, reply: `connection closed: ${err.message}` };
  }
}

async function probeNullSender(host, policy, timeout) {
  const client = new SmtpClient({ host, port: 25, timeout, log: () => {} });
  try {
    await client.connect();
    await client.greet(policy.helo_host || 'probe.local');
    if (client.supports('STARTTLS')) { try { await client.starttls(policy.helo_host || 'probe.local'); } catch { /* ignore */ } }
    const t = timed();
    const reply = await client.mailFrom('');
    const ms = Math.round(t());
    await client.quit();
    return { code: reply.code, reply: reply.text, accepted: reply.code === 250, ms };
  } catch (err) {
    client.destroy();
    return { code: 0, reply: err.message, accepted: false, error: true };
  }
}

export async function probeTarget(name, policy, { timeout = 12000 } = {}) {
  const domain = TARGETS[name] || name;
  const mx = await resolveMx(domain);
  const report = {
    target: name, domain, startedAt: new Date().toISOString(), mx: mx.map((m) => m.exchange),
    dns: {}, capabilities: {}, checks: {}, timing: {}, findings: [], score: 0,
  };

  report.dns.spf = Boolean(await spfRecord(domain));
  report.dns.dmarc = Boolean(await dmarcRecord(domain));
  report.dns.dkim = Boolean(await dkimRecord('s1', domain) || await dkimRecord('google', domain) || await dkimRecord('selector1', domain));
  report.dns.dnssec = await dnssecAd(domain);

  if (!mx.length) {
    report.findings.push({ id: 'no-mx', severity: 'info', detail: 'no MX records' });
    return report;
  }

  const host = mx[0].exchange;
  const client = new SmtpClient({ host, port: 25, timeout, log: () => {} });
  try {
    await client.connect();
    const greeted = await client.greet(policy.helo_host || 'probe.local');
    report.banner = greeted.banner.text;
    report.ehlo = greeted.reply.text;
    for (const cap of INTERESTING_CAPS) {
      if (client.supports(cap)) report.capabilities[cap] = client.capabilities.get(cap) || true;
    }
    if (client.capabilities.has('LIMITS')) {
      report.checks.limits = client.capabilities.get('LIMITS');
      report.findings.push({ id: 'ehlo-limits', severity: 'info', detail: `EHLO LIMITS: ${report.checks.limits}` });
    }

    if (client.supports('STARTTLS')) {
      try {
        await client.starttls(policy.helo_host || 'probe.local');
        report.tls = { negotiated: true, protocol: client.socket.getProtocol?.(), cipher: client.socket.getCipher?.()?.name || null };
        const cert = client.socket.getPeerCertificate?.();
        if (cert) report.tls.cert = { subject: cert.subject, issuer: cert.issuer, validTo: cert.valid_to, san: cert.subjectaltname };
      } catch (err) { report.tls = { negotiated: false, error: err.message }; }
    }

    // Null sender is tested on its own connection: some receivers drop the session afterwards.
    const nullSender = await probeNullSender(host, policy, timeout);
    report.timing.nullSenderMs = nullSender.ms || '-';
    report.checks.nullSender = { code: nullSender.code, accepted: nullSender.accepted };
    if (nullSender.accepted) report.findings.push({ id: 'null-sender', severity: 'info', detail: 'accepts MAIL FROM:<> (RFC-compliant bounce path; only a risk with broken forwarding)' });

    const local = randomLocal(16);
    const madeUp = `${local}@${domain}`;

    // SIZE handling on its own connection: receivers may 552 and hang up.
    if (client.capabilities.has('SIZE')) {
      const advertised = Number(client.capabilities.get('SIZE')) || 0;
      report.checks.maxSize = advertised;
      const overSized = await probeOversize(host, policy, timeout, advertised);
      report.checks.sizeOverLimit = overSized;
      if (overSized.code === 250 && advertised > 0) report.findings.push({ id: 'size-not-enforced-at-mail', severity: 'low', detail: 'MAIL FROM SIZE above advertised max accepted' });
      if (overSized.code === 0) report.findings.push({ id: 'size-check-dropped', severity: 'info', detail: 'receiver closed connection on oversized SIZE declaration' });
    }

    // MAIL and RCPT for a random mailbox: does the server validate at RCPT or accept everything?
    const mf = await client.mailFrom(policy.mail_from || 'probe@example.com');
    report.checks.mailFrom = { code: mf.code, reply: mf.text };
    if (mf.code >= 500) {
      report.findings.push({ id: 'mail-from-rejected', severity: 'high', detail: mf.text });
      report.checks.transactionSkipped = true;
    } else {
    const t1 = timed();
    const rcptRandom = await client.rcptTo(madeUp);
    const firstMs = t1();
    report.timing.rcptRandomMs = Math.round(firstMs);
    report.checks.rcptRandom = { code: rcptRandom.code, reply: rcptRandom.text, accepted: rcptRandom.code === 250 };

    if (rcptRandom.code === 250) {
      // Domain accepts unknown recipients at RCPT (likely catch-all or deferred validation).
      report.findings.push({
        id: 'rcpt-accepts-random', severity: 'info',
        detail: 'unknown local part accepted at RCPT; exists-check needs DATA bounce or VERP',
      });
    }

    // SMTPUTF8
    if (client.capabilities.has('SMTPUTF8')) {
      await client.cmd('RSET');
      const u = await client.mailFrom(policy.mail_from || 'probe@example.com', ['SMTPUTF8']);
      if (u.code === 250) {
        const ur = await client.rcptTo(`tést-${randomLocal(4)}@${domain}`, ['SMTPUTF8']);
        report.checks.smtputf8Rcpt = { code: ur.code, reply: ur.text };
      }
    }

    // Case folding: RCPT uppercase version of the random mailbox (same connection)
    await client.cmd('RSET');
    const mf2 = await client.mailFrom(policy.mail_from || 'probe@example.com');
    if (mf2.code === 250) {
      const t2 = timed();
      const upper = await client.rcptTo(madeUp.toUpperCase());
      report.timing.rcptUpperMs = Math.round(t2());
      report.checks.caseFolding = { code: upper.code, reply: upper.text };
      if (upper.code === 250 && firstMs > 50) report.findings.push({ id: 'timing-oracle', severity: 'low', detail: 'response time differs enough for mailbox enumeration' });
    }

    // Plus/dot alias acceptance (receiver-side alias semantics)
    if (domain === 'gmail.com' || domain === 'googlemail.com') {
      await client.cmd('RSET');
      const mf3 = await client.mailFrom(policy.mail_from || 'probe@example.com');
      if (mf3.code === 250) {
        const dotted = `${local.slice(0, 6)}.${local.slice(6)}@gmail.com`;
        const r = await client.rcptTo(dotted);
        report.checks.dotAliasRcpt = { code: r.code, reply: r.text, note: 'Gmail treats dots as insignificant; RCPT may still 550 for unregistered aliases' };
      }
    }
    }

    report.findings.push({
      id: 'caps', severity: 'info',
      detail: `advertised: ${Object.keys(report.capabilities).join(', ') || 'none'}`,
    });
    await client.quit();
  } catch (err) {
    report.error = `${err.name}: ${err.message}`;
    client.destroy();
  }

  if (report.error) report.findings.push({ id: 'probe-error', severity: 'info', detail: report.error });
  if (report.checks.rcptRandom?.accepted) report.score += 1;
  if (report.checks.nullSender?.accepted) report.score += 1;
  if (report.tls?.negotiated) report.score += 1;
  if (report.capabilities.SMTPUTF8) report.score += 1;
  if (report.capabilities.CHUNKING) report.score += 1;
  report.grade = report.score >= 4 ? 'A' : report.score >= 2 ? 'B' : 'C';
  return report;
}

export function probeSummary(reports) {
  const rows = [];
  for (const r of reports) {
    rows.push({
      target: r.target, mx: r.mx[0] || '-', grade: r.grade || '-',
      tls: r.tls?.negotiated ? 'yes' : 'no', nullSender: r.checks?.nullSender?.accepted ? 'accepted' : 'rejected',
      randomRcpt: r.checks?.rcptRandom?.code || '-', maxSize: r.checks?.maxSize || '-',
      ms: r.timing?.rcptRandomMs || '-', findings: r.findings?.length || 0,
    });
  }
  return rows;
}
