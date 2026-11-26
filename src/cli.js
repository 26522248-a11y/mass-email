#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline/promises';
import { ParseArgsError, parseArgs } from './lib/args.js';
import { ROOT, readJson, writeJson, parseCsv, normalizeEmail, sleep, randInt, ensureDir, makeLogger, expandPath } from './lib/util.js';
import { RelayPool, RelayGuard, loadRelays } from './core/pool.js';
import { Queue } from './core/queue.js';
import { loadKeys, loadTemplates, sendJob, renderJob } from './core/sender.js';
import { sendDirectJob } from './core/mxdeliver.js';
import { diagnoseEgress, diagnoseSummary, egressInfo } from './core/diagnose.js';
import { probeRateLimit } from './core/ratelimit.js';
import { runMailTester, readMailTester } from './core/mailtester.js';
import { proxycheck } from './core/proxycheck.js';
import { sendGraphJob } from './core/graph.js';
import { PROVIDERS, probeAll, probeProvider, espSummary, EspPool, sendEspJob, buildEspRequest } from './core/esp.js';
import { deviceCodeStart, deviceCodePoll, saveToken, loadToken, refreshToken, graphMe, sendGraphMeJob } from './core/graphdevice.js';
import { checkIdentity, identityLadder, inventory, choosePath, isRealSecret } from './core/identity.js';
import { buildMessage, htmlFromText } from './lib/mime.js';
import { scoreMessage } from './lib/spamscore.js';
import { verifyBatch, verificationSummary } from './core/verifier.js';
import { dnscheck, dnscheckMany } from './core/dnscheck.js';
import { probeTarget, probeSummary, TARGETS } from './core/probe.js';
import { buildWarmupPlan, writeWarmupCsv, warmupAdvice } from './core/warmup.js';
import { planCapacity } from './core/capacity.js';
import { signMessage, generateKeypair } from './lib/dkim.js';
import { transact } from './lib/smtp.js';

const HELP = `mass-email - multi-relay bulk mail engine + receiver probe kit

  init                          create policy.json, relays.json, dirs
  keys --domain d --selector s  generate DKIM keypair and print DNS record
  send --list f [options]       enqueue and send (CSV: email,name,token)
  verify --list f [--out f]     MX + RCPT verification, catch-all detection
  dnscheck --domain d [...]     SPF/DKIM/DMARC/PTR/MTA-STS/DNSSEC audit
  probe [--target gmail,...]    receiver capability + behaviour fingerprint
  score --text f [--html f]     local spam heuristics
  warmup --start n --target n   generate IP/domain warmup plan
  capacity --target n           relays/IPs/domains/cost for a daily volume
  diagnose                      egress IP, PTR, Spamhaus codes, per-receiver block
  ratelimit --target gmail.com  SMTP command-rate tolerance from this host
  mailtest [--path direct]      send to mail-tester.com and read the 0-10 report
  relaytest --id r --auth-only  test SMTP AUTH for one relay
  relaytest --id r --to a@b     send one real message through that relay
  proxycheck --user u --pass p  test whether a proxy allows SMTP ports
  graphtest --to a@b            send one message via Microsoft 365 Graph
  graphdevice [--to a@b]        Graph via device-code login (no app secret)
  send --path graph             send the list via Graph (10k/day/mailbox)
  espprobe [--provider id]      free-tier ESP reachability + free daily capacity
  espsend --list f [--limit n]  send through free ESP accounts (HTTPS API, no SMTP)
  identity [--ip i] [--domain d] identity score, receiver projection, inventory
  identity --plan               zero-cost identity ladder (ranked)
  pool                          relay health and remaining quota
  queue [stats|failed|retry]    queue inspection
  dns-records                   print the DNS records this policy needs

send options:
  --text f --html f --subject s --from addr
  --limit n --concurrency n --dry-run --yes --no-sign
  --path relay|direct|auto|graph|smart   (auto: direct per policy; smart: per-receiver identity)
  --relay id (force one relay)
`;
function loadPolicy() {
  const file = expandPath('config/policy.json');
  const p = readJson(file);
  if (!p) throw new Error('config/policy.json missing - run: node src/cli.js init');
  return p;
}

function recipients(file) {
  const rows = parseCsv(fs.readFileSync(expandPath(file), 'utf8'));
  return rows.map((r) => ({ ...r, email: normalizeEmail(r.email) }));
}

async function confirm(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const a = await rl.question(`${question} [y/N] `);
  rl.close();
  return /^y/i.test(a);
}

async function cmdInit() {
  const policyFile = expandPath('config/policy.json');
  const relaysFile = expandPath('config/relays.json');
  if (!fs.existsSync(policyFile)) {
    const src = expandPath('config/policy.json');
    if (!fs.existsSync(src)) throw new Error('policy template missing');
  }
  if (!fs.existsSync(relaysFile)) fs.copyFileSync(expandPath('config/relays.example.json'), relaysFile);
  for (const d of ['data', 'state', 'logs', 'keys', 'reports']) ensureDir(expandPath(d));
  console.log('initialized. edit config/policy.json + config/relays.json, then: node src/cli.js keys --domain <d>');
}

async function cmdKeys(args) {
  const domain = args.domain || loadPolicy().from_domain;
  if (!domain) throw new Error('--domain required');
  const selector = args.selector || 's1';
  const pair = generateKeypair(2048);
  writeJson(expandPath(`keys/${domain}.json`), {
    domain, selector, privateKey: pair.privateKey, publicKey: pair.publicKey, createdAt: new Date().toISOString(),
  });
  fs.writeFileSync(expandPath(`keys/${domain}.pub`), pair.dns + '\n');
  console.log(`wrote keys/${domain}.json`);
  console.log('\nDNS record:\n');
  console.log(`  Name:  ${selector}._domainkey.${domain}`);
  console.log('  Type:  TXT');
  console.log(`  Value: ${pair.dns}`);
  console.log('\nAlso publish: _dmarc TXT, SPF, MX, PTR, MTA-STS, TLS-RPT. Run: dnscheck --domain ' + domain);
}

async function cmdSend(args) {
  const policy = loadPolicy();
  if (args.subject) policy.subject = args.subject;
  if (args.from) policy.from_address = args.from;
  if (args['no-sign']) policy.sign = false;
  const list = recipients(args.list);
  if (args.limit) list.length = Math.min(list.length, Number(args.limit));
  if (!list.length) throw new Error('no valid recipients');
  const textFile = expandPath(args.text || 'templates/newsletter.txt');
  const htmlFile = args.html ? expandPath(args.html) : null;
  const templates = loadTemplates(policy, ROOT, textFile, htmlFile);

  // Pre-flight
  const demo = renderJob({ job: { id: 'preflight', email: list[0].email, row: list[0] }, policy, templates });
  const pre = scoreMessage({ subject: demo.subject, text: demo.text, html: demo.html, hasUnsubscribe: true });
  console.log(`preflight spam score: ${pre.score} ${pre.findings.join(',') || 'clean'}`);
  if (policy.spamscore && pre.score > policy.spamscore.fail_over) console.log('WARN: over fail_over, messages will be held');

  const keys = loadKeys(expandPath('keys'));
  if (args['dry-run']) {
    const built = buildMessage({
      row: demo.row, subject: demo.subject, text: demo.text, html: demo.html, policy,
      fromName: policy.from_name, from: policy.from_address, replyTo: policy.reply_to,
      unsubscribeMailto: policy.unsubscribe_mailto, token: demo.row.token, domain: policy.from_domain,
      extraHeaders: Object.entries(policy.headers || {}).filter(([, v]) => v).map(([k, v]) => [k, String(v)]),
    });
    let raw = built.raw;
    const demoKey = keys[policy.from_domain];
    if (demoKey) {
      const sig = signMessage({ rawHeaders: built.headers, body: built.body, domain: policy.from_domain, selector: demoKey.selector, privateKey: demoKey.privateKey });
      raw = sig + '\r\n' + raw;
    }
    console.log(`\n--- dry run (${raw.length} bytes) ---\n${raw.slice(0, 1200)}`);
    return;
  }

  if (!args.yes) {
    const ok = await confirm(`send ${list.length} messages now?`);
    if (!ok) return;
  }

  const relaysFile = expandPath('config/relays.json');
  const relays = loadRelays(relaysFile);
  const pathMode = args.path || policy.send_path || 'relay';
  const usableRelays = pathMode === 'smart' ? relays.filter((r) => isRealSecret(r.user) && isRealSecret(r.pass || r.access_token)) : relays;
  const pool = new RelayPool({ stateFile: expandPath('state/pool.json'), relays: usableRelays });
  const guard = new RelayGuard(pool);
  const queue = new Queue({ dir: expandPath('data/queue') });
  const jobs = queue.addMany(list);
  if (!keys[policy.from_domain] && policy.sign !== false) console.log('WARN: no DKIM key for ' + policy.from_domain);

  const logger = makeLogger(expandPath('logs/send.log'));
  const concurrency = Math.max(1, Number(args.concurrency) || policy.pacing?.per_relay_concurrency || 4);
  const gaps = [policy.pacing?.min_gap_ms ?? 250, policy.pacing?.max_gap_ms ?? 1200];
  const directDomains = (policy.direct_domains || ['gmail.com', 'googlemail.com']).map((d) => d.toLowerCase());
  const graphCfg = (pathMode === 'graph' || pathMode === 'smart') ? readJson(expandPath('config/graph.json')) : null;
  if (pathMode === 'graph' && !graphCfg) throw new Error('config/graph.json missing (copy config/graph.example.json)');
  const espAccounts = pathMode === 'smart' ? (readJson(expandPath('config/esp.json'), {})?.accounts || []).filter((a) => isRealSecret(a.api_key)) : [];
  const espPool = espAccounts.length ? new EspPool({ accounts: espAccounts, stateFile: expandPath('state/esp.json') }) : null;
  let route = null;
  if (pathMode === 'smart') {
    const domains = [...new Set(list.map((r) => (r.email.split('@')[1] || '').toLowerCase()))].slice(0, 24);
    const ip = args.ip || (await egressInfo())?.ip;
    const idReport = await checkIdentity({
      ip, domain: policy.from_domain, helo: policy.helo_host || policy.from_domain,
      from: policy.from_address, receivers: domains, timeout: 8000,
    });
    route = { grade: idReport.grade, score: idReport.score, verdicts: new Map(idReport.projected.map((p) => [p.domain, p.verdict])) };
    console.log(`smart routing: identity ${idReport.score}/100 (${idReport.grade}); ${idReport.blocked.length}/${domains.length} receiver(s) block this IP; esp=${espPool ? espAccounts.length : 0} graph=${graphCfg ? 'yes' : 'no'} relay=${usableRelays.length}`);
  }
  let sent = 0; let failed = 0; let retried = 0; let held = 0;
  const byPath = { relay: 0, direct: 0, graph: 0, esp: 0 };
  const started = Date.now();

  async function worker() {
    while (true) {
      const batch = queue.lease(1);
      if (!batch.length) {
        if (queue.stats().pending === 0 && queue.stats().leased === 0) return;
        await sleep(500);
        if (Date.now() - started > 1000 * 60 * 60 * 6) return;
        continue;
      }
      const job = batch[0];
      let result;
      try {
        const domain = job.email.split('@')[1] || '';
        const useDirect = pathMode === 'direct' || (pathMode === 'auto' && directDomains.includes(domain));
        if (pathMode === 'graph') {
          result = await sendGraphJob({ job, policy, templates, cfg: graphCfg });
          byPath.graph += 1;
        } else if (pathMode === 'smart') {
          const verdict = route.verdicts.get(domain) || 'unknown';
          const choice = choosePath({
            verdict, grade: route.grade,
            hasEsp: Boolean(espPool?.pick()), hasGraph: Boolean(graphCfg), hasRelay: usableRelays.length > 0,
            allowDirect: directDomains.includes(domain) || !directDomains.length,
          });
          if (choice === 'direct') {
            result = await sendDirectJob({ job, policy, templates, keys, logger });
            byPath.direct += 1;
          } else if (choice === 'esp') {
            const account = espPool.pick();
            result = await sendEspJob({ job, policy, templates, cfg: { ...account, from: account.from || policy.from_address } });
            if (result.status === 'sent') espPool.markSent(account);
            byPath.esp += 1;
          } else if (choice === 'graph') {
            result = await sendGraphJob({ job, policy, templates, cfg: graphCfg });
            byPath.graph += 1;
          } else if (choice === 'relay') {
            result = await sendJob({ job, pool, guard, policy, templates, keys, logger, relayId: args.relay || null });
            byPath.relay += 1;
          } else {
            result = { status: 'held', reason: `no identity accepted by ${domain}` };
          }
        } else {
          result = useDirect
            ? await sendDirectJob({ job, policy, templates, keys, logger })
            : await sendJob({ job, pool, guard, policy, templates, keys, logger, relayId: args.relay || null });
          byPath[useDirect ? 'direct' : 'relay'] += 1;
        }
      } catch (err) {
        result = { status: 'retry', reason: err.message, retrySeconds: 120 };
      }
      if (result.status === 'sent' || result.status === 'dry') {
        queue.complete(job, result); sent++;
        logger.info('sent', { email: job.email, relay: result.relayId, host: result.host, path: result.path, msg: result.messageId });
      } else if (result.status === 'bounced') {
        queue.fail(job, result); failed++;
        logger.warn('bounce', { email: job.email, reason: result.reason });
      } else if (result.status === 'held') {
        queue.hold(job, result); held++;
        logger.warn('held', { email: job.email, reason: result.reason });
      } else {
        const schedule = policy.retry?.schedule_seconds || [60, 300, 1800, 7200, 21600];
        if (job.attempts >= (policy.retry?.max_attempts || 5)) {
          queue.fail(job, result); failed++;
        } else {
          const wait = result.retrySeconds || schedule[Math.min(job.attempts, schedule.length - 1)];
          queue.retry(job, wait, result); retried++;
        }
      }
      if ((sent + failed + retried + held) % 10 === 0) {
        const st = queue.stats();
        console.log(`progress sent=${sent} failed=${failed} retry=${retried} held=${held} pending=${st.pending}`);
      }
      await sleep(randInt(gaps[0], Math.max(gaps[0], gaps[1])));
    }
  }

  await Promise.all(Array.from({ length: concurrency }, worker));
  logger.close();
  const st = queue.stats();
  console.log(`\ndone in ${((Date.now() - started) / 1000).toFixed(1)}s: sent=${sent} bounced=${failed} scheduled=${retried} held=${held}`);
  console.log(`path: relay=${byPath.relay} direct=${byPath.direct} graph=${byPath.graph}`);
  console.log(`queue: pending=${st.pending} done=${st.done} failed=${st.failed} held=${st.held}`);
  console.log('summary: data/queue, log: logs/send.log');
  void jobs;
}

async function cmdVerify(args) {
  const policy = loadPolicy();
  const rows = recipients(args.list);
  if (args.limit) rows.length = Math.min(rows.length, Number(args.limit));
  console.log(`verifying ${rows.length} addresses on port 25 (concurrency ${policy.verify?.concurrency || 8})...`);
  const results = await verifyBatch(rows, { ...policy.verify, catch_all_probes: policy.verify?.catch_all_probes ?? 2 }, {
    concurrency: Number(args.concurrency) || policy.verify?.concurrency || 8,
    onResult: (r) => { if (process.env.VERBOSE) console.log(r.email, r.status); },
  });
  const summary = verificationSummary(results);
  const out = expandPath(args.out || `reports/verify-${Date.now()}.json`);
  writeJson(out, { generatedAt: new Date().toISOString(), summary, results });
  console.log(JSON.stringify(summary, null, 2));
  console.log('report: ' + out);
}

async function cmdDns(args) {
  const policy = loadPolicy();
  const domains = [].concat(args.domain || policy.from_domain);
  const ips = args.ip ? [].concat(args.ip).flatMap((s) => String(s).split(',')).map((s) => s.trim()).filter(Boolean) : [];
  const reports = await dnscheckMany(domains, policy, expandPath(`reports/dns-${Date.now()}.json`), { selectors: policy.dkim_selectors || [], ips });
  for (const r of reports) {
    console.log(`\n${r.domain}  grade=${r.grade} score=${r.score}`);
    for (const f of r.findings) console.log(`  [${f.severity}] ${f.id}: ${f.detail}`);
    if (r.fixes.length) console.log('  fixes:', r.fixes.map((f) => f.fix).join(' '));
  }
  void dnscheck;
}

async function cmdProbe(args) {
  const policy = loadPolicy();
  const names = (args.target || 'gmail,outlook').split(',').map((s) => s.trim()).filter(Boolean);
  const reports = [];
  for (const n of names) {
    console.log('probing ' + n + '...');
    reports.push(await probeTarget(n, policy));
  }
  const out = expandPath(`reports/probe-${Date.now()}.json`);
  writeJson(out, { generatedAt: new Date().toISOString(), reports });
  console.table(probeSummary(reports));
  for (const r of reports) for (const f of r.findings) console.log(`${r.target}: [${f.severity}] ${f.id} - ${f.detail}`);
  console.log('report: ' + out);
  void TARGETS;
}

async function cmdScore(args) {
  const text = fs.readFileSync(expandPath(args.text), 'utf8');
  const html = args.html ? fs.readFileSync(expandPath(args.html), 'utf8') : null;
  const subject = args.subject || 'Test subject';
  const result = scoreMessage({ subject, text, html, hasUnsubscribe: true });
  console.log(JSON.stringify(result, null, 2));
}

function cmdWarmup(args) {
  const plan = buildWarmupPlan({
    start: Number(args.start) || 50, target: Number(args.target) || 5000,
    days: Number(args.days) || 28, growth: Number(args.growth) || 1.35,
  });
  const out = expandPath(args.out || 'reports/warmup.csv');
  const n = writeWarmupCsv(plan, out);
  console.log(plan.map((p) => `day ${p.day}: ${p.daily}`).join('\n'));
  console.log(`\n${n} days -> ${out}`);
  console.log(warmupAdvice().map((a) => '- ' + a).join('\n'));
}

function cmdCapacity(args) {
  const plan = planCapacity({
    targetPerDay: Number(args.target) || 100000,
    perRelayPerDay: Number(args['per-relay']) || undefined,
    perIpPerDay: Number(args['per-ip']) || undefined,
    perDomainPerDay: Number(args['per-domain']) || undefined,
    windowHours: Number(args.hours) || 16,
    headroom: Number(args.headroom) || 1.35,
  });
  console.log(JSON.stringify(plan, null, 2));
}

async function cmdDiagnose(args) {
  const policy = loadPolicy();
  console.log('checking egress IP, PTR, Spamhaus, port 25 and receiver acceptance...');
  const report = await diagnoseEgress({ policy, timeout: Number(args.timeout) || 12000 });
  const out = expandPath(`reports/diagnose-${Date.now()}.json`);
  writeJson(out, report);
  console.table([diagnoseSummary(report)]);
  console.log('\nblockers:');
  for (const b of report.blockers) console.log(`  [${b.severity}] ${b.id}: ${b.detail}`);
  console.log('\ntargets:');
  for (const [d, t] of Object.entries(report.targets)) console.log(`  ${d}: ${t.verdict}  MAIL=${t.checks?.mail?.code || '-'}  TLS=${t.tls}`);
  console.log('\nroute:', report.route.recommended);
  if (report.advice) console.log('advice:\n  - ' + report.advice.join('\n  - '));
  console.log('report: ' + out);
}

async function cmdRatelimit(args) {  const policy = loadPolicy();
  const report = await probeRateLimit({
    policy,
    domain: args.target || 'gmail.com',
    connections: Number(args.connections) || 10,
    rcptPerConn: Number(args.rcpt) || 5,
    concurrency: Number(args.concurrency) || 2,
    timeout: Number(args.timeout) || 12000,
  });
  const out = expandPath(`reports/ratelimit-${Date.now()}.json`);
  writeJson(out, report);
  console.log(JSON.stringify(report.summary, null, 2));
  console.log('report: ' + out);
}

async function cmdMailtest(args) {
  const policy = loadPolicy();
  if (args.id) {
    const checks = await readMailTester(args.id, { root: ROOT });
    const out = expandPath(`reports/mailtest-${args.id}.json`);
    writeJson(out, { id: args.id, readAt: new Date().toISOString(), checks });
    console.log(JSON.stringify({ id: args.id, checks }, null, 2));
    console.log('report: ' + out);
    return;
  }
  const templates = loadTemplates(policy, ROOT, expandPath(args.text || 'templates/newsletter.txt'), args.html ? expandPath(args.html) : expandPath('templates/newsletter.html'));
  const keys = loadKeys(expandPath('keys'));
  const pathMode = args.path || 'direct';
  let pool = null; let guard = null;
  if (pathMode === 'relay') {
    pool = new RelayPool({ stateFile: expandPath('state/pool.json'), relays: loadRelays(expandPath('config/relays.json')) });
    guard = new RelayGuard(pool);
  }
  console.log(`mail-tester: sending via ${pathMode}, waiting for report...`);
  const report = await runMailTester({ policy, templates, keys, pool, guard, pathMode, root: ROOT, logger: null });
  const out = expandPath(`reports/mailtest-${report.id}.json`);
  writeJson(out, report);
  console.log(JSON.stringify(report, null, 2));
  console.log('report: ' + out);
}

async function cmdRelayTest(args) {
  const policy = loadPolicy();
  const relays = loadRelays(expandPath('config/relays.json'));
  const relay = args.id ? relays.find((r) => r.id === args.id) : (relays.length === 1 ? relays[0] : null);
  if (!relay) throw new Error(`relay not found; pass --id (${relays.map((r) => r.id).join(', ')})`);

  const base = {
    host: relay.host, port: relay.port, secure: Boolean(relay.secure), starttls: relay.starttls !== false,
    user: relay.user, pass: relay.access_token || relay.pass, authMethod: relay.auth,
    heloHost: relay.helo_host || policy.helo_host || policy.from_domain,
    servername: relay.tls_servername || relay.host, timeout: Number(args.timeout) || 20000,
    log: (line) => { if (args.verbose) console.log(line); },
  };

  if (args['auth-only']) {
    const { client } = await transact(base);
    console.log(`AUTH OK: ${relay.id} via ${relay.host}:${relay.port} (${relay.user})`);
    await client.quit();
    return;
  }
  if (!args.to) throw new Error('--to required for a full test (or use --auth-only)');

  const testPolicy = {
    ...policy,
    from_address: args.from || policy.from_address,
    spamscore: { fail_over: 99, warn_over: 9 },
  };
  const templates = loadTemplates(policy, ROOT, expandPath(args.text || 'templates/newsletter.txt'), args.html ? expandPath(args.html) : expandPath('templates/newsletter.html'));
  const keys = loadKeys(expandPath('keys'));
  const pool = new RelayPool({ stateFile: expandPath('state/pool.json'), relays: [relay] });
  const guard = new RelayGuard(pool);
  const job = { id: `relaytest-${Date.now()}`, email: args.to, from: testPolicy.from_address, row: { email: args.to, name: 'Test', token: 'test', url: policy.link_url || 'https://example.com' } };
  const result = await sendJob({ job, pool, guard, policy: testPolicy, templates, keys, relayId: relay.id, timeout: Number(args.timeout) || 20000 });
  console.log(JSON.stringify(result, null, 2));
  if (result.status === 'sent') console.log(`SENT: ${relay.id} -> ${args.to} (${result.code})`);
}

async function cmdProxycheck(args) {
  const saved = readJson(expandPath('config/proxy.json'), {});
  const host = args.host || saved.host || 'pr.oxylabs.io';
  const user = args.user || process.env.PROXY_USER || saved.user;
  const pass = args.pass || process.env.PROXY_PASS || saved.pass;
  if (!user || !pass) throw new Error('set PROXY_USER/PROXY_PASS, config/proxy.json, or --user/--pass');
  const report = await proxycheck({ host, httpPort: Number(args['http-port'] || saved.http_port) || 7777, socksPort: Number(args['socks-port'] || saved.socks_port) || 10000, user, pass });
  const out = expandPath(`reports/proxy-${Date.now()}.json`);
  writeJson(out, report);
  console.table([...report.http.map((r) => ({ path: 'http', target: `${r.target}:${r.port}`, ok: r.ok, detail: r.status || r.error })), ...report.socks.map((r) => ({ path: 'socks', target: `${r.target}:${r.port}`, ok: r.ok, detail: r.error || 'open' }))]);
  if (report.egress) console.log('egress:', JSON.stringify(report.egress));
  console.log(`smtpUsable=${report.smtpUsable}\n${report.verdict}\nreport: ${out}`);
}

async function cmdGraphTest(args) {
  const policy = loadPolicy();
  const cfg = readJson(expandPath('config/graph.json'));
  if (!cfg) throw new Error('config/graph.json missing (copy config/graph.example.json)');
  if (!args.to) throw new Error('--to required');
  const templates = loadTemplates(policy, ROOT, expandPath(args.text || 'templates/newsletter.txt'), args.html ? expandPath(args.html) : expandPath('templates/newsletter.html'));
  const job = { id: `graph-${Date.now()}`, email: args.to, row: { email: args.to, name: 'Test', token: 'test', url: policy.link_url || 'https://example.com' } };
  const result = await sendGraphJob({ job, policy, templates, cfg });
  console.log(JSON.stringify(result, null, 2));
}

async function cmdEspProbe(args) {
  const rows = args.provider ? [await probeProvider(args.provider)] : await probeAll(Number(args.timeout) || 9000);
  const out = expandPath(`reports/espprobe-${Date.now()}.json`);
  writeJson(out, { at: new Date().toISOString(), summary: espSummary(rows), providers: rows });
  console.table(rows.map((r) => ({
    provider: r.id, free: r.free, domain_required: r.domain_required ? 'yes' : 'no',
    api: r.api.reachable ? 'ok' : r.api.error, smtp: r.smtp.reachable ? `${r.smtp.host}:${r.smtp.port}` : r.smtp.error,
    auth: r.smtp.auth ? 'yes' : 'n/a', starttls: r.smtp.starttls ? 'yes' : 'n/a',
  })));
  const s = espSummary(rows);
  console.log(`reachable ${s.reachable}/${s.providers}; sender-verify-only ${s.sender_verify_only}; combined free capacity ${s.combined_daily_capacity}/day`);
  console.log('report: ' + out);
}

async function cmdEspSend(args) {
  const policy = loadPolicy();
  const cfg = readJson(expandPath(args.config || 'config/esp.json'));
  if (!cfg?.accounts?.length) throw new Error('config/esp.json missing accounts (copy config/esp.example.json)');
  const providerFilter = args.provider || cfg.provider || null;
  const accounts = providerFilter ? cfg.accounts.filter((a) => a.provider === providerFilter) : cfg.accounts;
  if (!accounts.length) throw new Error(`no accounts for provider ${providerFilter}`);
  const pool = new EspPool({ accounts, stateFile: expandPath('state/esp.json') });
  const templates = loadTemplates(policy, ROOT, expandPath(args.text || 'templates/newsletter.txt'), args.html ? expandPath(args.html) : expandPath('templates/newsletter.html'));
  const rows = recipients(args.list);
  if (!rows.length) throw new Error('no valid recipients');
  const limit = Number(args.limit) || rows.length;
  const pace = Number(args.pace ?? cfg.pace_ms ?? 200);

  console.log(`accounts: ${accounts.length}  providers: ${[...new Set(accounts.map((a) => a.provider))].join(',')}  daily left: ${pool.stats().reduce((n, a) => n + a.remaining, 0)}`);
  if (!args['dry-run'] && !args.yes) {
    const ok = await confirm(`send up to ${Math.min(limit, rows.length)} messages via free ESP accounts?`);
    if (!ok) return;
  }

  const tally = { sent: 0, retry: 0, failed: 0, skipped: 0 };
  let n = 0;
  for (const row of rows) {
    if (n >= limit) break;
    const account = pool.pick(providerFilter);
    if (!account) { tally.skipped++; break; }
    const job = { id: `esp-${Date.now()}-${n}`, email: row.email, row: { ...row, url: policy.link_url || 'https://example.com' } };
    if (args['dry-run']) {
      const req = buildEspRequest({ provider: account.provider, job, policy, templates, cfg: account });
      console.log(`dry ${account.provider} -> ${row.email} subject="${req.json.subject || req.json.Messages?.[0]?.Subject || ''}"`);
      tally.sent++;
    } else {
      const result = await sendEspJob({ job, policy, templates, cfg: { ...account, from: account.from || policy.from_address } });
      if (result.status === 'sent') { pool.markSent(account); tally.sent++; }
      else if (result.status === 'retry') { tally.retry++; }
      else { tally.failed++; }
      if (!args.quiet) console.log(`${result.status} ${account.provider} -> ${row.email} ${result.code || ''} ${result.reason || ''}`.trim());
      await sleep(pace);
    }
    n++;
  }
  console.table([tally]);
  console.log('quota: ' + JSON.stringify(pool.stats()));
}

async function cmdGraphDevice(args) {
  const cfg = readJson(expandPath('config/graph.json'), {}) || {};
  const clientId = args['client-id'] || cfg.client_id || process.env.GRAPH_CLIENT_ID;
  const tenant = args.tenant || cfg.tenant_id || 'common';
  const tokenFile = expandPath('state/graph-device.json');
  if (!clientId) throw new Error('need a public-client app id: --client-id, config/graph.json client_id, or GRAPH_CLIENT_ID');

  let saved = loadToken(tokenFile);
  if (!saved || saved.expires_at < Date.now() + 60_000) {
    if (saved?.refresh_token) {
      try {
        saved = saveToken(tokenFile, await refreshToken({ clientId, tenant, refresh: saved.refresh_token }));
        console.log('token refreshed');
      } catch { saved = null; }
    }
    if (!saved) {
      const dc = await deviceCodeStart({ clientId, tenant });
      console.log(`\n1. open ${dc.verification_uri}`);
      console.log(`2. enter code: ${dc.user_code}\n`);
      const token = await deviceCodePoll({ clientId, tenant, deviceCode: dc.device_code, interval: dc.interval, expiresIn: dc.expires_in });
      saved = saveToken(tokenFile, token);
      console.log(`token saved (${Math.round((saved.expires_at - Date.now()) / 60000)} min)`);
    }
  }

  const sender = args.from || cfg.sender || await graphMe(saved.access_token);
  console.log('sender:', sender);
  if (!args.to) { console.log('auth ready; pass --to address to send a test message'); return; }

  const policy = loadPolicy();
  const templates = loadTemplates(policy, ROOT, expandPath(args.text || 'templates/newsletter.txt'), args.html ? expandPath(args.html) : expandPath('templates/newsletter.html'));
  const job = { id: `graphdev-${Date.now()}`, email: args.to, row: { email: args.to, name: 'Test', token: 'test', url: policy.link_url || 'https://example.com' } };
  const result = await sendGraphMeJob({ job, policy, templates, token: saved.access_token, sender });
  console.log(JSON.stringify(result, null, 2));
}

async function cmdIdentity(args) {
  const policy = readJson(expandPath('config/policy.json'));
  if (args.plan) {
    console.table(identityLadder().map((l) => ({ rank: l.rank, id: l.id, cost: l.cost, volume: l.volume, inbox: l.inbox, setup: l.setup })));
    return;
  }
  const domain = args.domain || policy?.from_domain || null;
  const ip = args.ip || policy?.sending_ips?.[0] || (await egressInfo())?.ip;
  if (!ip) throw new Error('cannot determine egress IP; pass --ip');
  const report = await checkIdentity({
    ip, domain,
    helo: args.helo || policy?.helo_host || domain || undefined,
    from: args.from || policy?.from_address || undefined,
    probe: !args['no-probe'],
    timeout: Number(args.timeout) || 9000,
  });
  const out = expandPath(`reports/identity-${Date.now()}.json`);
  writeJson(out, report);

  console.log(`identity ${ip}${domain ? ' / ' + domain : ''}  score=${report.score}/100 grade=${report.grade}`);
  if (report.blockers.length) console.table(report.blockers.map((b) => ({ id: b.id, severity: b.severity, detail: b.detail })));
  if (report.projected.length) console.table(report.projected.map((p) => ({ receiver: p.domain, verdict: p.verdict, detail: p.rcpt?.reply || p.mailFrom?.reply || p.error || '' })));

  const relays = loadRelays(expandPath('config/relays.json'));
  const esp = readJson(expandPath('config/esp.json'), {})?.accounts || [];
  const graph = readJson(expandPath('config/graph.json'));
  const device = loadToken(expandPath('state/graph-device.json'));
  console.table(inventory({ relays, esp, graph, device, directReady: report.blocked.length === 0 }).map((i) => ({ id: i.id, kind: i.kind, ready: i.ready ? 'yes' : 'no', note: i.note })));

  if (args.list) {
    const rows = recipients(args.list);
    const domains = [...new Set(rows.map((r) => (r.email.split('@')[1] || '').toLowerCase()))].slice(0, 24);
    const routeReport = await checkIdentity({
      ip, domain, helo: args.helo || policy?.helo_host || domain || undefined,
      from: args.from || policy?.from_address || undefined, receivers: domains, timeout: Number(args.timeout) || 8000,
    });
    const verdicts = new Map(routeReport.projected.map((p) => [p.domain, p.verdict]));
    const esp = readJson(expandPath('config/esp.json'), {})?.accounts || [];
    const hasEsp = esp.some((a) => isRealSecret(a.api_key));
    const hasGraph = Boolean(readJson(expandPath('config/graph.json')));
    const usableRelays = relays.filter((r) => isRealSecret(r.user) && isRealSecret(r.pass || r.access_token));
    const directDomains = (policy?.direct_domains || ['gmail.com', 'googlemail.com']).map((d) => d.toLowerCase());
    const plan = rows.slice(0, Number(args.limit) || rows.length).map((r) => {
      const d = (r.email.split('@')[1] || '').toLowerCase();
      const verdict = verdicts.get(d) || 'unknown';
      return {
        email: r.email, receiver: d, verdict,
        path: choosePath({ verdict, grade: routeReport.grade, hasEsp, hasGraph, hasRelay: usableRelays.length > 0, allowDirect: directDomains.includes(d) || !directDomains.length }),
      };
    });
    console.table(plan);
    console.log(`route identity ${routeReport.score}/100 (${routeReport.grade}); esp=${hasEsp ? 'ready' : 'no'} graph=${hasGraph ? 'ready' : 'no'} relay=${usableRelays.length}`);
  }

  const blocked = report.projected.filter((p) => p.verdict === 'ip-blocked').map((p) => p.domain);  if (blocked.length) {
    console.log(`\nblocked at receiver: ${blocked.join(', ')}`);
    console.log('cheapest replacement identity: rank 1 M365 dev tenant + Graph ($0, 10k/day).');
    console.log('run: node src/cli.js identity --plan');
  }
  console.log('report: ' + out);
}

function cmdPool(args) {  const pool = new RelayPool({ stateFile: expandPath('state/pool.json'), relays: loadRelays(expandPath('config/relays.json')) });
  console.table(pool.stats());
  if (args._[0] === 'reset' || args.command === 'reset') { fs.writeFileSync(expandPath('state/pool.json'), '{"relays":{}}'); console.log('reset (relay ids recreated on next load)'); }
}

function cmdQueue(args) {
  const queue = new Queue({ dir: expandPath('data/queue') });
  const sub = args._[0] || args.command || 'stats';
  if (sub === 'stats') console.log(queue.stats());
  else if (sub === 'failed') console.table(queue.listFailed().map((j) => ({ email: j.email, attempts: j.attempts, reason: j.result?.reason })));
  else if (sub === 'held') console.table(queue.listHeld().map((j) => ({ email: j.email, reason: j.result?.reason, spam: j.result?.spam?.score })));
  else if (sub === 'release') {
    let n = 0;
    for (const job of queue.listHeld(1000)) { queue.release(job); n++; }
    console.log(`released ${n}`);
  }
  else if (sub === 'retry') {
    let n = 0;
    for (const job of queue.listFailed(1000)) { queue.requeue(job, 0); n++; }
    console.log(`requeued ${n}`);
  } else throw new Error('queue stats|failed|held|release|retry');
}

async function cmdDnsRecords(args) {
  const policy = loadPolicy();
  const domain = args.domain || policy.from_domain;
  const key = readJson(expandPath(`keys/${domain}.json`));
  const org = domain.split('.').slice(-2).join('.');
  console.log(`# Publish these (zone example.com; adjust if ${domain} is its own zone)\n`);
  console.log(`${domain}.        MX    10 ${domain}.`);
  console.log(`${domain}.        A     <sending IP>`);
  console.log(`${domain}.        TXT   "v=spf1 ip4:<sending IP> -all"`);
  if (key) console.log(`${key.selector}._domainkey.${domain}.  TXT  "${fs.readFileSync(expandPath(`keys/${domain}.pub`), 'utf8').trim()}"`);
  console.log(`_dmarc.${org}.       TXT   "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100; rua=mailto:dmarc@${org}"`);
  console.log(`_mta-sts.${domain}.   TXT   "v=STSv1; id=${Date.now().toString(36)}"`);
  console.log(`_smtp._tls.${domain}. TXT   "v=TLSRPTv1; rua=mailto:tlsrpt@${org}"`);
  console.log(`\n# PTR for <sending IP> -> ${domain}`);
  console.log(`\n# https://mta-sts.${domain}/.well-known/mta-sts.txt`);
  console.log(`version: STSv1\nmode: enforce\nmx: ${domain}\nmax_age: 86400`);
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  let args;
  try { args = parseArgs(rest); } catch (err) { if (err instanceof ParseArgsError) { console.error(err.message); process.exit(2); } throw err; }
  const table = {
    init: cmdInit, keys: cmdKeys, send: cmdSend, verify: cmdVerify, dnscheck: cmdDns,
    probe: cmdProbe, score: cmdScore, warmup: cmdWarmup, pool: cmdPool, queue: cmdQueue, 'dns-records': cmdDnsRecords,
    capacity: cmdCapacity, diagnose: cmdDiagnose, ratelimit: cmdRatelimit, mailtest: cmdMailtest, relaytest: cmdRelayTest, proxycheck: cmdProxycheck, graphtest: cmdGraphTest,
    espprobe: cmdEspProbe, espsend: cmdEspSend, graphdevice: cmdGraphDevice, identity: cmdIdentity,
  };
  if (!cmd || cmd === 'help' || args.help) { console.log(HELP); return; }
  const fn = table[cmd];
  if (!fn) { console.error(`unknown command ${cmd}\n` + HELP); process.exit(2); }
  await fn(args);
}

main().catch((err) => { console.error('ERROR:', err.message); if (process.env.DEBUG) console.error(err); process.exit(1); });
