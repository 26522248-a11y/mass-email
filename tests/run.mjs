import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import http from 'node:http';
import { RelayPool, RelayGuard } from '../src/core/pool.js';
import { Queue } from '../src/core/queue.js';
import { sendJob } from '../src/core/sender.js';
import { generateKeypair, signMessage, verifyMessage, canonicalBody, bodyHash } from '../src/lib/dkim.js';
import { buildMessage, render, rngFor, expandSpintax } from '../src/lib/mime.js';
import { parseArgs } from '../src/lib/args.js';
import { parseMailTester } from '../src/core/mailtester.js';
import { buildGraphPayload, sendGraphJob } from '../src/core/graph.js';
import { buildEspRequest, sendEspJob, EspPool, getProvider } from '../src/core/esp.js';
import { scoreIdentity, choosePath, isRealSecret } from '../src/core/identity.js';
import { startMockSmtp } from './mock-smtp.mjs';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mass-email-test-'));
const keysDir = path.join(tmp, 'keys');
fs.mkdirSync(keysDir, { recursive: true });
let passed = 0;
const test = (name, fn) => { fn(); passed++; console.log('ok -', name); };
const testAsync = async (name, fn) => { await fn(); passed++; console.log('ok -', name); };

const policy = {
  from_name: 'Test Brand', from_address: 'news@test.local', from_domain: 'test.local',
  reply_to: 'reply@test.local', return_path: 'bounce@test.local', return_path_domain: 'test.local',
  unsubscribe_mailto: 'unsub@test.local', unsubscribe_url: 'https://test.local/u/{{token}}',
  one_click_unsubscribe: true, helo_host: 'test.local', subject: 'Quick note for {{name}}',
  headers: { 'X-Entity-Ref-ID': true, 'Feedback-ID': 'c:1', Precedence: 'bulk' },
  spamscore: { fail_over: 20, warn_over: 10 }, retry: { throttle_cooldown_seconds: 1, max_attempts: 3, schedule_seconds: [0] },
};
const templates = {
  text: 'Hi {{name}},\n\nThis is a real paragraph with enough words to look like a normal message. Read more: {{url}}\n\nUnsubscribe: {{unsubscribe}}\n',
  html: '<html><body><p>Hi {{name}}, this is a real paragraph with enough words to look like a normal message.</p><p><a href="{{url}}">Read more</a></p><p><a href="{{unsubscribe}}">Unsubscribe</a></p></body></html>',
};
const key = generateKeypair(2048);
fs.writeFileSync(path.join(keysDir, 'test.local.json'), JSON.stringify({ selector: 's1', privateKey: key.privateKey }));
const keys = { 'test.local': { selector: 's1', privateKey: key.privateKey } };

test('spintax picks and nests deterministically', () => {
  const a = expandSpintax('{a|b} {x|{y|z}}', rngFor('seed'));
  const b = expandSpintax('{a|b} {x|{y|z}}', rngFor('seed'));
  assert.equal(a, b);
  assert.match(a, /^[ab] [xyz]$/);
});

test('message builds CRLF, encoded subject, unsubscribe headers', () => {
  const row = { email: 'u@example.com', name: 'Ünïcode', token: 't1' };
  const rng = rngFor('m1');
  const msg = buildMessage({
    row, subject: render(policy.subject, row, rng), text: render(templates.text, row, rng), html: null,
    policy, fromName: policy.from_name, from: policy.from_address, replyTo: policy.reply_to,
    unsubscribeMailto: policy.unsubscribe_mailto, token: 't1', domain: 'test.local',
  });
  assert.match(msg.raw, /^From: Test Brand <news@test.local>\r\n/);
  assert.match(msg.raw, /List-Unsubscribe-Post: List-Unsubscribe=One-Click/);
  assert.match(msg.raw, /Subject: =\?UTF-8\?B\?/);
  assert.match(msg.raw, /\r\n\r\n/);
  assert.ok(!/[^\r]\n/.test(msg.raw), 'no bare LF');
});

test('DKIM signs and verifies; tamper breaks body hash', () => {
  const body = 'Hello world\r\nsecond line\r\n';
  const headers = [['From', 'a@test.local'], ['To', 'b@example.com'], ['Subject', 'x'], ['Date', 'Wed, 25 Nov 2026 00:00:00 +0000'], ['Message-ID', '<1@test.local>'], ['MIME-Version', '1.0'], ['Content-Type', 'text/plain']];
  const sig = signMessage({ rawHeaders: headers, body, domain: 'test.local', selector: 's1', privateKey: key.privateKey });
  const raw = [sig, ...headers.map(([n, v]) => `${n}: ${v}`)].join('\r\n') + '\r\n\r\n' + body;
  const res = verifyMessage({ raw, dnsRecord: key.dns });
  assert.equal(res.ok, true);
  const tampered = raw.replace('Hello world', 'Hello there');
  assert.equal(verifyMessage({ raw: tampered, dnsRecord: key.dns }).bodyHash, false);
  assert.equal(bodyHash(body), res.tags.bh);
  assert.equal(canonicalBody('a \r\n\r\n\r\n'), 'a\r\n');
});

test('args parse flags and values', () => {
  const a = parseArgs(['--list', 'x.csv', '--dry-run', '--target=gmail.com']);
  assert.equal(a.list, 'x.csv'); assert.equal(a['dry-run'], true); assert.equal(a.target, 'gmail.com');
});

test('mail-tester parser extracts score, auth and blocklists', () => {
  const html = `<html><body>Score : 7/10 Subject : Hello Received 1 minute ago
    X-Spam-Status: No/1.5/5.0 X-Spam-Test-Scores: SPF_NONE=0.1,DKIM_INVALID=0.1 X-Spam-Report: ...
    Authentication-Results: mx; dkim=fail header.d=example.com
    Matches your server IP address ( 203.0.113.9 ) against 20 blocklists.
    Not listed in Spamhaus SBL Advisory Listed in Barracuda ( -0.5 ) Not listed in SPAMCOP Truncate
    </body></html>`;
  const r = parseMailTester(html);
  assert.equal(r.score, '7');
  assert.equal(r.spamAssassin, 'No/1.5/5.0');
  assert.deepEqual(r.blacklists, ['Barracuda']);
  assert.match(r.auth[0], /dkim=fail/);
});

test('graph payload has recipient, sender and one-click unsubscribe', () => {
  const p = buildGraphPayload({
    job: { id: 'g1', email: 'dest@example.com', row: { email: 'dest@example.com', name: 'Ann', token: 't1' } },
    policy: { ...policy, from_address: 'news@test.local', from_domain: 'test.local' },
    templates, sender: 'news@test.local',
  });
  assert.equal(p.message.toRecipients[0].emailAddress.address, 'dest@example.com');
  assert.equal(p.message.from.emailAddress.address, 'news@test.local');
  assert.ok(p.message.internetMessageHeaders.some((h) => h.name === 'List-Unsubscribe-Post'));
});

await testAsync('sendJob delivers through pool, DKIM intact, dot-stuffed', async () => {
  const server = await startMockSmtp();
  const pool = new RelayPool({
    stateFile: path.join(tmp, 'pool.json'),
    relays: [{ id: 'mock', kind: 'generic', host: '127.0.0.1', port: server.port, from: 'news@test.local', domain: 'test.local', max_per_hour: 100, max_concurrent: 2 }],
  });
  const guard = new RelayGuard(pool);
  const job = { id: 'job1', email: 'dest@example.com', row: { email: 'dest@example.com', name: 'Ann', token: 't9' }, attempts: 1 };
  const result = await sendJob({ job, pool, guard, policy, templates, keys, timeout: 5000 });
  assert.equal(result.status, 'sent', JSON.stringify(result));
  assert.equal(server.messages.length, 1);
  const msg = server.messages[0];
  assert.match(msg.raw, /DKIM-Signature: v=1;/);
  const vr = verifyMessage({ raw: msg.raw, dnsRecord: key.dns });
  assert.equal(vr.ok, true);
  assert.equal(msg.rcpts[0], 'dest@example.com');
  assert.match(msg.raw, /X-Entity-Ref-ID: [0-9a-f]{32}/);
  assert.equal(pool.stats()[0].sentHour, 1);
  // 550 recipient turns into bounce, not retry
  const bad = { id: 'job2', email: 'bad@example.com', row: { email: 'bad@example.com' }, attempts: 1 };
  const r2 = await sendJob({ job: bad, pool, guard, policy, templates, keys, timeout: 5000 });
  assert.equal(r2.status, 'bounced');
  await server.close();
});

await testAsync('queue leases, recovers and completes', async () => {  const q = new Queue({ dir: path.join(tmp, 'queue') });
  const job = q.add({ email: 'q@example.com' });
  assert.deepEqual(q.stats().pending, 1);
  const leased = q.lease(5);
  assert.equal(leased.length, 1);
  assert.equal(leased[0].attempts, 1);
  q.complete(leased[0], { status: 'sent' });
  assert.equal(q.stats().done, 1);
  // lock recovery
  const job2 = q.add({ email: 'q2@example.com' });
  const l2 = q.lease(5);
  const file = path.join(tmp, 'queue', 'pending', `${job2.id}.json`);
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  raw.leaseUntil = 0;
  fs.writeFileSync(file, JSON.stringify(raw));
  const q2 = new Queue({ dir: path.join(tmp, 'queue') });
  assert.equal(q2.stats().pending, 1);
  assert.ok(l2.length >= 1);
});

await testAsync('graph sends through mock token + sendMail endpoints', async () => {
  let sentBody = null;
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (d) => { body += d; });
    req.on('end', () => {
      if (req.url === '/token') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ access_token: 'tok', expires_in: 3600 }));
        return;
      }
      if (req.url.includes('/sendMail')) {
        sentBody = JSON.parse(body);
        res.writeHead(202); res.end();
        return;
      }
      res.writeHead(404); res.end();
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const cfg = { tenant_id: 't', client_id: 'c', client_secret: 's', sender: 'news@test.local', token_url: `http://127.0.0.1:${port}/token`, base_url: `http://127.0.0.1:${port}` };
  const job = { id: 'g2', email: 'dest@example.com', row: { email: 'dest@example.com', name: 'Ann', token: 't2' } };
  const r = await sendGraphJob({ job, policy: { ...policy, from_address: 'news@test.local', from_domain: 'test.local' }, templates, cfg });
  assert.equal(r.status, 'sent');
  assert.ok(sentBody.message.subject.length > 0);
  await new Promise((r2) => server.close(r2));
});

test('esp payload adapters address the recipient and set auth', () => {
  const job = { id: 'e1', email: 'dest@example.com', row: { email: 'dest@example.com', name: 'Ann', token: 't1' } };
  const p = { ...policy, from_address: 'news@test.local', from_domain: 'test.local' };
  for (const id of ['brevo', 'sendgrid', 'mailjet', 'elasticemail', 'smtp2go', 'resend', 'mailersend']) {
    const req = buildEspRequest({ provider: id, job, policy: p, templates, cfg: { api_key: 'k', secret: 's', from: 'news@test.local' } });
    const json = JSON.stringify(req.json);
    assert.ok(json.includes('dest@example.com'), `${id} recipient`);
    assert.ok(json.includes('Quick note for Ann'), `${id} subject`);
    assert.ok(json.includes('List-Unsubscribe'), `${id} unsubscribe`);
    assert.ok(req.headers['content-type'] === 'application/json', `${id} json header`);
    assert.ok(Object.keys(req.headers).length >= 2, `${id} auth header`);
  }
  assert.equal(getProvider('brevo').domain_required, false);
});

await testAsync('espsend posts to the API and drains quota', async () => {
  let received = null;
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (d) => { body += d; });
    req.on('end', () => { received = { url: req.url, body: JSON.parse(body), auth: req.headers.authorization || req.headers['api-key'] }; res.writeHead(202, { 'content-type': 'application/json' }); res.end('{"messageId":"m1"}'); });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const account = { id: 'sg-test', provider: 'sendgrid', api_key: 'SG.test', from: 'news@test.local', daily_limit: 1, url: `http://127.0.0.1:${port}/v3/mail/send` };
  const job = { id: 'e2', email: 'dest@example.com', row: { email: 'dest@example.com', name: 'Ann', token: 't2' } };
  const r = await sendEspJob({ job, policy: { ...policy, from_address: 'news@test.local' }, templates, cfg: account });
  assert.equal(r.status, 'sent', JSON.stringify(r));
  assert.equal(received.auth, 'Bearer SG.test');
  assert.equal(received.body.personalizations[0].to[0].email, 'dest@example.com');

  const pool = new EspPool({ accounts: [account], stateFile: path.join(tmp, 'esp.json') });
  pool.markSent(account);
  assert.equal(pool.remaining(account), 0);
  assert.equal(pool.pick(), null);
  await new Promise((r2) => server.close(r2));
});

test('identity scoring detects blockers and clean identity grades A', () => {
  const bad = scoreIdentity({
    ip: '203.0.113.9', ptr: [], fcrdns: false,
    spamhaus: { listed: true, lists: [{ list: 'SBL CSS', meaning: 'spam source' }, { list: 'PBL CSS', meaning: 'dynamic' }] },
    spf: null, spfAll: null, dkimBits: 0, dmarc: null, dmarcPolicy: null,
  });
  assert.equal(bad.score, 0);
  assert.equal(bad.grade, 'F');
  assert.ok(bad.blockers.some((b) => b.id === 'no-ptr'));
  assert.ok(bad.fixes.length >= 4);

  const good = scoreIdentity({
    ip: '203.0.113.9', ptr: ['mail.good.test'], fcrdns: true,
    spamhaus: { listed: false, lists: [] },
    spf: 'v=spf1 include:esp.test -all', spfAll: '-all', dkimBits: 2048,
    dmarc: 'v=DMARC1; p=reject', dmarcPolicy: 'reject',
  });
  assert.equal(good.score, 100);
  assert.equal(good.grade, 'A');
  assert.equal(good.blockers.length, 0);
});

test('smart routing never sends direct into a blocked receiver', () => {
  assert.equal(choosePath({ verdict: 'ip-blocked', grade: 'F', hasEsp: true, hasGraph: true, hasRelay: true }), 'esp');
  assert.equal(choosePath({ verdict: 'ip-blocked', grade: 'F', hasEsp: false, hasGraph: true, hasRelay: true }), 'graph');
  assert.equal(choosePath({ verdict: 'ip-blocked', grade: 'F', hasEsp: false, hasGraph: false, hasRelay: true }), 'relay');
  assert.equal(choosePath({ verdict: 'ip-blocked', grade: 'F', hasEsp: false, hasGraph: false, hasRelay: false }), 'none');
  // accepted at protocol level but identity grade F => still not direct (would land in spam)
  assert.equal(choosePath({ verdict: 'accepted', grade: 'F', hasEsp: true }), 'esp');
  assert.equal(choosePath({ verdict: 'accepted', grade: 'B', hasEsp: true }), 'direct');
  assert.equal(choosePath({ verdict: 'no-mx', grade: 'A', hasRelay: true }), 'relay');
});

test('placeholder credentials are not counted as ready identities', () => {
  assert.equal(isRealSecret('AKIA...'), false);
  assert.equal(isRealSecret('BASE64_SMTP_PASSWORD'), false);
  assert.equal(isRealSecret('app-password'), false);
  assert.equal(isRealSecret('SG.realLookingKey123'), true);
  assert.equal(isRealSecret('xkeysib-abc123def456'), true);
});

test('CLI dry run renders and exits clean', () => {
  const out = execFileSync(process.execPath, ['src/cli.js', 'send', '--list', 'tests/fixtures/list.csv', '--text', 'templates/newsletter.txt', '--html', 'templates/newsletter.html', '--dry-run', '--yes'], { cwd: path.join(import.meta.dirname, '..'), encoding: 'utf8' });
  assert.match(out, /DKIM-Signature/);
  assert.match(out, /List-Unsubscribe/);
});

console.log(`\n${passed} tests passed`);
