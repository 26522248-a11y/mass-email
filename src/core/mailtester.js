import { sendDirectJob } from './mxdeliver.js';
import { sendJob } from './sender.js';
import { randomLocal } from '../lib/util.js';
import fs from 'node:fs';
import path from 'node:path';

function decode(html) {
  return html.replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ').replace(/&nbsp;|&#160;/g, ' ').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/\s+/g, ' ');
}

export function parseMailTester(html) {
  const text = decode(html);
  const checks = {};
  checks.score = /Score\s*:\s*(\d+)\s*\/\s*10/i.exec(text)?.[1] ?? null;
  checks.subject = /Subject\s*:\s*(.{0,120}?)\s*Received/i.exec(text)?.[1]?.trim() || null;
  checks.spamAssassin = (/X-Spam-Status:\s*([\s\S]{0,260}?)(?:\s+X-Spam-|\s+X-Spam-Report|$)/i.exec(text)?.[1] || '').trim() || null;
  checks.spamTests = /X-Spam-Test-Scores:\s*([^X]{0,400})/i.exec(text)?.[1]?.trim() || null;
  checks.auth = [...text.matchAll(/Authentication-Results:[^\[]{0,260}/gi)].map((m) => m[0].trim()).slice(0, 4);
  checks.spf = /Received-SPF:\s*([^\[]{0,240})/i.exec(text)?.[1]?.trim() || null;
  const rbl = /Matches your server IP address([\s\S]{0,1800}?)(?:Truncate|Export as PDF|$)/i.exec(text)?.[1] || '';
  checks.rblSummary = rbl ? rbl.replace(/\s+/g, ' ').trim().slice(0, 1200) : null;
  checks.blacklists = [...rbl.matchAll(/(?:^|\s)Listed in ([A-Za-z0-9][A-Za-z0-9 ._-]{1,40}?)\s*\(/g)]
    .map((m) => m[1].trim()).filter((v) => !/^the\b/i.test(v)).slice(0, 10);
  return checks;
}

/** Read an existing report without sending (id is the part after /test-). */
export async function readMailTester(id, { root, attempts = 10, waitMs = 6000 } = {}) {
  let html = '';
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(`https://mail-tester.com/test-${id}`, { headers: { 'user-agent': 'Mozilla/5.0 Chrome/126' }, signal: AbortSignal.timeout(20000) });
      html = await res.text();
      if (/Score\s*:\s*\d+\s*\/\s*10/i.test(decode(html))) break;
    } catch { /* retry */ }
    if (i < attempts - 1) await new Promise((r) => setTimeout(r, waitMs));
  }
  if (root && html) {
    const dir = path.join(root, 'reports');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, `mailtester-${id}.html`), html);
  }
  return parseMailTester(html);
}

/**
 * End-to-end deliverability check against mail-tester.com: fresh address,
 * one message, then read the public 0-10 report.
 */
export async function runMailTester({ policy, templates, keys, pool, guard, pathMode = 'direct', logger, root }) {
  const id = randomLocal(9);
  const email = `test-${id}@srv1.mail-tester.com`;
  const job = { id: `mt-${id}`, email, row: { email, name: 'Test', token: id, url: policy.link_url || 'https://example.com' } };

  const send = pathMode === 'relay'
    ? await sendJob({ job, pool, guard, policy, templates, keys, logger })
    : await sendDirectJob({ job, policy, templates, keys, logger });

  const report = { id, email, sentAt: new Date().toISOString(), send, checks: {} };
  if (send.status !== 'sent') return report;
  report.checks = await readMailTester(id, { root, attempts: 15 });
  return report;
}
