import net from 'node:net';
import tls from 'node:tls';
import { resolvePtr, resolveA } from '../lib/dns.js';
import { spamhausLookup } from '../lib/spamhaus.js';

/**
 * Test whether a residential/HTTP proxy can carry SMTP. Most providers block
 * ports 25/465/587 to prevent spam; this returns the exact refusal so you do
 * not waste time wiring a proxy that cannot work.
 */
function httpConnect({ host, port, user, pass, target, targetPort, timeout = 10000 }) {
  return new Promise((resolve) => {
    const auth = 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64');
    const s = net.connect(port, host);
    let buf = '';
    let done = false;
    const end = (result) => { if (done) return; done = true; s.destroy(); resolve(result); };
    s.setTimeout(timeout, () => end({ ok: false, error: 'timeout' }));
    s.on('error', (e) => end({ ok: false, error: e.code || e.message }));
    s.on('connect', () => s.write(`CONNECT ${target}:${targetPort} HTTP/1.1\r\nHost: ${target}:${targetPort}\r\nProxy-Authorization: ${auth}\r\nProxy-Connection: keep-alive\r\n\r\n`));
    s.on('data', (d) => {
      buf += d.toString();
      if (!buf.includes('\r\n\r\n')) return;
      const status = buf.split('\r\n')[0];
      end({ ok: /^HTTP\/1\.[01] 200/.test(status), status });
    });
  });
}

function socksConnect({ host, port, user, pass, target, targetPort, timeout = 12000 }) {
  return new Promise((resolve) => {
    const s = net.connect(port, host);
    let buf = Buffer.alloc(0);
    let stage = 'greet';
    let done = false;
    const end = (result) => { if (done) return; done = true; s.destroy(); resolve(result); };
    s.setTimeout(timeout, () => end({ ok: false, error: 'timeout' }));
    s.on('error', (e) => end({ ok: false, error: e.code || e.message }));
    s.on('connect', () => s.write(Buffer.from([5, 2, 0, 2])));
    s.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 'greet') {
        if (buf.length < 2) return;
        if (buf[0] !== 5) return end({ ok: false, error: 'bad socks version' });
        const method = buf[1]; buf = buf.slice(2);
        if (method === 2) {
          const u = Buffer.from(user); const p = Buffer.from(pass);
          s.write(Buffer.concat([Buffer.from([1, u.length]), u, Buffer.from([p.length]), p]));
          stage = 'auth';
        } else if (method === 0) { stage = 'connect'; sendConnect(); }
        else return end({ ok: false, error: `auth method ${method}` });
      } else if (stage === 'auth') {
        if (buf.length < 2) return;
        if (buf[1] !== 0) return end({ ok: false, error: `auth failed ${buf[1]}` });
        buf = buf.slice(2); stage = 'connect'; sendConnect();
      } else if (stage === 'connect') {
        if (buf.length < 10) return;
        const rep = buf[1];
        end({ ok: rep === 0, reply: rep, error: rep === 0 ? null : socksError(rep) });
      }
    });
    function sendConnect() {
      const h = Buffer.from(target);
      const b = Buffer.alloc(5 + h.length + 2);
      b[0] = 5; b[1] = 1; b[2] = 0; b[3] = 3; b[4] = h.length;
      h.copy(b, 5); b.writeUInt16BE(targetPort, 5 + h.length);
      s.write(b);
    }
  });
}

function socksError(rep) {
  return ({ 1: 'general failure', 2: 'connection not allowed by ruleset', 3: 'network unreachable', 4: 'host unreachable', 5: 'connection refused', 6: 'TTL expired', 7: 'command not supported', 8: 'address type not supported' })[rep] || `rep=${rep}`;
}

function httpsJson({ host, port, user, pass, target, path = '/', timeout = 15000 }) {
  return new Promise((resolve) => {
    const auth = 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64');
    const s = net.connect(port, host);
    let stage = 'connect';
    let buf = Buffer.alloc(0);
    let done = false;
    const end = (result) => { if (done) return; done = true; try { s.destroy(); } catch { /* */ } resolve(result); };
    s.setTimeout(timeout, () => end({ ok: false, error: 'timeout' }));
    s.on('error', (e) => end({ ok: false, error: e.code || e.message }));
    s.on('connect', () => s.write(`CONNECT ${target}:443 HTTP/1.1\r\nHost: ${target}:443\r\nProxy-Authorization: ${auth}\r\n\r\n`));
    s.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 'connect') {
        const idx = buf.indexOf('\r\n\r\n');
        if (idx === -1) return;
        const head = buf.slice(0, idx).toString();
        if (!/^HTTP\/1\.[01] 200/.test(head)) return end({ ok: false, error: head.split('\r\n')[0] });
        const rest = buf.slice(idx + 4);
        stage = 'tls';
        const t = tls.connect({ socket: s, servername: target, rejectUnauthorized: false }, () => {
          t.write(`GET ${path} HTTP/1.1\r\nHost: ${target}\r\nAccept: application/json\r\nConnection: close\r\n\r\n`);
        });
        if (rest.length) t.unshift(rest);
        let body = '';
        t.on('data', (x) => { body += x.toString(); });
        t.on('error', (e) => end({ ok: false, error: e.message }));
        t.on('end', () => {
          const text = body.slice(body.indexOf('\r\n\r\n') + 4);
          try { end({ ok: true, json: JSON.parse(text) }); } catch { end({ ok: false, error: 'bad json', body: text.slice(0, 200) }); }
        });
      }
    });
  });
}

export async function proxycheck({ host, httpPort = 7777, socksPort = 10000, user, pass, timeout = 10000 }) {
  const targets = [
    ['gmail-smtp-in.l.google.com', 25],
    ['outlook-com.olc.protection.outlook.com', 25],
    ['smtp.gmail.com', 587],
    ['smtp.sendgrid.net', 587],
    ['smtp.gmail.com', 465],
  ];
  const http = [];
  for (const [target, port] of targets) {
    http.push({ target, port, ...(await httpConnect({ host, port: httpPort, user, pass, target, targetPort: port, timeout })) });
  }
  const socks = [];
  for (const [target, port] of targets.slice(0, 3)) {
    socks.push({ target, port, ...(await socksConnect({ host, port: socksPort, user, pass, target, targetPort: port, timeout: timeout + 2000 })) });
  }

  const egressRes = await httpsJson({ host, port: httpPort, user, pass, target: 'ip.oxylabs.io', path: '/location', timeout: timeout + 5000 });
  const ip = egressRes.json?.ip || null;
  let egress = { ok: egressRes.ok, ip, error: egressRes.error || null };
  if (ip) {
    const ptr = await resolvePtr(ip);
    const fcrdns = ptr.length ? (await resolveA(ptr[0])).includes(ip) : false;
    const sh = await spamhausLookup(ip);
    egress = { ...egress, ptr, fcrdns, spamhaus: sh.lists || [], org: egressRes.json?.providers?.ipinfo?.org_name || null };
  }

  return {
    proxy: { host, httpPort, socksPort },
    egress,
    http,
    socks,
    smtpUsable: http.some((r) => r.ok) || socks.some((r) => r.ok),
    verdict: (http.some((r) => r.ok) || socks.some((r) => r.ok))
      ? 'SMTP port open through proxy; check the exit IP reputation before sending.'
      : `SMTP blocked by proxy policy (expected on residential plans). HTTPS works${ip ? ` (exit ${ip})` : ''}; use the proxy only for HTTPS APIs.`,
  };
}
