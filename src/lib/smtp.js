/**
 * SMTP client: raw socket, STARTTLS, AUTH PLAIN/LOGIN, PIPELINING.
 * Gives full control over EHLO name, envelope sender and per-command timing,
 * which library SMTP clients hide. Needed both to send bulk mail and to probe
 * receiver behaviour.
 */
import net from 'node:net';
import tls from 'node:tls';

const MULTILINE = /^\d{3}-/;
const FINAL = /^\d{3} /;

export class SmtpError extends Error {
  constructor(message, code, reply) {
    super(message);
    this.name = 'SmtpError';
    this.code = code;
    this.reply = reply;
  }
}

export class SmtpClient {
  constructor({ host, port = 587, servername, timeout = 20000, log = () => {} }) {
    this.host = host;
    this.port = port;
    this.servername = servername || host;
    this.timeout = timeout;
    this.log = log;
    this.socket = null;
    this.buffer = '';
    this.replies = [];
    this.waiters = [];
    this.closed = false;
    this.capabilities = new Map();
  }

  connect({ secure = false } = {}) {
    return new Promise((resolve, reject) => {
      const onError = (err) => { this.closed = true; reject(err); };
      this.socket = secure
        ? tls.connect({ host: this.host, port: this.port, servername: this.servername, rejectUnauthorized: false })
        : net.connect({ host: this.host, port: this.port });
      this.socket.setTimeout(this.timeout, () => this.socket.destroy(new Error('socket timeout')));
      this.socket.once('connect', () => resolve());
      this.socket.once('error', onError);
      this.socket.on('data', (chunk) => this.onData(chunk));
      this.socket.once('close', () => { this.closed = true; this.flushWaiters(new SmtpError('connection closed')); });
    });
  }

  onData(chunk) {
    this.buffer += chunk.toString('utf8');
    let idx;
    while ((idx = this.buffer.indexOf('\r\n')) !== -1) {
      const line = this.buffer.slice(0, idx);
      this.buffer = this.buffer.slice(idx + 2);
      this.replies.push(line);
    }
    this.drain();
  }

  drain() {
    while (this.waiters.length) {
      const finalIdx = this.replies.findIndex((l) => FINAL.test(l));
      if (finalIdx === -1) return;
      const lines = this.replies.slice(0, finalIdx + 1);
      this.replies = this.replies.slice(finalIdx + 1);
      const waiter = this.waiters.shift();
      clearTimeout(waiter.timer);
      waiter.resolve({ code: Number(lines.at(-1).slice(0, 3)), lines, text: lines.join('\n') });
    }
  }

  flushWaiters(err) {
    while (this.waiters.length) {
      const w = this.waiters.shift();
      clearTimeout(w.timer);
      w.reject(err);
    }
  }

  readReply() {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new SmtpError('reply timeout')), this.timeout);
      this.waiters.push({ resolve, reject, timer });
      this.drain();
    });
  }

  async cmd(line, { redact = false } = {}) {
    this.log(`C: ${redact ? redactSecret(line) : line}`);
    this.socket.write(line + '\r\n');
    const reply = await this.readReply();
    this.log(`S: ${reply.text.replace(/\n/g, ' | ')}`);
    return reply;
  }

  async greet(heloHost) {
    const banner = await this.readReply();
    const reply = await this.cmd(`EHLO ${heloHost}`);
    if (reply.code !== 250) {
      const alt = await this.cmd(`HELO ${heloHost}`);
      if (alt.code !== 250) throw new SmtpError('EHLO/HELO rejected', alt.code, alt.text);
      return { banner, reply: alt };
    }
    this.capabilities = parseCaps(reply.lines);
    return { banner, reply };
  }

  supports(cap) { return this.capabilities.has(cap.toUpperCase()); }

  async starttls(heloHost) {
    const reply = await this.cmd('STARTTLS');
    if (reply.code !== 220) throw new SmtpError('STARTTLS rejected', reply.code, reply.text);
    this.socket.removeAllListeners('data');
    this.socket = tls.connect({ socket: this.socket, servername: this.servername, rejectUnauthorized: false });
    this.buffer = '';
    this.replies = [];
    this.waiters = [];
    await new Promise((resolve, reject) => {
      this.socket.once('secureConnect', resolve);
      this.socket.once('error', reject);
      this.socket.setTimeout(this.timeout, () => this.socket.destroy(new Error('tls timeout')));
    });
    this.socket.on('data', (chunk) => this.onData(chunk));
    const reply2 = await this.cmd(`EHLO ${heloHost}`);
    if (reply2.code !== 250) throw new SmtpError('EHLO after TLS rejected', reply2.code, reply2.text);
    this.capabilities = parseCaps(reply2.lines);
  }

  async auth(user, pass, method = 'PLAIN') {
    const mech = this.capabilities.get('AUTH') || '';
    if (method === 'XOAUTH2' || (!mech.toUpperCase().includes('PLAIN') && mech.toUpperCase().includes('XOAUTH2'))) {
      const token = Buffer.from(`user=${user}\u0001auth=Bearer ${pass}\u0001\u0001`).toString('base64');
      const r = await this.cmd(`AUTH XOAUTH2 ${token}`, { redact: true });
      if (r.code !== 235) throw new SmtpError('AUTH XOAUTH2 failed', r.code, r.text);
      return r;
    }
    const chosen = mech.toUpperCase().includes(method) ? method : (mech.toUpperCase().includes('LOGIN') ? 'LOGIN' : 'PLAIN');
    if (chosen === 'PLAIN') {
      const token = Buffer.from(`\u0000${user}\u0000${pass}`).toString('base64');
      const r = await this.cmd(`AUTH PLAIN ${token}`, { redact: true });
      if (r.code !== 235) throw new SmtpError('AUTH PLAIN failed', r.code, r.text);
      return r;
    }
    const r1 = await this.cmd('AUTH LOGIN');
    if (r1.code !== 334) throw new SmtpError('AUTH LOGIN not accepted', r1.code, r1.text);
    const r2 = await this.cmd(Buffer.from(user).toString('base64'));
    if (r2.code !== 334) throw new SmtpError('AUTH username rejected', r2.code, r2.text);
    const r3 = await this.cmd(Buffer.from(pass).toString('base64'));
    if (r3.code !== 235) throw new SmtpError('AUTH password rejected', r3.code, r3.text);
    return r3;
  }

  async mailFrom(from, params = []) {
    const suffix = params.length ? ' ' + params.join(' ') : '';
    return this.cmd(`MAIL FROM:<${from}>${suffix}`);
  }

  async rcptTo(to, params = []) {
    const suffix = params.length ? ' ' + params.join(' ') : '';
    return this.cmd(`RCPT TO:<${to}>${suffix}`);
  }

  async data(raw) {
    const r = await this.cmd('DATA');
    if (r.code !== 354) throw new SmtpError('DATA rejected', r.code, r.text);
    const payload = dotStuff(raw).replace(/\r?\n/g, '\r\n');
    this.socket.write(payload + (payload.endsWith('\r\n') ? '' : '\r\n') + '.\r\n');
    const done = await this.readReply();
    if (done.code !== 250) throw new SmtpError('message rejected', done.code, done.text);
    return done;
  }

  async quit() {
    try { if (!this.closed) { await this.cmd('QUIT'); } } catch { /* ignore */ }
    this.socket?.end();
  }

  destroy() { try { this.socket?.destroy(); } catch { /* ignore */ } }
}

function parseCaps(lines) {
  const caps = new Map();
  for (const line of lines) {
    if (!/^\d{3}[ -]/.test(line)) continue;
    const body = line.slice(4).trim();
    if (!body) continue;
    const [key, ...rest] = body.split(/\s+/);
    caps.set(key.toUpperCase(), rest.join(' '));
  }
  return caps;
}

function redactSecret(line) {
  return line
    .replace(/(AUTH PLAIN\s+)\S+/i, '$1***')
    .replace(/(AUTH XOAUTH2\s+)\S+/i, '$1***')
    .replace(/(AUTH LOGIN.*)/i, '$1');
}

export function dotStuff(s) {
  return s.replace(/(^|\r?\n)\./g, '$1..');
}

export async function transact(opts) {
  const client = new SmtpClient(opts);
  try {
    await client.connect({ secure: opts.secure });
    const greeted = await client.greet(opts.heloHost);
    if (!opts.secure && opts.starttls !== false && client.supports('STARTTLS')) {
      await client.starttls(opts.heloHost);
    }
    if (opts.user) await client.auth(opts.user, opts.pass, opts.authMethod);
    return { client, greeted };
  } catch (err) {
    client.destroy();
    throw err;
  }
}
