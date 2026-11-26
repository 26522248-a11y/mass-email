import crypto from 'node:crypto';

const LINE = '\r\n';

export function generateKeypair(bits = 2048) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: bits,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const der = crypto.createPublicKey(publicKey).export({ type: 'spki', format: 'der' });
  return {
    privateKey,
    publicKey,
    dns: `v=DKIM1; k=rsa; p=${der.toString('base64')}`,
    selectorHint: 's1',
  };
}

export function relaxedHeader(name, value) {
  return `${name.toLowerCase().trim()}:${String(value)
    .replace(/\r?\n[ \t]+/g, ' ')
    .replace(/[ \t]+/g, ' ')
    .trim()}`;
}

export function canonicalBody(body) {
  const normalized = String(body).replace(/\r?\n/g, '\n');
  const lines = normalized.split('\n').map((l) => l.replace(/[ \t]+$/g, '').replace(/[ \t]+/g, ' '));
  let out = lines.join(LINE);
  out = out.replace(/(\r\n)+$/, '');
  return out + LINE;
}

export function bodyHash(body, algorithm = 'sha256') {
  return crypto.createHash(algorithm).update(canonicalBody(body), 'utf8').digest('base64');
}

/**
 * Sign an already-serialized message. `rawHeaders` is an array of [name, value]
 * in the order they appear in the message. `signedHeaders` defaults to a safe set
 * that always includes From/To/Subject/Date/Message-ID.
 */
export function signMessage({ rawHeaders, body, domain, selector, privateKey, signedHeaders, algorithm = 'sha256' }) {
  const names = (signedHeaders || ['From', 'To', 'Subject', 'Date', 'Message-ID', 'MIME-Version', 'Content-Type', 'List-Unsubscribe', 'List-Unsubscribe-Post'])
    .map((n) => n.toLowerCase());
  const present = new Set(rawHeaders.map(([n]) => n.toLowerCase()));
  const hList = names.filter((n) => present.has(n));
  if (!hList.includes('from')) hList.unshift('from');

  const bh = bodyHash(body, algorithm);
  const ts = Math.floor(Date.now() / 1000);
  const tag = `v=1; a=rsa-${algorithm}; c=relaxed/relaxed; d=${domain}; s=${selector}; t=${ts}; h=${hList.join(':')}; bh=${bh}; b=`;

  const headerEntries = rawHeaders.map(([n, v]) => [n.toLowerCase(), v]);
  const headerIndex = new Map();
  for (const [n, v] of headerEntries) {
    if (!headerIndex.has(n)) headerIndex.set(n, []);
    headerIndex.get(n).push(v);
  }

  const chunks = [relaxedHeader('DKIM-Signature', tag)];
  for (const name of hList) {
    const values = headerIndex.get(name);
    if (!values || !values.length) continue;
    // Sign the last occurrence, matching most receivers' expectation for single headers.
    chunks.push(relaxedHeader(name, values[values.length - 1]));
  }
  const toSign = chunks.join(LINE) + LINE;

  const signature = crypto.sign(`RSA-${algorithm.toUpperCase()}`, Buffer.from(toSign, 'utf8'), privateKey).toString('base64');
  const folded = foldSignature(`${tag}${signature}`);
  return `DKIM-Signature: ${folded}`;
}

function foldSignature(value) {
  const parts = value.split(';').map((s) => s.trim());
  const lines = [];
  let current = '';
  for (const part of parts) {
    const piece = part + ';';
    if ((current + ' ' + piece).length > 74 && current) {
      lines.push(current);
      current = ' ' + piece;
    } else {
      current = current ? current + ' ' + piece : piece;
    }
  }
  if (current) lines.push(current);
  return lines.join(LINE).replace(/;$/, '');
}

export function verifyMessage({ raw, dnsRecord }) {
  const split = raw.indexOf('\r\n\r\n');
  if (split === -1) return { ok: false, reason: 'no header/body split' };
  const headerText = raw.slice(0, split);
  const body = raw.slice(split + 4);
  const headers = unfold(headerText);
  const sig = headers.find(([n]) => n.toLowerCase() === 'dkim-signature');
  if (!sig) return { ok: false, reason: 'no signature' };
  const tags = parseTags(sig[1]);
  const hList = (tags.h || '').split(':').filter(Boolean);
  const signed = [relaxedHeader('DKIM-Signature', sig[1].replace(/b=[^;]*/, 'b='))];
  for (const name of hList) {
    const values = headers.filter(([n]) => n.toLowerCase() === name);
    if (values.length) signed.push(relaxedHeader(name, values.at(-1)[1]));
  }
  const hash = crypto.createHash('sha256').update(canonicalBody(body)).digest('base64');
  const key = publicKeyFromRecord(dnsRecord);
  const ok = crypto.verify('RSA-SHA256', Buffer.from(signed.join(LINE) + LINE), key, Buffer.from(tags.b, 'base64'));
  return { ok: ok && hash === tags.bh, bodyHash: hash === tags.bh, signature: ok, tags };
}

export function publicKeyFromRecord(record) {
  const value = String(record);
  if (value.includes('BEGIN PUBLIC KEY')) return crypto.createPublicKey(value);
  const b64 = /p=([A-Za-z0-9+/=]+)/.exec(value)?.[1];
  if (!b64) throw new Error('no p= in DKIM record');
  const der = Buffer.from(b64, 'base64');
  return crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
}

function unfold(text) {
  return text.split('\r\n').reduce((acc, line) => {
    if (/^[ \t]/.test(line) && acc.length) acc[acc.length - 1][1] += ' ' + line.trim();
    else {
      const idx = line.indexOf(':');
      if (idx > 0) acc.push([line.slice(0, idx), line.slice(idx + 1).trim()]);
    }
    return acc;
  }, []);
}

function parseTags(value) {
  const out = {};
  for (const part of value.split(';')) {
    const idx = part.indexOf('=');
    if (idx > 0) out[part.slice(0, idx).trim()] = part.slice(idx + 1).trim();
  }
  return out;
}
