import dns from 'node:dns/promises';

/**
 * Spamhaus blocks queries from public resolvers (Cloudflare/Google) and returns
 * 127.255.255.254. Quad9 (9.9.9.9) is on Spamhaus' allowed resolver list and
 * returns the real return codes, so DNSBL checks use it directly over UDP/53.
 */
const ZEN_CODES = {
  '127.0.0.2': { list: 'SBL', meaning: 'spam source' },
  '127.0.0.3': { list: 'SBL CSS', meaning: 'spam source, composite snowshoe' },
  '127.0.0.4': { list: 'XBL CBL', meaning: 'exploited/compromised host' },
  '127.0.0.5': { list: 'XBL CSS', meaning: 'exploited host, composite snowshoe' },
  '127.0.0.6': { list: 'XBL', meaning: 'compromised host' },
  '127.0.0.7': { list: 'XBL', meaning: 'compromised host' },
  '127.0.0.9': { list: 'DBL', meaning: 'domain blocklist' },
  '127.0.0.10': { list: 'PBL ISP', meaning: 'not authorized to send directly (ISP range)' },
  '127.0.0.11': { list: 'PBL CSS', meaning: 'not authorized to send directly (dynamic/shared)' },
};

export async function spamhausLookup(ip) {
  const rev = ip.split('.').reverse().join('.');
  const resolver = new dns.Resolver({ timeout: 5000, tries: 2 });
  resolver.setServers(['9.9.9.9', '149.112.112.112']);
  try {
    const answers = await resolver.resolve4(`${rev}.zen.spamhaus.org`);
    const codes = answers.filter((a) => a.startsWith('127.0.0.'));
    if (!codes.length) return { listed: false, codes: [], lists: [] };
    if (codes.includes('127.255.255.254')) {
      return { listed: null, unknown: true, reason: 'resolver blocked by Spamhaus', codes };
    }
    const lists = codes.map((c) => ({ code: c, ...(ZEN_CODES[c] || { list: 'unknown', meaning: 'unknown code' }) }));
    return { listed: true, codes, lists };
  } catch (err) {
    if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') return { listed: false, codes: [], lists: [] };
    return { listed: null, unknown: true, reason: err.message, codes: [] };
  }
}

export function spamhausAdvice(result) {
  if (!result?.listed) return [];
  const tips = [];
  const names = result.lists.map((l) => l.list);
  if (names.some((n) => n.startsWith('SBL'))) {
    tips.push('SBL/CSS listing: the IP range has active spam sources. Individual delist will not hold; use an ESP smart host or ask the ISP to clean the range.');
  }
  if (names.some((n) => n.startsWith('PBL'))) {
    tips.push('PBL listing: this is an ISP/dynamic range that is not authorized to send mail directly. Direct-to-MX is structurally blocked; use SMTP relay with its own IPs.');
  }
  if (names.some((n) => n.startsWith('XBL'))) {
    tips.push('XBL listing: a host in the range is compromised. Clean/rebuild before sending; delist after 24h of clean traffic.');
  }
  tips.push('Check delist status: https://check.spamhaus.org/ (Cloudflare-protected; use a real browser).');
  return tips;
}
