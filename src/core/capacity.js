/**
 * Capacity planner. "Unlimited" is horizontal scaling inside provider quotas:
 * relays x quota, IPs x reputation, domains x alignment. This computes the
 * minimum footprint for a target daily volume with headroom.
 */
export function planCapacity({
  targetPerDay = 100000,
  perRelayPerDay = 5000,
  perIpPerDay = 3000,
  perDomainPerDay = 10000,
  windowHours = 16,
  concurrencyPerRelay = 4,
  avgTransactionMs = 350,
  headroom = 1.35,
}) {
  const need = Math.ceil(targetPerDay * headroom);
  const relays = Math.ceil(need / perRelayPerDay);
  const ips = Math.ceil(need / perIpPerDay);
  const domains = Math.max(3, Math.ceil(need / perDomainPerDay));
  const perSecond = targetPerDay / (windowHours * 3600);
  const relayThroughput = (concurrencyPerRelay * 1000) / avgTransactionMs;
  const relaysBySpeed = Math.ceil(perSecond / relayThroughput);
  const units = Math.max(relays, relaysBySpeed);
  const cost = {
    vps: [units * 5, units * 40],
    ipv4: [ips * 3, ips * 12],
    domains: [Math.ceil(domains / 20) * 12, Math.ceil(domains / 20) * 40],
    esp: [Math.round(targetPerDay / 1000 * 0.10), Math.round(targetPerDay / 1000 * 1.20)],
    mailboxes: [relays * 6, relays * 12],
  };
  const totalLow = Object.values(cost).reduce((s, v) => s + v[0], 0);
  const totalHigh = Object.values(cost).reduce((s, v) => s + v[1], 0);
  return {
    input: { targetPerDay, perRelayPerDay, perIpPerDay, perDomainPerDay, windowHours, headroom },
    required: { relays: units, relayAccounts: relays, ips, domains },
    throughput: {
      messagesPerSecond: Number(perSecond.toFixed(2)),
      perRelayPerSecond: Number(relayThroughput.toFixed(2)),
      relayLimitedBy: relaysBySpeed > relays ? 'speed' : 'quota',
      drainHours: Number((targetPerDay / (units * relayThroughput * 3600)).toFixed(2)),
    },
    costUsdPerMonth: { low: totalLow, high: totalHigh, breakdown: cost },
    notes: [
      'Headroom covers retries, throttling and reputation dips; never plan at 100% of quota.',
      'One domain per 10k/day keeps DMARC/blacklist blast radius small; rotate after 6-12 months, not weekly.',
      'IPs need 2-4 weeks warmup each; adding IPs faster than warmup is the usual failure mode.',
      'ESP quotas are contractual, not technical: exceeding them gets the account frozen, not just throttled.',
    ],
  };
}
