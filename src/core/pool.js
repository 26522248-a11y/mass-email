import fs from 'node:fs';
import { readJson, writeJson, clamp, randomHex } from '../lib/util.js';

const HOUR = 3600_000;
const DAY = 86_400_000;

const DEFAULTS = {
  gmail: { max_per_hour: 100, max_per_day: 600, max_concurrent: 2, weight: 2 },
  outlook: { max_per_hour: 60, max_per_day: 300, max_concurrent: 2, weight: 1 },
  ses: { max_per_hour: 800, max_per_day: 12000, max_concurrent: 8, weight: 10 },
  generic: { max_per_hour: 200, max_per_day: 2000, max_concurrent: 4, weight: 1 },
};

export class RelayPool {
  constructor({ stateFile, relays }) {
    this.stateFile = stateFile;
    this.relays = relays.map((r) => this.hydrate(r));
    this.state = readJson(stateFile, { relays: {} });
    for (const relay of this.relays) {
      if (!this.state.relays[relay.id]) {
        this.state.relays[relay.id] = {
          health: 1, disabled: false, quarantineUntil: 0, lastUsed: 0, sentHour: 0, sentDay: 0,
          hourStart: Date.now(), dayStart: Date.now(), errors: 0, successes: 0,
        };
      }
    }
    this.save();
  }

  hydrate(r) {
    const base = DEFAULTS[r.kind] || DEFAULTS.generic;
    return {
      ...base,
      ...r,
      max_per_hour: r.max_per_hour ?? base.max_per_hour,
      max_per_day: r.max_per_day ?? base.max_per_day,
      max_concurrent: r.max_concurrent ?? base.max_concurrent,
      weight: r.weight ?? base.weight,
    };
  }

  save() { writeJson(this.stateFile, this.state); }

  rolling(relay) {
    const st = this.state.relays[relay.id];
    const now = Date.now();
    if (now - st.hourStart > HOUR) { st.hourStart = now; st.sentHour = 0; }
    if (now - st.dayStart > DAY) { st.dayStart = now; st.sentDay = 0; }
    return st;
  }

  quotaLeft(relay) {
    const st = this.rolling(relay);
    return {
      hour: Math.max(0, relay.max_per_hour - st.sentHour),
      day: Math.max(0, relay.max_per_day - st.sentDay),
    };
  }

  eligible(now = Date.now()) {
    return this.relays.filter((r) => {
      const st = this.state.relays[r.id];
      if (st.disabled) return false;
      if (st.quarantineUntil > now) return false;
      if (st.health < 0.15) return false;
      const left = this.quotaLeft(r);
      return left.hour > 0 && left.day > 0;
    });
  }

  pick(now = Date.now()) {
    const candidates = this.eligible(now);
    if (!candidates.length) return null;
    const scored = candidates.map((r) => {
      const st = this.state.relays[r.id];
      const left = this.quotaLeft(r);
      const quotaFactor = Math.min(1, left.hour / Math.max(1, r.max_per_hour));
      const freshness = 1 - Math.min(1, (now - st.lastUsed) / HOUR);
      const score = r.weight * st.health * (0.4 + 0.6 * quotaFactor) * (0.5 + 0.5 * freshness);
      return { relay: r, score };
    }).sort((a, b) => b.score - a.score);

    const top = scored.slice(0, Math.min(5, scored.length));
    const total = top.reduce((s, x) => s + x.score, 0);
    let roll = Math.random() * total;
    for (const item of top) {
      roll -= item.score;
      if (roll <= 0) return item.relay;
    }
    return top[0].relay;
  }

  markUsed(id) {
    const st = this.state.relays[id];
    const relay = this.relays.find((r) => r.id === id);
    this.rolling(relay);
    st.lastUsed = Date.now();
    st.sentHour += 1;
    st.sentDay += 1;
    this.save();
  }

  recordSuccess(id) {
    const st = this.state.relays[id];
    st.successes += 1;
    st.health = clamp(st.health + 0.02, 0, 1);
    st.quarantineUntil = 0;
    this.save();
  }

  recordThrottle(id, seconds = 900) {
    const st = this.state.relays[id];
    st.errors += 1;
    st.health = clamp(st.health - 0.08, 0, 1);
    st.quarantineUntil = Math.max(st.quarantineUntil, Date.now() + seconds * 1000);
    this.save();
  }

  recordFailure(id, { permanent = false, auth = false } = {}) {
    const st = this.state.relays[id];
    st.errors += 1;
    st.health = clamp(st.health - (permanent ? 0.05 : 0.02), 0, 1);
    if (auth) st.disabled = true;
    this.save();
  }

  stats() {
    return this.relays.map((r) => {
      const st = this.state.relays[r.id];
      const left = this.quotaLeft(r);
      return {
        id: r.id, kind: r.kind, host: r.host, health: Number(st.health.toFixed(2)),
        quarantined: st.quarantineUntil > Date.now(), disabled: st.disabled,
        sentHour: st.sentHour, sentDay: st.sentDay, leftHour: left.hour, leftDay: left.day,
      };
    });
  }

  get(id) { return this.relays.find((r) => r.id === id) || null; }
}

export class RelayGuard {
  constructor(pool) { this.pool = pool; this.active = new Map(); }

  acquire(relayId) {
    const relay = this.pool.get(relayId);
    const n = this.active.get(relayId) || 0;
    if (relay && n >= relay.max_concurrent) return false;
    this.active.set(relayId, n + 1);
    return true;
  }

  release(relayId) {
    const n = (this.active.get(relayId) || 1) - 1;
    if (n <= 0) this.active.delete(relayId); else this.active.set(relayId, n);
  }
}

export function newRelayId(prefix = 'relay') { return `${prefix}-${randomHex(4)}`; }

export function loadRelays(file) {
  const cfg = readJson(file);
  if (!cfg?.relays?.length) throw new Error(`no relays in ${file} (copy relays.example.json)`);
  for (const r of cfg.relays) {
    if (!r.id || !r.host || !r.from) throw new Error('relay needs id, host, from');
    r.domain = r.domain || r.from.split('@')[1];
  }
  return cfg.relays;
}

export function relayFileExists(file) { return fs.existsSync(file); }
