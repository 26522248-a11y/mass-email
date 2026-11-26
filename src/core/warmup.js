import fs from 'node:fs';
import path from 'node:path';
import { ensureDir } from '../lib/util.js';

/**
 * Warmup ramp: geometric growth with plateaus. New IP/domain starts at `start`
 * per day and doubles roughly every 3-4 days until `target`.
 */
export function buildWarmupPlan({ start = 50, target = 5000, days = 28, growth = 1.35, restDays = [6, 7] }) {
  const plan = [];
  let volume = start;
  for (let day = 1; day <= days; day++) {
    const dow = new Date(Date.UTC(2026, 0, 4 + day)).getUTCDay(); // Monday-based reference
    const rest = restDays.includes(dow === 0 ? 7 : dow);
    const daily = Math.max(1, Math.round(rest ? volume * 0.6 : volume));
    plan.push({
      day, daily, cumulative: plan.reduce((s, p) => s + p.daily, 0) + daily,
      note: rest ? 'reduced (weekend)' : day % 4 === 0 ? 'hold before next step' : 'ramp',
    });
    if (!rest && day % 4 !== 0) volume = Math.min(target, volume * growth);
    if (volume >= target && plan.length > 0) {
      // fill remaining days at target
      for (let d = day + 1; d <= days; d++) plan.push({ day: d, daily: target, cumulative: plan.reduce((s, p) => s + p.daily, 0) + target, note: 'target' });
      break;
    }
  }
  return plan;
}

export function writeWarmupCsv(plan, file) {
  ensureDir(path.dirname(file));
  const lines = ['day,daily,volume_note'];
  for (const p of plan) lines.push(`${p.day},${p.daily},${p.note}`);
  fs.writeFileSync(file, lines.join('\n') + '\n');
  return lines.length - 1;
}

export function warmupAdvice() {
  return [
    'Start with the most engaged 10% of your list, not the oldest.',
    'Keep daily volume under 60% of the relay ceiling for the first 2 weeks.',
    'Send at the same times each day; jitter inside a 2h window, not all day.',
    'One link domain, one From domain, one design during warmup. Change one variable at a time.',
    'Watch Google Postmaster Tools / SNDS daily: spam rate must stay < 0.1% during warmup.',
    'Pause 24h on any 421/451 burst above 2% of volume; do not push through throttling.',
    'After warmup, keep a 20% headroom and never send a cold list at full speed.',
  ];
}
