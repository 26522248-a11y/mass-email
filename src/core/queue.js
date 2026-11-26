import fs from 'node:fs';
import path from 'node:path';
import { ensureDir, readJson, writeJson, randomHex } from '../lib/util.js';

const LEASE_MS = 10 * 60 * 1000;

export class Queue {
  constructor({ dir }) {
    this.dir = dir;
    this.pendingDir = path.join(dir, 'pending');
    this.doneDir = path.join(dir, 'done');
    this.failedDir = path.join(dir, 'failed');
    for (const d of [this.pendingDir, this.doneDir, this.failedDir]) ensureDir(d);
    this.recoverLeases();
  }

  add(row, extra = {}) {
    const id = `${Date.now().toString(36)}-${randomHex(6)}`;
    const job = {
      id, email: row.email, row, attempts: 0, dueAt: Date.now(), status: 'pending',
      createdAt: Date.now(), ...extra,
    };
    writeJson(path.join(this.pendingDir, `${id}.json`), job);
    return job;
  }

  addMany(rows, extra = {}) {
    return rows.map((row) => this.add(row, extra));
  }

  read(id) {
    try { return readJson(path.join(this.pendingDir, `${id}.json`)); } catch { return null; }
  }

  save(job) { writeJson(path.join(this.pendingDir, `${job.id}.json`), job); }

  /** Return due jobs and lease them. */
  lease(limit = 20) {
    const now = Date.now();
    const files = fs.readdirSync(this.pendingDir).filter((f) => f.endsWith('.json'));
    const due = [];
    for (const file of files) {
      if (due.length >= limit) break;
      const job = readJson(path.join(this.pendingDir, file));
      if (!job) continue;
      if (job.status === 'leased' && job.leaseUntil > now) continue;
      if (job.dueAt > now) continue;
      job.status = 'leased';
      job.leaseUntil = now + LEASE_MS;
      job.attempts += 1;
      this.save(job);
      due.push(job);
    }
    return due;
  }

  complete(job, result = {}) {
    job.status = 'done';
    job.result = result;
    job.completedAt = Date.now();
    fs.renameSync(path.join(this.pendingDir, `${job.id}.json`), path.join(this.doneDir, `${job.id}.json`));
  }

  retry(job, delaySeconds, result = {}) {
    job.status = 'pending';
    job.dueAt = Date.now() + delaySeconds * 1000;
    job.leaseUntil = 0;
    job.lastResult = result;
    this.save(job);
  }

  fail(job, result = {}) {
    job.status = 'failed';
    job.result = result;
    job.completedAt = Date.now();
    fs.renameSync(path.join(this.pendingDir, `${job.id}.json`), path.join(this.failedDir, `${job.id}.json`));
  }

  requeue(job, delaySeconds = 0) {
    job.status = 'pending';
    job.dueAt = Date.now() + delaySeconds * 1000;
    job.leaseUntil = 0;
    job.attempts = 0;
    job.result = undefined;
    job.completedAt = undefined;
    const from = path.join(this.failedDir, `${job.id}.json`);
    if (fs.existsSync(from)) fs.renameSync(from, path.join(this.pendingDir, `${job.id}.json`));
    this.save(job);
  }

  hold(job, result = {}) {
    job.status = 'held';
    job.result = result;
    this.save(job);
  }

  recoverLeases() {
    const now = Date.now();
    for (const file of fs.readdirSync(this.pendingDir)) {
      if (!file.endsWith('.json')) continue;
      const job = readJson(path.join(this.pendingDir, file));
      if (job?.status === 'leased' && job.leaseUntil < now) {
        job.status = 'pending';
        job.dueAt = now;
        this.save(job);
      }
    }
  }

  stats() {
    const count = (dir, pred = () => true) => fs.readdirSync(dir).filter((f) => f.endsWith('.json')).filter((f) => pred(readJson(path.join(dir, f)))).length;
    return {
      pending: count(this.pendingDir, (j) => j?.status === 'pending'),
      leased: count(this.pendingDir, (j) => j?.status === 'leased'),
      held: count(this.pendingDir, (j) => j?.status === 'held'),
      done: fs.readdirSync(this.doneDir).filter((f) => f.endsWith('.json')).length,
      failed: fs.readdirSync(this.failedDir).filter((f) => f.endsWith('.json')).length,
    };
  }

  listFailed(limit = 100) {
    return fs.readdirSync(this.failedDir).filter((f) => f.endsWith('.json')).slice(0, limit)
      .map((f) => readJson(path.join(this.failedDir, f))).filter(Boolean);
  }

  listHeld(limit = 100) {
    return fs.readdirSync(this.pendingDir).filter((f) => f.endsWith('.json')).slice(0, limit)
      .map((f) => readJson(path.join(this.pendingDir, f)))
      .filter((j) => j?.status === 'held');
  }

  release(job) {
    job.status = 'pending';
    job.dueAt = Date.now();
    job.attempts = 0;
    this.save(job);
  }
}

export function queuePaths(root) {
  return {
    dir: path.join(root, 'data', 'queue'),
    logFile: path.join(root, 'logs', 'send.jsonl'),
  };
}
