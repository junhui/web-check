import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { createRequire } from 'module';

// Leak hunt history in SQLite (node:sqlite, Node 22.5+). Only masked values are ever stored.

export const STATUSES = ['new', 'confirmed', 'false_positive', 'resolved'];

const defaultPath = () =>
  process.env.WC_SERVER && fs.existsSync('/app')
    ? '/app/data/leak-hunt.db'
    : path.resolve('data', 'leak-hunt.db');

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    keywords TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    new_count INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS runs_domain ON runs (domain, id);
  CREATE TABLE IF NOT EXISTS findings (
    fingerprint TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    source TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT,
    url TEXT,
    rules TEXT NOT NULL,
    snippet TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    last_run_id INTEGER,
    status TEXT NOT NULL DEFAULT 'new'
      CHECK (status IN ('new', 'confirmed', 'false_positive', 'resolved')),
    note TEXT
  );
  CREATE INDEX IF NOT EXISTS findings_domain ON findings (domain, last_seen);
`;

let db; // undefined = not tried yet, null = unavailable
let disabledReason = '';

// Open on first use, so a missing node:sqlite or unwritable dir only disables history
const open = () => {
  if (db !== undefined) return db;
  try {
    const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite');
    const file = process.env.LEAK_DB_PATH || defaultPath();
    fs.mkdirSync(path.dirname(file), { recursive: true });
    db = new DatabaseSync(file);
    db.exec('PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;');
    db.exec(SCHEMA);
  } catch (err) {
    db = null;
    disabledReason = `History disabled: ${err.code || err.message}`;
    console.warn(`[leak-store] ${disabledReason}`);
  }
  return db;
};

export const isEnabled = () => !!open();
export const disabledMessage = () => (open() ? '' : disabledReason);

// Stable id: source, url without its query, sorted rule ids, plus the masked title, since
// some sources (crt.sh) only differ by query string
export const fingerprint = (f) =>
  crypto
    .createHash('sha256')
    .update(
      [
        f.source,
        String(f.url || '').split(/[?#]/)[0],
        [...(f.rules || [])].sort().join(','),
        f.title || '',
      ].join('|'),
    )
    .digest('hex');

const toFinding = (row) => ({
  ...row,
  rules: String(row.rules || '')
    .split(',')
    .filter(Boolean),
});

// Save a finished hunt; tags result.findings with fingerprint, isNew and status
export const recordRun = (domain, keywords, result, startedAt = Date.now()) => {
  const d = open();
  if (!d || !Array.isArray(result?.findings)) return { enabled: !!d, runId: null, newCount: 0 };
  const now = new Date().toISOString();
  const { piiCounts, ...counts } = result.summary || {};
  const summary = JSON.stringify({ ...counts, piiCounts, total: result.findings.length });
  const getStatus = d.prepare('SELECT status FROM findings WHERE fingerprint = ?');
  const upsert = d.prepare(`
    INSERT INTO findings (fingerprint, domain, source, severity, title, url, rules, snippet,
      first_seen, last_seen, last_run_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT (fingerprint) DO UPDATE SET severity = excluded.severity,
      title = excluded.title, url = excluded.url, snippet = excluded.snippet,
      last_seen = excluded.last_seen, last_run_id = excluded.last_run_id`);

  d.exec('BEGIN');
  try {
    const { lastInsertRowid } = d
      .prepare(
        'INSERT INTO runs (domain, keywords, started_at, finished_at, summary_json) VALUES (?, ?, ?, ?, ?)',
      )
      .run(domain, keywords.join(','), new Date(startedAt).toISOString(), now, summary);
    const runId = Number(lastInsertRowid);
    let newCount = 0;
    const seen = new Set();
    for (const f of result.findings) {
      const fp = fingerprint(f);
      const existing = getStatus.get(fp);
      f.fingerprint = fp;
      f.isNew = !existing && !seen.has(fp);
      f.status = existing?.status || 'new';
      if (f.isNew) newCount++;
      seen.add(fp);
      upsert.run(
        fp,
        domain,
        f.source,
        f.severity,
        f.title || '',
        f.url || '',
        (f.rules || []).join(','),
        f.snippet || '',
        now,
        now,
        runId,
      );
    }
    d.prepare('UPDATE runs SET new_count = ? WHERE id = ?').run(newCount, runId);
    d.exec('COMMIT');
    return { enabled: true, runId, newCount };
  } catch (err) {
    d.exec('ROLLBACK');
    throw err;
  }
};

export const listRuns = (domain, limit = 20) => {
  const d = open();
  if (!d) return [];
  return d
    .prepare('SELECT * FROM runs WHERE domain = ? ORDER BY id DESC LIMIT ?')
    .all(domain, limit)
    .map(({ summary_json: s, ...r }) => ({ ...r, summary: JSON.parse(s || '{}') }));
};

// Findings for a domain, isNew = first seen in the latest run
export const listFindings = (domain, { status } = {}) => {
  const d = open();
  if (!d) return [];
  const latest = d
    .prepare('SELECT id, finished_at FROM runs WHERE domain = ? ORDER BY id DESC LIMIT 1')
    .get(domain);
  const rows = status
    ? d
        .prepare('SELECT * FROM findings WHERE domain = ? AND status = ? ORDER BY last_seen DESC')
        .all(domain, status)
    : d.prepare('SELECT * FROM findings WHERE domain = ? ORDER BY last_seen DESC').all(domain);
  return rows.map((row) => ({
    ...toFinding(row),
    isNew: !!latest && row.last_run_id === latest.id && row.first_seen === latest.finished_at,
  }));
};

// Update a finding's triage status (and note, if given); domain guards against cross-domain ids
export const setStatus = (fingerprintId, status, note, domain) => {
  const d = open();
  if (!d || !STATUSES.includes(status)) return null;
  const row = d.prepare('SELECT * FROM findings WHERE fingerprint = ?').get(fingerprintId);
  if (!row || (domain && row.domain !== domain)) return null;
  d.prepare('UPDATE findings SET status = ?, note = ? WHERE fingerprint = ?').run(
    status,
    note === undefined ? row.note : note,
    fingerprintId,
  );
  return toFinding(d.prepare('SELECT * FROM findings WHERE fingerprint = ?').get(fingerprintId));
};

// fingerprint -> status, for a list of fingerprints
export const getStatuses = (fingerprints) => {
  const d = open();
  const ids = fingerprints.filter(Boolean);
  if (!d || !ids.length) return {};
  const rows = d
    .prepare(
      `SELECT fingerprint, status FROM findings WHERE fingerprint IN (${ids.map(() => '?').join(',')})`,
    )
    .all(...ids);
  return Object.fromEntries(rows.map((r) => [r.fingerprint, r.status]));
};

// For tests
export const close = () => {
  db?.close();
  db = undefined;
};
