import { httpPost } from './http.js';

// Scheduled leak hunts, from LEAK_HUNT_SCHEDULE, e.g. `example.com=example,example.com;other.com=other@12h`
// Each target runs on its own interval (default 24h, min 1h); the first run is after FIRST_DELAY.

const HOUR = 60 * 60 * 1000;
const DEFAULT_INTERVAL = 24 * HOUR;
const MIN_INTERVAL = HOUR;
const FIRST_DELAY = 5 * 60 * 1000;
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const UNITS = { m: 60 * 1000, h: HOUR, d: 24 * HOUR };
const DOMAIN_RE = /^[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}$/;

// Parse the schedule string into [{ domain, keywords, intervalMs }], throwing on bad entries
export const parseSchedule = (value, { minInterval = MIN_INTERVAL } = {}) =>
  String(value || '')
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((entry) => {
      const [main, every] = entry.split('@').map((s) => s.trim());
      const [rawDomain, rawKeywords = ''] = main.split('=').map((s) => s.trim());
      const domain = rawDomain.toLowerCase();
      if (!DOMAIN_RE.test(domain)) throw new Error(`Invalid domain in schedule: "${rawDomain}"`);
      const keywords = rawKeywords
        .split(',')
        .map((k) => k.trim())
        .filter(Boolean);
      if (keywords.length > 8 || keywords.some((k) => k.length > 50 || /["\\]/.test(k))) {
        throw new Error(`Invalid keywords for ${domain} (max 8, under 50 chars, no quotes)`);
      }
      let intervalMs = DEFAULT_INTERVAL;
      if (every) {
        const m = every.match(/^(\d+)\s*([mhd])$/i);
        if (!m) throw new Error(`Invalid interval in schedule: "${every}" (use e.g. 12h or 2d)`);
        intervalMs = Number(m[1]) * UNITS[m[2].toLowerCase()];
      }
      return { domain, keywords, intervalMs: Math.max(minInterval, intervalMs) };
    });

// Counts and a link only; never snippets or finding URLs
export const alertText = (domain, newFindings, baseUrl = '') => {
  const counts = SEVERITIES.map(
    (s) => `${s} ${newFindings.filter((f) => f.severity === s).length}`,
  ).join(', ');
  const base = String(baseUrl || '').replace(/\/+$/, '');
  return (
    `Leak Hunt: ${newFindings.length} new findings for ${domain} (${counts}). ` +
    `Review: ${base}/leak-hunt?domain=${encodeURIComponent(domain)}`
  );
};

// Run one target through the same job function as the API, alert on new findings
export const runTarget = async (target, { runHunt, env = process.env, log = console }) => {
  const result = await runHunt(target);
  if (result.error) {
    log.warn(`[leak-scheduler] ${target.domain}: run failed`);
    return result;
  }
  const newCount = result.history?.newCount || 0;
  log.log(`[leak-scheduler] ${target.domain}: ${result.findings.length} findings, ${newCount} new`);
  if (newCount > 0 && env.LEAK_HUNT_WEBHOOK) {
    const text = alertText(
      target.domain,
      result.findings.filter((f) => f.isNew),
      env.LEAK_HUNT_PUBLIC_URL,
    );
    try {
      await httpPost(env.LEAK_HUNT_WEBHOOK, { text }, { timeout: 15000 });
      log.log(`[leak-scheduler] ${target.domain}: webhook sent`);
    } catch (err) {
      log.warn(`[leak-scheduler] ${target.domain}: webhook failed (${err.code || err.message})`);
    }
  }
  return result;
};

// Start the timers; targets run one at a time, so hunts never overlap
export const startScheduler = ({
  runHunt,
  schedule = process.env.LEAK_HUNT_SCHEDULE,
  firstDelay = FIRST_DELAY,
  minInterval = MIN_INTERVAL,
  tickMs = 60 * 1000,
  env = process.env,
  log = console,
} = {}) => {
  let targets;
  try {
    targets = parseSchedule(schedule, { minInterval });
  } catch (err) {
    log.error(`[leak-scheduler] ${err.message}; scheduler not started`);
    return null;
  }
  if (!targets.length) return null;
  const firstAt = Date.now() + firstDelay;
  for (const t of targets) t.nextAt = firstAt;
  let busy = false;

  const tick = async () => {
    if (busy) return;
    busy = true;
    try {
      for (const t of targets) {
        if (Date.now() < t.nextAt) continue;
        t.nextAt = Date.now() + t.intervalMs;
        try {
          await runTarget(t, { runHunt, env, log });
        } catch (err) {
          log.warn(`[leak-scheduler] ${t.domain}: ${err.message}`);
        }
      }
    } finally {
      busy = false;
    }
  };

  const timer = setInterval(tick, Math.min(tickMs, firstDelay || tickMs));
  timer.unref?.();
  log.log(
    `[leak-scheduler] ${targets.length} target(s) scheduled, first run in ${Math.round(firstDelay / 1000)}s`,
  );
  return { targets, tick, stop: () => clearInterval(timer) };
};
