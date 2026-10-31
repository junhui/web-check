import net from 'net';
import middleware from './_common/middleware.js';
import { parseTarget, baseDomain } from './_common/parse-target.js';
import { runJob } from './_common/jobs.js';
import { upstreamError } from './_common/upstream.js';
import { severityRank, worst } from './_common/leak-rules.js';
import * as sources from './_common/leak-sources.js';
import * as store from './_common/leak-store.js';

const MAX_KEYWORDS = 8;
const MAX_KEYWORD_LEN = 50;
const MAX_FINDINGS = 300;
// Cap on the whole job, and on each source within it
const JOB_TIMEOUT = 120000;
const WAIT_BEFORE_PENDING = 10000;
const RESULT_TTL = 30 * 60 * 1000;

// Postman runs last, as it inspects pages found by the search sources
export const SOURCES = ['wayback', 'commoncrawl', 'crtsh', 'github', 'google', 'brave', 'postman'];
const SEARCH_SOURCES = ['google', 'brave'];

export const defaultKeywords = (domain) => [domain.split('.')[0], domain];

const getQuery = (request) => request?.query || request?.queryStringParameters || {};

const parseList = (value) =>
  String(value || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

// Reject on timeout, so one slow source can't hold up the rest
const withTimeout = (promise, ms) =>
  Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`timed out after ${ms / 1000}s`)), ms).unref?.(),
    ),
  ]);

const errorEntry = (err, name) => {
  const { error, skipped } = err.response || err.code ? upstreamError(err, name) : {};
  return { status: 'error', count: 0, findings: [], message: error || skipped || err.message };
};

// Merge findings for the same url, keeping the worst severity and all rules
const dedupe = (findings) => {
  const byUrl = new Map();
  for (const f of findings) {
    const prev = byUrl.get(f.url);
    if (!prev) {
      byUrl.set(f.url, { ...f });
      continue;
    }
    prev.rules = [...new Set([...prev.rules, ...f.rules])];
    prev.severity = worst([prev.severity, f.severity]);
    prev.snippet ||= f.snippet;
  }
  return [...byUrl.values()];
};

const hunt = async ({ domain, keywords, selected }, report) => {
  const start = Date.now();
  const deadline = start + JOB_TIMEOUT;
  const piiCounts = { emails: 0, phones: 0, addresses: 0 };
  const ctx = { domain, keywords, piiCounts };
  const status = Object.fromEntries(selected.map((s) => [s, 'running']));
  const results = {};
  const progress = () => report({ ...status });

  const run = async (name) => {
    const left = Math.max(1000, deadline - Date.now());
    try {
      results[name] = await withTimeout(
        sources[name](ctx, (msg) => {
          status[name] = `running: ${msg}`;
          progress();
        }),
        left,
      );
    } catch (err) {
      results[name] = errorEntry(err, name);
    }
    status[name] = results[name].status;
    progress();
  };

  progress();
  await Promise.all(selected.filter((s) => s !== 'postman').map(run));
  if (selected.includes('postman')) {
    ctx.searchFindings = SEARCH_SOURCES.flatMap((s) => results[s]?.findings || []);
    await run('postman');
  }

  const findings = dedupe(selected.flatMap((s) => results[s].findings))
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
    .slice(0, MAX_FINDINGS)
    .map(({ rawUrl, ...f }, i) => ({ id: `${f.source}-${i + 1}`, ...f }));

  const summary = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) summary[f.severity]++;

  return {
    domain,
    keywords,
    sources: Object.fromEntries(
      selected.map((s) => [
        s,
        { status: results[s].status, count: results[s].count, message: results[s].message },
      ]),
    ),
    findings,
    summary: { ...summary, piiCounts },
    links: sources.searchLinks(keywords),
    timeTaken: Date.now() - start,
  };
};

// Hunt, then save to history; tags each finding with isNew and its stored status
export const huntAndRecord = async (params, report = () => {}) => {
  const startedAt = Date.now();
  const result = await hunt(params, report);
  let history = { enabled: false, runId: null, newCount: 0 };
  try {
    history = store.recordRun(params.domain, params.keywords, result, startedAt);
  } catch (err) {
    console.error(`[leak-hunt] could not save history: ${err.message}`);
  }
  if (!history.enabled) {
    history.message = store.disabledMessage();
    for (const f of result.findings) Object.assign(f, { isNew: false, status: 'new' });
  }
  return { ...result, history };
};

// Results are cached for a while, so pick up any status changes made since the run
const withCurrentStatus = (result) => {
  if (!result.history?.enabled || !result.findings) return result;
  const statuses = store.getStatuses(result.findings.map((f) => f.fingerprint));
  return {
    ...result,
    findings: result.findings.map((f) => ({ ...f, status: statuses[f.fingerprint] || f.status })),
  };
};

const leakHuntHandler = async (url, request) => {
  const { hostname } = parseTarget(url);
  if (net.isIP(hostname)) return { error: 'Leak hunt needs a domain name, not an IP address' };
  const domain = baseDomain(hostname).toLowerCase();
  const query = getQuery(request);

  let keywords = parseList(query.keywords);
  if (!keywords.length) keywords = defaultKeywords(domain);
  if (keywords.length > MAX_KEYWORDS) return { error: `At most ${MAX_KEYWORDS} keywords allowed` };
  if (keywords.some((k) => k.length > MAX_KEYWORD_LEN || /["\\]/.test(k))) {
    return { error: `Keywords must be under ${MAX_KEYWORD_LEN} chars, without quotes` };
  }
  keywords = [...new Set(keywords)];

  const requested = parseList(query.sources).map((s) => s.toLowerCase());
  const unknown = requested.filter((s) => s !== 'links' && !SOURCES.includes(s));
  if (unknown.length) {
    return { error: `Unknown sources: ${unknown.join(', ')}. Valid: ${SOURCES.join(', ')}, links` };
  }
  const selected = requested.length ? SOURCES.filter((s) => requested.includes(s)) : SOURCES;

  const key = `leak|${domain}|${[...keywords].sort().join(',')}|${selected.join(',')}`;
  const result = await runJob(
    key,
    (report) => huntAndRecord({ domain, keywords, selected }, report),
    {
      waitMs: WAIT_BEFORE_PENDING,
      ttlMs: RESULT_TTL,
    },
  );
  if (!result.pending) return withCurrentStatus(result);
  return { ...result, domain, keywords };
};

export const handler = middleware(leakHuntHandler);
export default handler;
