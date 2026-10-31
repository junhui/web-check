import middleware from './_common/middleware.js';
import { httpGet, isBotCheck, BOT_CHECK_ERROR, APP_UA } from './_common/http.js';
import { upstreamError } from './_common/upstream.js';

const REPO_URL =
  'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json';
const CACHE_MS = 6 * 60 * 60 * 1000;
const MAX_SCRIPTS = 10;
const MAX_BYTES = 2 * 1024 * 1024;
const VERSION = '[0-9][0-9.a-z_\\-]+';

let cache = { at: 0, repo: null };

// Retire.js vulnerability repo, held in memory for 6h
const getRepo = async () => {
  if (cache.repo && Date.now() - cache.at < CACHE_MS) return cache.repo;
  const { data } = await httpGet(REPO_URL, { timeout: 10000, headers: { 'user-agent': APP_UA } });
  const repo = typeof data === 'string' ? JSON.parse(data) : data;
  cache = { at: Date.now(), repo };
  return repo;
};

const toRegex = (pattern) => {
  try {
    return new RegExp(pattern.replace(/§§version§§/g, VERSION));
  } catch {
    return null;
  }
};

const match = (patterns = [], text) => {
  for (const p of patterns) {
    const m = toRegex(p)?.exec(text);
    // Greedy version pattern can swallow a trailing .min
    if (m?.[1]) return m[1].replace(/[.-]min$/, '').replace(/[.-]$/, '');
  }
  return null;
};

// Numeric-ish version compare, good enough for retire's ranges
const cmp = (a, b) => {
  const pa = String(a).split(/[.-]/);
  const pb = String(b).split(/[.-]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? '0';
    const y = pb[i] ?? '0';
    const nx = parseInt(x, 10);
    const ny = parseInt(y, 10);
    if (!isNaN(nx) && !isNaN(ny) && nx !== ny) return nx - ny;
    if (isNaN(nx) !== isNaN(ny)) return isNaN(nx) ? -1 : 1; // pre-release sorts first
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
};

const vulnsFor = (lib, version) =>
  (lib.vulnerabilities || [])
    .filter(
      (v) =>
        (!v.below || cmp(version, v.below) < 0) && (!v.atOrAbove || cmp(version, v.atOrAbove) >= 0),
    )
    .map((v) => ({
      severity: v.severity || 'unknown',
      identifiers: { ...v.identifiers, summary: undefined },
      summary: v.identifiers?.summary || null,
      info: (v.info || []).slice(0, 3),
    }));

const scriptSrcs = (html, base) =>
  [...html.matchAll(/<script\b[^>]*\ssrc\s*=\s*["']?([^"'\s>]+)/gi)]
    .map((m) => {
      try {
        return new URL(m[1], base).href;
      } catch {
        return null;
      }
    })
    .filter((u) => u && /^https?:/.test(u));

const fetchScript = async (src) => {
  try {
    const { data } = await httpGet(src, { timeout: 6000 });
    return String(data).slice(0, MAX_BYTES);
  } catch {
    return '';
  }
};

const jsLibsHandler = async (url) => {
  let html;
  let base;
  try {
    const response = await httpGet(url, { timeout: 10000 });
    if (isBotCheck(response)) return BOT_CHECK_ERROR;
    html = String(response.data);
    base = response.url || url;
  } catch (error) {
    return upstreamError(error, 'Page fetch');
  }

  let repo;
  try {
    repo = await getRepo();
  } catch (error) {
    return upstreamError(error, 'Retire.js repository');
  }

  const srcs = [...new Set(scriptSrcs(html, base))];
  const bodies = await Promise.all(srcs.slice(0, MAX_SCRIPTS).map(fetchScript));
  // Inline scripts count as one more source, matched by content only
  const sources = [
    ...srcs.map((src, i) => ({ src, content: bodies[i] || '' })),
    { src: 'inline', content: html },
  ];

  const found = new Map();
  for (const [name, lib] of Object.entries(repo)) {
    const ex = lib.extractors || {};
    for (const { src, content } of sources) {
      const file = src === 'inline' ? '' : src.split('/').pop().split('?')[0];
      const version =
        (src !== 'inline' && (match(ex.uri, src) || match(ex.filename, file))) ||
        match(ex.filecontent, content.slice(0, 50000));
      if (version && !found.has(`${name}@${version}`)) {
        found.set(`${name}@${version}`, {
          name,
          version,
          source: src,
          vulnerabilities: vulnsFor(lib, version),
        });
      }
    }
  }

  const libs = [...found.values()];
  return { libs, vulnerableCount: libs.filter((l) => l.vulnerabilities.length).length };
};

export const handler = middleware(jsLibsHandler);
export default handler;
