import { httpGet } from './http.js';
import { scan, maskUrl, maskPII, SENSITIVE_PARAMS } from './leak-rules.js';
import { launchBrowser, openPage, closeBrowser, isBrowserMissing } from './browser.js';

// Wayback capture list for the URL minus its query, so links work without exposing masked params
const archiveLink = (u) => `https://web.archive.org/web/*/${u.split(/[?#]/)[0]}*`;

// Each source returns { status: 'ok'|'skipped'|'error', count, findings, message? }

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const ok = (findings, message) => ({ status: 'ok', count: findings.length, findings, message });
const skipped = (message) => ({ status: 'skipped', count: 0, findings: [], message });

const EXT = 'sql|bak|env|log|config|pem|key|zip|tar\\.gz|dump|xlsx?|csv';
// Extensions that usually mean credentials or full data dumps
const HIGH_EXT = /\.(?:sql|env|pem|key|dump|bak)$/i;
const URL_RE = new RegExp(`\\.(?:${EXT})(?:[?#]|$)|[?&](?:${SENSITIVE_PARAMS.join('|')})=`, 'i');
const isoDay = (ts) => `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}`;

// A finding for an archived/indexed URL, judged on the URL alone
const urlFinding = (source, original, link, foundAt) => {
  const { rules, severity } = scan(original);
  if (!rules.length) return null;
  const path = original.split(/[?#]/)[0];
  const bump = HIGH_EXT.test(path) && severity !== 'critical' ? 'high' : severity;
  return {
    source,
    severity: bump,
    title: maskUrl(original),
    url: link,
    rules,
    snippet: '',
    ...(foundAt && { foundAt }),
  };
};

// Parse Common Crawl's newline-delimited JSON
const parseNdjson = (body) =>
  String(body || '')
    .split('\n')
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    })
    .filter(Boolean);

const WAYBACK_LIMIT = 10000;

// Wayback Machine CDX: archived URLs on the domain with sensitive extensions or params
// (server-side regex filters time out on big domains, so filter here instead)
export const wayback = async ({ domain }) => {
  const res = await httpGet('https://web.archive.org/cdx/search/cdx', {
    params: {
      url: domain,
      matchType: 'domain',
      output: 'json',
      fl: 'timestamp,original',
      collapse: 'urlkey',
      filter: 'statuscode:200',
      limit: WAYBACK_LIMIT,
    },
    timeout: 100000,
  });
  const rows = Array.isArray(res.data) ? res.data.slice(1) : [];
  const findings = rows
    .filter(([, original]) => URL_RE.test(original))
    .map(([ts, original]) => {
      const archived = archiveLink(original);
      return urlFinding('wayback', original, archived, isoDay(ts));
    })
    .filter(Boolean);
  const capped = rows.length >= WAYBACK_LIMIT ? ` (capped at ${WAYBACK_LIMIT})` : '';
  return ok(findings, `${rows.length} archived URLs checked${capped}`);
};

// Common Crawl: first page of the newest index that answers, same filtering as wayback
export const commoncrawl = async ({ domain }) => {
  const { data: indexes } = await httpGet('https://index.commoncrawl.org/collinfo.json', {
    timeout: 15000,
  });
  if (!indexes?.length) throw new Error('No Common Crawl index found');
  let lastError;
  // The index server often times out, so fall back to the previous crawl once
  for (const index of indexes.slice(0, 2)) {
    try {
      const res = await httpGet(index['cdx-api'], {
        params: {
          url: domain,
          matchType: 'domain',
          output: 'json',
          page: 0,
          fl: 'timestamp,url,status',
        },
        timeout: 30000,
        validateStatus: (s) => s < 500,
      });
      if (res.status === 404) return ok([], `No captures in ${index.id}`);
      if (res.status >= 400) throw new Error(`Common Crawl returned HTTP ${res.status}`);
      const rows = parseNdjson(res.data).filter((r) => String(r.status) === '200');
      const findings = rows
        .filter((r) => URL_RE.test(r.url))
        .map((r) => {
          const link = archiveLink(r.url);
          return urlFinding('commoncrawl', r.url, link, isoDay(r.timestamp));
        })
        .filter(Boolean);
      return ok(findings, `${rows.length} captures checked in ${index.id}`);
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError;
};

const INTERNAL_LABEL =
  /^(?:dev|devel|test|qa|uat|stage|staging|stg|preprod|internal|intranet|corp|vpn|admin|jenkins|gitlab|git|jira|confluence|k8s|kube|db|mysql|sql|mongo|redis|elastic|kibana|grafana|sonar|nexus|artifactory|ldap|sso)\d*$/;

// crt.sh: certificate names on the domain that look like internal infrastructure
export const crtsh = async ({ domain }) => {
  const res = await httpGet('https://crt.sh/', {
    params: { q: `%.${domain}`, output: 'json' },
    headers: { Accept: 'application/json' },
    timeout: 60000,
  });
  if (!Array.isArray(res.data)) throw new Error('crt.sh returned an unexpected response');
  const names = new Set(
    res.data
      .flatMap((row) => String(row?.name_value ?? '').split('\n'))
      .map((n) => n.trim().toLowerCase().replace(/^\*\./, ''))
      .filter((n) => n.endsWith(`.${domain}`)),
  );
  const findings = [...names]
    .filter((n) =>
      n
        .slice(0, -domain.length - 1)
        .split(/[.-]/)
        .some((label) => INTERNAL_LABEL.test(label)),
    )
    .map((n) => ({
      source: 'crtsh',
      severity: 'medium',
      title: n,
      url: `https://crt.sh/?q=${encodeURIComponent(n)}`,
      rules: ['internal-host'],
      snippet: '',
    }));
  return ok(findings, `${names.size} certificate names checked`);
};

const GH_TERMS = ['password', 'secret', 'api_key', 'jdbc', 'smtp', '"BEGIN RSA PRIVATE KEY"'];
const GH_MAX_QUERIES = 8;
// Code search allows 10 requests a minute
const GH_DELAY = 6500;

// Build up to max queries, spreading sensitive terms across keywords
const pairQueries = (keywords, terms, max) => {
  const out = [];
  for (let i = 0; out.length < max && i < terms.length * keywords.length; i++) {
    out.push(`"${keywords[i % keywords.length]}" ${terms[Math.floor(i / keywords.length)]}`);
  }
  return out;
};

// GitHub code search, scanning only the returned text-match fragments
export const github = async ({ keywords, piiCounts }, report) => {
  const token = process.env.GITHUB_TOKEN;
  if (!token) return skipped('Set GITHUB_TOKEN to enable GitHub code search');
  const queries = pairQueries(keywords, [...GH_TERMS, 'filename:.env'], GH_MAX_QUERIES);
  const findings = [];
  let errors = 0;
  for (const [i, q] of queries.entries()) {
    if (i) await sleep(GH_DELAY);
    report?.(`query ${i + 1}/${queries.length}`);
    try {
      const res = await httpGet('https://api.github.com/search/code', {
        params: { q, per_page: 30 },
        headers: {
          Accept: 'application/vnd.github.text-match+json',
          Authorization: `Bearer ${token}`,
          'X-GitHub-Api-Version': '2022-11-28',
        },
        timeout: 20000,
      });
      for (const item of res.data?.items || []) {
        const text = (item.text_matches || []).map((m) => m.fragment).join('\n');
        const hit = scan(text, { piiCounts });
        findings.push({
          source: 'github',
          severity: hit.severity || 'low',
          title: `${item.repository?.full_name}/${item.path}`,
          url: item.html_url,
          rules: hit.rules.length ? hit.rules : ['keyword-mention'],
          snippet: hit.snippet,
          owner: item.repository?.owner?.login,
          repo: item.repository?.full_name,
          path: item.path,
        });
      }
    } catch (err) {
      errors++;
      // Out of quota: stop rather than hammer the API
      if ([403, 429].includes(err.response?.status)) break;
    }
  }
  return ok(findings, `${queries.length} queries${errors ? `, ${errors} failed` : ''}`);
};

// Dork queries shared by search APIs and the manual links
export const dorkSet = (kw) => [
  ['Pastebin', `site:pastebin.com "${kw}"`],
  ['Exposed files', `"${kw}" (filetype:sql OR filetype:env OR filetype:log)`],
  ['Trello boards', `site:trello.com "${kw}"`],
  ['Postman', `site:postman.com "${kw}"`],
  ['Password mentions', `"${kw}" intext:password`],
];

const DORK_MAX = 5;

// Turn a search result into a finding, scanning only its title and snippet
const resultFinding = (source, { link, title, snippet }, piiCounts) => {
  const hit = scan(`${title}\n${snippet}`, { piiCounts });
  return {
    source,
    severity: hit.severity || 'low',
    title: maskPII(title || link).text,
    url: maskUrl(link),
    rules: hit.rules.length ? hit.rules : ['keyword-mention'],
    snippet: hit.snippet,
    rawUrl: link,
  };
};

// Pick DORK_MAX dorks, rotating through keywords
const searchQueries = (keywords) =>
  dorkSet('')
    .map((_, i) => dorkSet(keywords[i % keywords.length])[i][1])
    .slice(0, DORK_MAX);

// Google Programmable Search JSON API (100 queries/day free)
export const google = async ({ keywords, piiCounts }) => {
  const key = process.env.GOOGLE_CSE_KEY;
  const cx = process.env.GOOGLE_CSE_ID;
  if (!key || !cx) return skipped('Set GOOGLE_CSE_KEY and GOOGLE_CSE_ID to enable Google search');
  const findings = [];
  for (const q of searchQueries(keywords)) {
    const res = await httpGet('https://www.googleapis.com/customsearch/v1', {
      params: { key, cx, q, num: 10 },
      timeout: 15000,
    });
    for (const r of res.data?.items || []) findings.push(resultFinding('google', r, piiCounts));
  }
  return ok(findings);
};

// Brave Search API
export const brave = async ({ keywords, piiCounts }) => {
  const key = process.env.BRAVE_API_KEY;
  if (!key) return skipped('Set BRAVE_API_KEY to enable Brave search');
  const findings = [];
  for (const [i, q] of searchQueries(keywords).entries()) {
    // Free plan allows 1 request per second
    if (i) await sleep(1100);
    const res = await httpGet('https://api.search.brave.com/res/v1/web/search', {
      params: { q, count: 20 },
      headers: { Accept: 'application/json', 'X-Subscription-Token': key },
      timeout: 15000,
    });
    for (const r of res.data?.web?.results || []) {
      findings.push(
        resultFinding('brave', { link: r.url, title: r.title, snippet: r.description }, piiCounts),
      );
    }
  }
  return ok(findings);
};

const POSTMAN_MAX = 3;
const POSTMAN_TIMEOUT = 15000;

// Render postman.com pages found by search, scanning the visible text
export const postman = async ({ piiCounts, searchFindings = [] }) => {
  const urls = [
    ...new Set(
      searchFindings
        .map((f) => f.rawUrl)
        .filter((u) => /^https:\/\/(?:www\.)?postman\.com\//i.test(u || '')),
    ),
  ].slice(0, POSTMAN_MAX);
  if (!urls.length) return skipped('No postman.com results from Google or Brave to inspect');
  let browser;
  try {
    browser = await launchBrowser();
  } catch (err) {
    if (isBrowserMissing(err)) return skipped('No headless browser available');
    throw err;
  }
  const findings = [];
  try {
    for (const link of urls) {
      const page = await openPage(browser);
      try {
        await page.goto(link, { waitUntil: 'networkidle2', timeout: POSTMAN_TIMEOUT });
        const text = await page.evaluate(() => document.body?.innerText || '');
        const hit = scan(text, { piiCounts });
        if (hit.rules.length) {
          findings.push({
            source: 'postman',
            severity: hit.severity,
            title: maskUrl(link),
            url: maskUrl(link),
            rules: hit.rules,
            snippet: hit.snippet,
          });
        }
      } catch {
        // Skip pages that fail to load
      } finally {
        await page.close().catch(() => {});
      }
    }
  } finally {
    await closeBrowser(browser);
  }
  return ok(findings, `${urls.length} pages rendered`);
};

const ENGINES = {
  Google: (q) => `https://www.google.com/search?q=${encodeURIComponent(q)}`,
  Bing: (q) => `https://www.bing.com/search?q=${encodeURIComponent(q)}`,
  DuckDuckGo: (q) => `https://duckduckgo.com/?q=${encodeURIComponent(q)}`,
};

// Search links for manual review, makes no requests
export const searchLinks = (keywords) =>
  keywords.flatMap((kw) =>
    dorkSet(kw).flatMap(([title, q]) =>
      Object.entries(ENGINES).map(([engine, toUrl]) => ({
        engine,
        title: `${title}: ${q}`,
        url: toUrl(q),
      })),
    ),
  );
