import middleware from './_common/middleware.js';
import { parseTarget, baseDomain } from './_common/parse-target.js';
import { runJob } from './_common/jobs.js';
import { SCANNER_UA } from './_common/http.js';
import { launchBrowser, closeBrowser, isBrowserMissing } from './_common/browser.js';
import { domainTag } from './_common/consent-domains.js';
import * as osano from './_common/consent-osano.js';

// Each mode runs in its own fresh incognito context, one after another
export const DENY_CATEGORIES = ['MARKETING', 'ANALYTICS', 'PERSONALIZATION'];
export const MODES = [
  'baseline',
  'accept-all',
  'opt-out',
  'gpc',
  ...DENY_CATEGORIES.map((c) => `deny-${c}`),
];
const US_STATES =
  'al ak az ar ca co ct de dc fl ga hi id il in ia ks ky la me md ma mi mn ms mo mt ne nv nh nj nm ny nc nd oh ok or pa ri sc sd tn tx ut vt va wa wv wi wy'.split(
    ' ',
  );

// Per-site default pages; {product} is filled from the first product link on the search page
const SITE_PROFILES = {
  'newegg.com': {
    search: process.env.CONSENT_AUDIT_SEARCH_PATH || '/p/pl?d=laptop',
    productLink: /\/p\/(?!pl\b)/,
    cart: '/shop/cart',
  },
};
const PRODUCT = '{product}';

const MAX_PAGES = 6;
const JOB_TIMEOUT = 8 * 60 * 1000;
const WAIT_BEFORE_PENDING = 10000;
const RESULT_TTL = 30 * 60 * 1000;
const NAV_TIMEOUT = 20000;
const IDLE = { idleTime: 1000, timeout: 7000 };
const MAX_REQUESTS = 600;

const getQuery = (request) => request?.query || request?.queryStringParameters || {};
const parseList = (value) =>
  String(value || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// host + path only, never the query string
const splitUrl = (u) => {
  try {
    const { hostname, pathname } = new URL(u);
    return { host: hostname, path: pathname };
  } catch {
    return { host: '', path: '' };
  }
};

export const defaultPages = (host) => {
  const profile = SITE_PROFILES[baseDomain(host)];
  if (!profile) return ['/'];
  return ['/', profile.search, PRODUCT, profile.cart].filter(Boolean);
};

// Paths must be same-origin: start with a single slash, no scheme or protocol-relative tricks
const validPath = (p, origin) => {
  if (!/^\/(?!\/)/.test(p) || /[\s\\]/.test(p) || p.length > 300) return false;
  try {
    return new URL(p, origin).origin === origin;
  } catch {
    return false;
  }
};

const isBotCheck = (title, headers = {}) =>
  /just a moment|attention required|access denied|verify you are human/i.test(title || '') ||
  String(headers['cf-mitigated'] || '').toLowerCase() === 'challenge';

// Names only: keys of web storage, plus counts of inline scripts
const readPageExtras = () => {
  const keys = (s) => {
    try {
      return Object.keys(s);
    } catch {
      return [];
    }
  };
  return {
    storage: {
      localStorage: keys(window.localStorage),
      sessionStorage: keys(window.sessionStorage),
    },
    inlineScripts: document.querySelectorAll('script:not([src])').length,
  };
};

const findProductLink = (page, pattern) =>
  page
    .$$eval('a[href]', (links) => links.map((a) => a.href))
    .then((hrefs) => {
      const origin = new URL(page.url()).origin;
      for (const href of hrefs) {
        try {
          const u = new URL(href);
          if (u.origin === origin && pattern.test(u.pathname)) return u.pathname;
        } catch {
          /* skip bad link */
        }
      }
      return null;
    })
    .catch(() => null);

// Open a fresh incognito context and wire up CDP request capture
const openMode = async (browser, mode, { state, onOsanoSource }) => {
  const context = await browser.createBrowserContext();
  const page = await context.newPage();
  const userAgent = SCANNER_UA || (await browser.userAgent()).replace('HeadlessChrome', 'Chrome');
  await page.setUserAgent({ userAgent });
  page.on('dialog', (d) => d.dismiss().catch(() => {}));
  const cdp = await page.createCDPSession();
  await cdp.send('Network.enable');

  if (mode === 'gpc') {
    await cdp.send('Network.setExtraHTTPHeaders', { headers: { 'Sec-GPC': '1' } });
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
      source:
        "Object.defineProperty(Navigator.prototype, 'globalPrivacyControl', { get: () => true, configurable: true });",
    });
  }

  // Rewrite osano.js jurisdiction when simulating a state
  if (state) {
    await cdp.send('Fetch.enable', {
      patterns: [{ urlPattern: '*cmp.osano.com*osano.js*', requestStage: 'Response' }],
    });
    cdp.on(
      'Fetch.requestPaused',
      async ({ requestId, request, responseStatusCode, responseHeaders }) => {
        try {
          if (!osano.isScriptUrl(request.url) || responseStatusCode !== 200) {
            await cdp.send('Fetch.continueRequest', { requestId });
            return;
          }
          const { body, base64Encoded } = await cdp.send('Fetch.getResponseBody', { requestId });
          const text = Buffer.from(body, base64Encoded ? 'base64' : 'utf8').toString('utf8');
          const rewritten = osano.rewriteJurisdiction(text, state);
          await cdp.send('Fetch.fulfillRequest', {
            requestId,
            responseCode: 200,
            responseHeaders: (responseHeaders || []).filter(
              (h) => !/^(content-length|content-encoding)$/i.test(h.name),
            ),
            body: Buffer.from(rewritten).toString('base64'),
          });
        } catch {
          await cdp.send('Fetch.continueRequest', { requestId }).catch(() => {});
        }
      },
    );
  }

  const log = { requests: [], docHeaders: {} };
  const scriptIds = new Map();
  cdp.on('Network.requestWillBeSent', ({ requestId, request, type }) => {
    if (!request.url.startsWith('http') || log.requests.length >= MAX_REQUESTS) return;
    const { host, path } = splitUrl(request.url);
    log.requests.push({ host, path, type: (type || 'Other').toLowerCase() });
    if (onOsanoSource && osano.isScriptUrl(request.url)) scriptIds.set(requestId, true);
  });
  cdp.on('Network.responseReceived', ({ type, response }) => {
    if (type === 'Document' && response.url === page.url()) log.docHeaders = response.headers || {};
  });
  cdp.on('Network.loadingFinished', ({ requestId }) => {
    if (!scriptIds.has(requestId)) return;
    scriptIds.delete(requestId);
    cdp
      .send('Network.getResponseBody', { requestId })
      .then(({ body, base64Encoded }) =>
        onOsanoSource(Buffer.from(body, base64Encoded ? 'base64' : 'utf8').toString('utf8')),
      )
      .catch(() => {});
  });

  return { context, page, cdp, log };
};

// Cookie metadata only: values are never read into the result
const cookieMeta = (cookies, siteBase) =>
  cookies.map((c) => {
    const domain = (c.domain || '').replace(/^\./, '');
    return {
      name: c.name,
      domain: c.domain,
      path: c.path,
      expires: c.session || !(c.expires > 0) ? 'session' : new Date(c.expires * 1000).toISOString(),
      httpOnly: !!c.httpOnly,
      secure: !!c.secure,
      sameSite: c.sameSite || null,
      size: c.size,
      firstParty: baseDomain(domain) === siteBase,
    };
  });

// Roll a page's requests into scripts and third-party hosts
const summariseRequests = (requests, siteBase) => {
  const scripts = new Map();
  const hosts = new Map();
  for (const r of requests) {
    const thirdParty = baseDomain(r.host) !== siteBase;
    if (r.type === 'script') {
      const key = `${r.host}${r.path}`;
      if (!scripts.has(key)) scripts.set(key, { host: r.host, path: r.path, thirdParty });
    }
    if (!thirdParty) continue;
    const h = hosts.get(r.host) || { host: r.host, count: 0, types: {}, paths: [] };
    h.count++;
    h.types[r.type] = (h.types[r.type] || 0) + 1;
    if (h.paths.length < 5 && !h.paths.includes(r.path)) h.paths.push(r.path);
    hosts.set(r.host, h);
  }
  return {
    scripts: [...scripts.values()],
    requests: [...hosts.values()].sort((a, b) => b.count - a.count),
  };
};

// Load one path and capture what it produced
// With navigate: false, capture the current document as is (requests logged since the last reset)
const visit = async ({ page, cdp, log }, origin, path, siteBase, { navigate = true } = {}) => {
  let navError = null;
  if (navigate) {
    log.requests = [];
    log.docHeaders = {};
    try {
      await page.goto(new URL(path, origin).href, {
        waitUntil: 'domcontentloaded',
        timeout: NAV_TIMEOUT,
      });
    } catch (err) {
      navError = err.message;
    }
  }
  await page.waitForNetworkIdle(IDLE).catch(() => {});
  const title = await page.title().catch(() => '');
  const blocked = isBotCheck(title, log.docHeaders);
  const osanoLoaded = blocked ? false : await osano.detect(page, 4000);
  await sleep(1500); // let consent-gated tags fire
  const [osanoState, extras, { cookies = [] }] = await Promise.all([
    osanoLoaded ? osano.readState(page) : { loaded: false },
    page.evaluate(readPageExtras).catch(() => ({ storage: {}, inlineScripts: 0 })),
    cdp.send('Network.getAllCookies').catch(() => ({})),
  ]);
  const { scripts, requests } = summariseRequests(log.requests, siteBase);
  return {
    path,
    ...(navigate ? {} : { phase: 'after-consent' }),
    title,
    blocked,
    ...(navError ? { error: navError } : {}),
    osano: osanoState,
    cookies: cookieMeta(cookies, siteBase),
    scripts,
    inlineScripts: extras.inlineScripts,
    requests,
    storage: extras.storage,
  };
};

const runMode = async (browser, mode, ctx) => {
  const session = await openMode(browser, mode, {
    state: ctx.state,
    onOsanoSource: ctx.osanoSource ? null : (src) => (ctx.osanoSource ||= src),
  });
  const out = { status: 'ok', interaction: null, osano: null, pages: [] };
  try {
    // Interactive modes: set consent on the home page first, then browse with a clean log
    if (!['baseline', 'gpc'].includes(mode)) {
      ctx.progress(mode, 'setting consent');
      const setup = await visit(session, ctx.origin, '/', ctx.siteBase);
      if (setup.blocked) {
        out.status = 'blocked';
        out.error = 'Bot check page shown, could not interact with consent manager';
      } else {
        session.log.requests = [];
        out.interaction = await osano.applyMode(session.page, mode);
        if (!out.interaction.ok) {
          out.status = 'error';
          out.error = `Consent interaction failed: ${out.interaction.error}`;
        }
        // What the same document does once the choice is saved, before any reload
        out.pages.push(await visit(session, ctx.origin, '/', ctx.siteBase, { navigate: false }));
      }
    }
    for (let i = 0; i < ctx.pages.length; i++) {
      if (Date.now() > ctx.deadline) {
        out.status = out.status === 'ok' ? 'partial' : out.status;
        out.error ||= 'Job time limit reached';
        break;
      }
      let path = ctx.pages[i];
      if (path === PRODUCT) {
        if (!ctx.productPath) continue;
        path = ctx.productPath;
      }
      ctx.progress(mode, `page ${i + 1}/${ctx.pages.length}: ${path}`);
      const result = await visit(session, ctx.origin, path, ctx.siteBase);
      out.pages.push(result);
      if (path === ctx.profile?.search && ctx.productPath === undefined && !result.blocked) {
        ctx.productPath = await findProductLink(session.page, ctx.profile.productLink);
      }
    }
    const last = out.pages.findLast((p) => p.osano?.loaded);
    out.osano = last?.osano || { loaded: false };
    if (out.pages.length && out.pages.every((p) => p.blocked)) out.status = 'blocked';
  } finally {
    await session.context.close().catch(() => {});
  }
  return out;
};

// Build the cross-mode comparison tables
const buildMatrix = (modes, config) => {
  const cookies = new Map();
  const hosts = new Map();
  const scripts = new Map();
  const cls = config?.classification || {};
  for (const [mode, res] of Object.entries(modes)) {
    for (const page of res.pages || []) {
      for (const c of page.cookies) {
        const key = `${c.name}@${c.domain}`;
        const row = cookies.get(key) || {
          key,
          name: c.name,
          domain: c.domain,
          firstParty: c.firstParty,
          adTag: domainTag(c.domain),
          category: osano.classify(cls.cookies, c.name),
          presentIn: [],
        };
        if (!row.presentIn.includes(mode)) row.presentIn.push(mode);
        cookies.set(key, row);
      }
      for (const r of page.requests) {
        const row = hosts.get(r.host) || {
          host: r.host,
          paths: [],
          types: {},
          presentIn: [],
          requestsByMode: {},
        };
        if (!row.presentIn.includes(mode)) row.presentIn.push(mode);
        row.requestsByMode[mode] = (row.requestsByMode[mode] || 0) + r.count;
        for (const [t, n] of Object.entries(r.types)) row.types[t] = (row.types[t] || 0) + n;
        for (const p of r.paths)
          if (row.paths.length < 8 && !row.paths.includes(p)) row.paths.push(p);
        hosts.set(r.host, row);
      }
      for (const s of page.scripts) {
        const key = `${s.host}${s.path}`;
        const row = scripts.get(key) || { key, thirdParty: s.thirdParty, presentIn: [] };
        if (!row.presentIn.includes(mode)) row.presentIn.push(mode);
        scripts.set(key, row);
      }
    }
  }
  const hostCategory = (row) => {
    if (!config?.available) return null;
    for (const p of ['/', ...row.paths]) {
      const url = `https://${row.host}${p}`;
      const hit = osano.classify(cls.scripts, url) || osano.classify(cls.iframes, url);
      if (hit) return hit;
    }
    return 'UNCLASSIFIED';
  };
  return {
    cookies: [...cookies.values()].sort((a, b) => a.key.localeCompare(b.key)),
    hosts: [...hosts.values()]
      .map(({ paths, ...row }) => ({
        ...row,
        adTag: domainTag(row.host, paths),
        osanoCategory: hostCategory({ ...row, paths }),
      }))
      .sort((a, b) => a.host.localeCompare(b.host)),
    scripts: [...scripts.values()].sort((a, b) => a.key.localeCompare(b.key)),
  };
};

export const audit = async ({ origin, host, modes, pages, state }, report = () => {}) => {
  const start = Date.now();
  const status = Object.fromEntries(modes.map((m) => [m, 'queued']));
  const ctx = {
    origin,
    siteBase: baseDomain(host),
    pages,
    state,
    profile: SITE_PROFILES[baseDomain(host)] || null,
    productPath: pages.includes(PRODUCT) ? undefined : null,
    osanoSource: null,
    deadline: start + JOB_TIMEOUT - 30000,
    progress: (mode, msg) => {
      status[mode] = msg;
      report({ ...status });
    },
  };
  report({ ...status });

  let browser;
  try {
    browser = await launchBrowser();
  } catch (err) {
    if (isBrowserMissing(err)) return { skipped: err.message };
    throw err;
  }
  const results = {};
  try {
    for (const mode of modes) {
      if (Date.now() > ctx.deadline) {
        results[mode] = { status: 'skipped', error: 'Job time limit reached', pages: [] };
        ctx.progress(mode, 'skipped');
        continue;
      }
      ctx.progress(mode, 'starting');
      try {
        results[mode] = await runMode(browser, mode, ctx);
      } catch (err) {
        results[mode] = { status: 'error', error: err.message, pages: [] };
      }
      ctx.progress(mode, results[mode].status);
    }
    const osanoConfig = ctx.osanoSource
      ? await osano.readConfig(browser, ctx.osanoSource)
      : { available: false, reason: 'osano.js was not seen on any page' };
    const matrix = buildMatrix(results, osanoConfig);
    // Keep the classification map to the hosts actually seen
    if (osanoConfig.available) {
      osanoConfig.classifiedHosts = Object.fromEntries(
        matrix.hosts.map((h) => [h.host, h.osanoCategory]),
      );
      osanoConfig.classificationCounts = Object.fromEntries(
        Object.entries(osanoConfig.classification).map(([k, v]) => [k, Object.keys(v).length]),
      );
      delete osanoConfig.classification;
    }
    const resolvedPages = pages.map((p) => (p === PRODUCT ? ctx.productPath : p)).filter(Boolean);
    return {
      site: origin,
      pages: resolvedPages,
      state: state || null,
      simulated: !!state,
      cmp: osano.name,
      blockedPages: Object.values(results).reduce(
        (n, r) => n + (r.pages || []).filter((pg) => pg.blocked).length,
        0,
      ),
      modes: results,
      matrix,
      osanoConfig,
      timeTaken: Date.now() - start,
    };
  } finally {
    await closeBrowser(browser);
  }
};

const consentAuditHandler = async (url, request) => {
  const { hostname, port, protocol } = parseTarget(url);
  const origin = `${protocol}//${hostname}${port ? `:${port}` : ''}`;
  const query = getQuery(request);

  const requested = parseList(query.modes).map((m) =>
    m.toLowerCase().startsWith('deny-') ? `deny-${m.slice(5).toUpperCase()}` : m.toLowerCase(),
  );
  const unknown = requested.filter((m) => !MODES.includes(m) && !/^deny-[A-Z_]{2,30}$/.test(m));
  if (unknown.length) {
    return { error: `Unknown modes: ${unknown.join(', ')}. Valid: ${MODES.join(', ')}` };
  }
  const modes = requested.length ? [...new Set(requested)] : MODES;

  let pages = parseList(query.pages);
  if (pages.length > MAX_PAGES) return { error: `At most ${MAX_PAGES} pages allowed` };
  const bad = pages.filter((p) => !validPath(p, origin));
  if (bad.length)
    return { error: `Pages must be same-origin paths starting with /: ${bad.join(', ')}` };
  if (!pages.length) pages = defaultPages(hostname);
  pages = [...new Set(pages)];

  const state = String(query.state || '')
    .trim()
    .toLowerCase();
  if (state && !US_STATES.includes(state)) return { error: `Unknown US state code: ${state}` };

  const key = `consent|${origin}|${modes.join(',')}|${pages.join(',')}|${state}`;
  const result = await runJob(
    key,
    (report) => audit({ origin, host: hostname, modes, pages, state }, report),
    {
      waitMs: WAIT_BEFORE_PENDING,
      ttlMs: RESULT_TTL,
    },
  );
  if (!result.pending) return result;
  return { ...result, site: origin, requestedModes: modes, pages, state: state || null };
};

export const handler = middleware(consentAuditHandler);
export default handler;
