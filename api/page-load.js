import crypto from 'crypto';
import middleware from './_common/middleware.js';
import { baseDomain } from './_common/parse-target.js';
import { launchBrowser, openPage, closeBrowser, isBrowserMissing } from './_common/browser.js';

const NAV_TIMEOUT = 15000;
const IDLE = { idleTime: 800, timeout: 6000 };
const MAX_REQUESTS = 300;
const MAX_HASH_BYTES = 5 * 1024 * 1024;
const MAX_CONSOLE = 50;
const MAX_GLOBALS = 100;
const MAX_SCAN_BYTES = 2 * 1024 * 1024;
const DOWNLOAD_MIME =
  /octet-stream|x-msdownload|x-msi|zip|x-7z|x-rar|x-tar|gzip|android\.package|x-apple-diskimage|x-executable|x-sh|java-archive/i;

// Tracking IDs worth pulling out of the page source
const ID_PATTERNS = [
  ['Google Analytics (UA)', /\bUA-\d{4,10}-\d{1,4}\b/g],
  ['Google Analytics (GA4)', /\bG-[A-Z0-9]{6,12}\b/g],
  ['Google Tag Manager', /\bGTM-[A-Z0-9]{4,10}\b/g],
  ['Google AdSense', /\bca-pub-\d{10,20}\b/g],
  ['Facebook Pixel', /fbq\(\s*['"]init['"]\s*,\s*['"](\d{8,20})['"]/g],
  ['Hotjar', /\bhjid\s*[:=]\s*(\d{5,10})/g],
  ['Microsoft Clarity', /clarity\.ms\/tag\/([a-z0-9]{6,12})/gi],
  [
    'Microsoft Clarity',
    /\(window,\s*document,\s*["']clarity["'],\s*["']script["'],\s*["']([a-z0-9]{6,12})["']/gi,
  ],
  ['Yandex Metrica', /\bym\(\s*(\d{5,10})\s*,\s*['"]init['"]/g],
  ['Yandex Metrica', /mc\.yandex\.ru\/watch\/(\d{5,10})/g],
];

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const hostOf = (u) => {
  try {
    return new URL(u).hostname;
  } catch {
    return '';
  }
};
const trim = (s, n = 300) => (s.length > n ? `${s.slice(0, n)}…` : s);
const pct = (n, total) => (total ? Math.round((n / total) * 1000) / 10 : 0);
const tally = (list) => list.reduce((acc, k) => ((acc[k] = (acc[k] || 0) + 1), acc), {});

// Validate the optional ua / referer query params
const parseOptions = (request) => {
  const q = request?.query || request?.queryStringParameters || {};
  const ua = typeof q.ua === 'string' && q.ua.trim() ? q.ua.trim().slice(0, 300) : null;
  let referer = null;
  if (typeof q.referer === 'string' && /^https?:\/\//i.test(q.referer)) {
    try {
      referer = new URL(q.referer).href;
    } catch {
      /* ignore bad referer */
    }
  }
  return { ua, referer };
};

// Match tracking IDs across some text blobs, deduped
const findIdentifiers = (texts) => {
  const seen = new Map();
  for (const text of texts) {
    for (const [type, re] of ID_PATTERNS) {
      for (const m of text.matchAll(re)) {
        const id = m[1] || m[0];
        seen.set(`${type}|${id}`, { type, id });
      }
    }
  }
  return [...seen.values()];
};

// True if the response looks like a file download rather than page content
const isDownload = (headers = {}, mime = '') => {
  const disposition = headers['content-disposition'] || headers['Content-Disposition'] || '';
  return /attachment/i.test(disposition) || DOWNLOAD_MIME.test(mime);
};

// Window properties the page added, versus a blank iframe's window
const readGlobals = (max) => {
  const frame = document.createElement('iframe');
  frame.style.display = 'none';
  document.body.appendChild(frame);
  const standard = new Set(Object.getOwnPropertyNames(frame.contentWindow));
  frame.remove();
  return Object.keys(window)
    .filter((k) => !standard.has(k))
    .slice(0, max);
};

// Keys (never values) from web storage
const readStorage = () => {
  const keys = (s) => {
    try {
      return Object.keys(s);
    } catch {
      return [];
    }
  };
  return { localStorage: keys(window.localStorage), sessionStorage: keys(window.sessionStorage) };
};

// Load the page once and record everything it does
const capture = async (url, { ua, referer }) => {
  const browser = await launchBrowser();
  try {
    const page = await openPage(browser);
    if (ua) await page.setUserAgent({ userAgent: ua });
    if (referer) await page.setExtraHTTPHeaders({ referer });
    page.on('dialog', (d) => d.dismiss().catch(() => {}));

    const cdp = await page.createCDPSession();
    await cdp.send('Network.enable');
    await cdp
      .send('Browser.setDownloadBehavior', { behavior: 'deny' })
      .catch(() => cdp.send('Page.setDownloadBehavior', { behavior: 'deny' }).catch(() => {}));

    const reqs = new Map();
    const websockets = new Set();
    const consoleMsgs = [];
    const pageErrors = [];
    const navigations = [];
    const pending = [];

    cdp.on(
      'Network.requestWillBeSent',
      ({ requestId, request, type, initiator, redirectResponse }) => {
        if (!request.url.startsWith('http')) return;
        if (redirectResponse && reqs.has(requestId)) {
          // Archive the redirect hop under its own key
          const prev = reqs.get(requestId);
          Object.assign(prev, {
            status: redirectResponse.status,
            ip: redirectResponse.remoteIPAddress || null,
            protocol: redirectResponse.protocol || null,
          });
          reqs.set(`${requestId}:${reqs.size}`, prev);
        }
        if (reqs.size >= MAX_REQUESTS && !reqs.has(requestId)) return;
        reqs.set(requestId, {
          url: request.url,
          domain: hostOf(request.url),
          type: (type || 'Other').toLowerCase(),
          method: request.method,
          status: null,
          mimeType: null,
          size: 0,
          ip: null,
          protocol: null,
          sha256: null,
          initiator: initiator?.type || null,
          headers: null,
        });
      },
    );
    cdp.on('Network.responseReceived', ({ requestId, response }) => {
      const r = reqs.get(requestId);
      if (!r) return;
      Object.assign(r, {
        status: response.status,
        mimeType: response.mimeType,
        ip: response.remoteIPAddress || null,
        protocol: response.protocol || null,
        headers: response.headers,
      });
    });
    cdp.on('Network.loadingFinished', ({ requestId, encodedDataLength }) => {
      const r = reqs.get(requestId);
      if (!r) return;
      r.size = encodedDataLength || 0;
      if (r.size > MAX_HASH_BYTES || r.status === null || (r.status >= 300 && r.status < 400))
        return;
      pending.push(
        cdp
          .send('Network.getResponseBody', { requestId })
          .then(({ body, base64Encoded }) => {
            const buf = Buffer.from(body, base64Encoded ? 'base64' : 'utf8');
            if (buf.length > MAX_HASH_BYTES) return;
            r.sha256 = sha256(buf);
            if (['script', 'document'].includes(r.type) && buf.length < MAX_SCAN_BYTES)
              r.text = buf.toString('utf8');
          })
          .catch(() => {}),
      );
    });
    cdp.on('Network.webSocketCreated', ({ url: wsUrl }) => websockets.add(wsUrl));

    page.on('console', (msg) => {
      const type = msg.type();
      if (!['error', 'warn', 'warning'].includes(type) || consoleMsgs.length >= MAX_CONSOLE) return;
      consoleMsgs.push({ type: type === 'warn' ? 'warning' : type, text: trim(msg.text()) });
    });
    page.on('pageerror', (err) => {
      if (pageErrors.length < MAX_CONSOLE) pageErrors.push(trim(String(err?.message || err)));
    });
    page.on('framenavigated', (frame) => {
      if (frame === page.mainFrame()) navigations.push(frame.url());
    });

    let response = null;
    let navError = null;
    try {
      response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: NAV_TIMEOUT });
    } catch (error) {
      navError = error.message;
    }
    await page.waitForNetworkIdle(IDLE).catch(() => {});
    if (!response && navError) throw new Error(navError);

    // HTTP redirect hops for the main document
    const chain = response?.request().redirectChain() || [];
    const httpRedirects = chain.map((req) => ({
      url: req.url(),
      status: req.response()?.status() ?? null,
    }));

    const [title, html, globals, storage] = await Promise.all([
      page.title().catch(() => ''),
      page.content().catch(() => ''),
      page.evaluate(readGlobals, MAX_GLOBALS).catch(() => []),
      page.evaluate(readStorage).catch(() => ({ localStorage: [], sessionStorage: [] })),
    ]);
    // Give body fetches a brief window to finish
    await Promise.race([Promise.allSettled(pending), new Promise((r) => setTimeout(r, 3000))]);

    return {
      response,
      httpRedirects,
      navigations,
      title,
      html,
      globals,
      storage,
      reqs: [...reqs.values()],
      websockets: [...websockets],
      consoleMsgs,
      pageErrors,
    };
  } finally {
    await closeBrowser(browser);
  }
};

// Roll requests up into per-domain, protocol and type counts
const summarise = (requests) => {
  const domains = {};
  for (const r of requests) {
    domains[r.domain] ??= { domain: r.domain, requests: 0, bytes: 0, thirdParty: r.thirdParty };
    domains[r.domain].requests += 1;
    domains[r.domain].bytes += r.size;
  }
  const total = requests.length;
  return {
    domains: Object.values(domains).sort((a, b) => b.requests - a.requests),
    ips: [...new Set(requests.map((r) => r.ip).filter(Boolean))],
    protocols: tally(requests.map((r) => r.protocol || 'unknown')),
    types: tally(requests.map((r) => r.type)),
    totals: {
      requests: total,
      bytes: requests.reduce((n, r) => n + r.size, 0),
      httpsPct: pct(requests.filter((r) => r.url.startsWith('https:')).length, total),
      ipv6Pct: pct(
        requests.filter((r) => r.ip?.includes(':')).length,
        requests.filter((r) => r.ip).length,
      ),
      thirdPartyPct: pct(requests.filter((r) => r.thirdParty).length, total),
    },
  };
};

// Load a page in a real browser and report its requests, redirects, downloads and scripts
const pageLoadHandler = async (url, request) => {
  const options = parseOptions(request);
  const started = Date.now();
  let visit;
  try {
    visit = await capture(url, options);
  } catch (error) {
    if (isBrowserMissing(error)) return { skipped: error.message };
    return { error: `Couldn't load page: ${error.message}` };
  }
  const finalUrl = visit.response?.url() || visit.navigations.at(-1) || url;
  const siteBase = baseDomain(hostOf(finalUrl));

  const requests = visit.reqs.map(({ headers, text, ...r }) => ({
    ...r,
    thirdParty: !!r.domain && baseDomain(r.domain) !== siteBase,
  }));
  const downloads = visit.reqs
    .filter(
      (r) =>
        r.status &&
        r.status < 300 &&
        r.type !== 'document' &&
        isDownload(r.headers || {}, r.mimeType || ''),
    )
    .map((r) => ({ url: r.url, mimeType: r.mimeType, size: r.size, sha256: r.sha256 }));
  // A document whose response was itself a download
  const mainReq = visit.reqs.find((r) => r.type === 'document' && r.url === finalUrl);
  if (mainReq && isDownload(mainReq.headers || {}, mainReq.mimeType || '')) {
    downloads.push({
      url: mainReq.url,
      mimeType: mainReq.mimeType,
      size: mainReq.size,
      sha256: mainReq.sha256,
    });
  }

  const scripts = visit.reqs.map((r) => r.text).filter(Boolean);
  const navChain = visit.navigations.filter((u, i, a) => u !== 'about:blank' && u !== a[i - 1]);

  return {
    url,
    finalUrl,
    title: visit.title,
    status: visit.response?.status() ?? null,
    options: { userAgent: options.ua, referer: options.referer },
    redirects: {
      http: visit.httpRedirects,
      navigations: navChain,
      count: visit.httpRedirects.length + Math.max(0, navChain.length - 1),
    },
    requests,
    ...summarise(requests),
    downloads,
    console: visit.consoleMsgs,
    pageErrors: visit.pageErrors,
    websockets: visit.websockets,
    storage: visit.storage,
    globals: visit.globals,
    identifiers: findIdentifiers([visit.html, ...scripts]),
    dom: { length: visit.html.length, sha256: sha256(visit.html) },
    timeMs: Date.now() - started,
  };
};

export const handler = middleware(pageLoadHandler);
export default handler;
