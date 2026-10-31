import dns from 'dns';
import net from 'net';
import crypto from 'crypto';
import middleware from './_common/middleware.js';
import { parseTarget, baseDomain } from './_common/parse-target.js';
import { UA, isBotCheck } from './_common/http.js';
import { TLDS, permutations, resolveWithTimeout, mapLimit } from './typosquat.js';

const MAX_CANDIDATES = 200;
const DNS_CONCURRENCY = 30;
const DNS_TIMEOUT = 2000;
const MAX_SUSPECTS = 40;
const FETCH_CONCURRENCY = 8;
const FETCH_TIMEOUT = 5000;
const MAX_BODY = 512 * 1024;
const DEADLINE = 27000;

// MurmurHash3 x86_32 over raw bytes, returned as a signed int like Python's mmh3.hash
const murmur3 = (bytes, seed = 0) => {
  let h = seed >>> 0;
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;
  const len = bytes.length;
  const blocks = len & ~3;
  for (let i = 0; i < blocks; i += 4) {
    let k = bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24);
    k = Math.imul(k, c1);
    k = (k << 15) | (k >>> 17);
    k = Math.imul(k, c2);
    h ^= k;
    h = (h << 13) | (h >>> 19);
    h = (Math.imul(h, 5) + 0xe6546b64) | 0;
  }
  let k = 0;
  switch (len & 3) {
    case 3:
      k ^= bytes[blocks + 2] << 16;
    // falls through
    case 2:
      k ^= bytes[blocks + 1] << 8;
    // falls through
    case 1:
      k ^= bytes[blocks];
      k = Math.imul(k, c1);
      k = (k << 15) | (k >>> 17);
      k = Math.imul(k, c2);
      h ^= k;
  }
  h ^= len;
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b);
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35);
  h ^= h >>> 16;
  return h | 0;
};

// Shodan's favicon hash: mmh3 of base64 with a newline every 76 chars (Python's encodebytes)
const faviconMmh3 = (buf) => {
  const b64 = buf.toString('base64');
  const lines = b64.match(/.{1,76}/g) || [];
  const encoded = lines.map((l) => l + '\n').join('');
  return murmur3(Buffer.from(encoded, 'ascii'));
};

// Fetch with a timeout, reading at most MAX_BODY bytes of the body
const fetchCapped = async (url, deadline, timeout = FETCH_TIMEOUT) => {
  const remaining = deadline - Date.now();
  if (remaining < 500) throw new Error('Out of time');
  const res = await fetch(url, {
    headers: { 'user-agent': UA, accept: '*/*' },
    redirect: 'follow',
    signal: AbortSignal.timeout(Math.min(timeout, remaining)),
  });
  const chunks = [];
  let size = 0;
  if (res.body) {
    const reader = res.body.getReader();
    try {
      while (size < MAX_BODY) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        size += value.length;
      }
    } finally {
      reader.cancel().catch(() => {});
    }
  }
  const body = Buffer.concat(chunks).subarray(0, MAX_BODY);
  return {
    status: res.status,
    finalUrl: res.url,
    body,
    type: res.headers.get('content-type') || '',
  };
};

const decode = (s) =>
  s
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&#x27;/g, "'")
    .replace(/\s+/g, ' ')
    .trim();

const getTitle = (html) => {
  const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return m ? decode(m[1]).slice(0, 200) : null;
};

const getAttr = (tag, name) => {
  const m = tag.match(new RegExp(`\\b${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'));
  return m ? (m[2] ?? m[3] ?? m[4]) : null;
};

const getSiteName = (html) => {
  for (const tag of html.match(/<meta\b[^>]*>/gi) || []) {
    if ((getAttr(tag, 'property') || getAttr(tag, 'name') || '').toLowerCase() === 'og:site_name') {
      return decode(getAttr(tag, 'content') || '') || null;
    }
  }
  return null;
};

const getIconHref = (html) => {
  for (const tag of html.match(/<link\b[^>]*>/gi) || []) {
    const rel = (getAttr(tag, 'rel') || '').toLowerCase().split(/\s+/);
    if (rel.includes('icon')) return getAttr(tag, 'href');
  }
  return null;
};

const bodyText = (html) =>
  html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .toLowerCase();

const hasPasswordInput = (html) => /<input\b[^>]*\btype\s*=\s*["']?password\b/i.test(html);

const hostOf = (u) => {
  try {
    return new URL(u).hostname.toLowerCase();
  } catch {
    return '';
  }
};

// Fetch a page over https, falling back to http
const fetchPage = async (domain, deadline) => {
  for (const scheme of ['https', 'http']) {
    try {
      return await fetchCapped(`${scheme}://${domain}/`, deadline);
    } catch {
      /* try the next scheme */
    }
  }
  return null;
};

// Fetch and hash the favicon declared in the page, or /favicon.ico
const fetchFavicon = async (html, pageUrl, deadline) => {
  const urls = [];
  const href = getIconHref(html);
  if (href && !href.startsWith('data:')) {
    try {
      urls.push(new URL(href, pageUrl).href);
    } catch {
      /* ignore bad href */
    }
  }
  try {
    urls.push(new URL('/favicon.ico', pageUrl).href);
  } catch {
    /* ignore */
  }
  for (const u of [...new Set(urls)]) {
    try {
      const res = await fetchCapped(u, deadline);
      if (res.status !== 200 || !res.body.length || /text\/html/i.test(res.type)) continue;
      return {
        url: u,
        mmh3: faviconMmh3(res.body),
        sha256: crypto.createHash('sha256').update(res.body).digest('hex'),
      };
    } catch {
      /* try the next one */
    }
  }
  return null;
};

const verdictFor = (score) =>
  score >= 60 ? 'likely impersonation' : score >= 30 ? 'suspicious' : 'benign/parked';

const brandImpersonationHandler = async (url) => {
  const deadline = Date.now() + DEADLINE;
  const { hostname } = parseTarget(url);
  if (net.isIP(hostname))
    return { skipped: 'Brand impersonation checks only apply to domain names' };
  const domain = baseDomain(hostname);
  const dot = domain.indexOf('.');
  if (dot < 1) return { skipped: 'Could not resolve a registrable domain' };
  const brand = domain.slice(0, dot).toLowerCase();
  const tld = domain.slice(dot + 1);

  // Fingerprint the real site and find registered lookalikes at the same time
  const fingerprintTask = (async () => {
    const page = await fetchPage(hostname, deadline);
    const html = page ? page.body.toString('utf8') : '';
    const favicon = page ? await fetchFavicon(html, page.finalUrl, deadline) : null;
    const rawTitle = getTitle(html);
    // A bot check or error page's title (e.g. "Just a moment...", "403") says nothing about the brand
    const botCheck =
      !page ||
      page.status >= 400 ||
      isBotCheck({ status: page.status, headers: {}, data: html }) ||
      /^(just a moment|attention required|access denied)/i.test(rawTitle || '');
    return {
      title: botCheck ? null : rawTitle,
      botCheck,
      siteName: getSiteName(html),
      faviconUrl: favicon?.url || null,
      faviconMmh3: favicon?.mmh3 ?? null,
      faviconSha256: favicon?.sha256 || null,
    };
  })();

  const lookalikeTask = (async () => {
    const tldSwaps = TLDS.filter((t) => t !== tld).map((t) => `${brand}.${t}`);
    const labelSwaps = permutations(brand).map((l) => `${l}.${tld}`);
    const candidates = [...new Set([...tldSwaps, ...labelSwaps])].slice(0, MAX_CANDIDATES);
    const resolver = new dns.Resolver({ timeout: DNS_TIMEOUT, tries: 1 });
    const resolved = await mapLimit(candidates, DNS_CONCURRENCY, async (d) =>
      (await resolveWithTimeout(resolver, 'resolve4', d)).length ? d : null,
    );
    return { candidates: candidates.length, registered: resolved.filter(Boolean) };
  })();

  const [fingerprint, { candidates, registered }] = await Promise.all([
    fingerprintTask,
    lookalikeTask,
  ]);
  const targets = registered.slice(0, MAX_SUSPECTS);
  const realTitle = fingerprint.title?.toLowerCase();

  const suspects = await mapLimit(targets, FETCH_CONCURRENCY, async (d) => {
    const page = await fetchPage(d, deadline);
    if (!page) {
      return {
        domain: d,
        finalUrl: null,
        status: null,
        title: null,
        score: 0,
        verdict: 'unreachable',
        signals: [],
      };
    }
    const finalHost = hostOf(page.finalUrl);
    const title = getTitle(page.body.toString('utf8'));
    const base = { domain: d, finalUrl: page.finalUrl, status: page.status, title };
    if (finalHost === domain || finalHost.endsWith(`.${domain}`)) {
      return { ...base, score: 0, verdict: 'redirects-to-brand', signals: ['redirects-to-brand'] };
    }
    const html = page.body.toString('utf8');
    const signals = [];
    let score = 0;
    if (fingerprint.faviconMmh3 !== null) {
      const fav = await fetchFavicon(html, page.finalUrl, deadline);
      if (fav && fav.sha256 === fingerprint.faviconSha256) {
        score += 50;
        signals.push('same-favicon');
      }
    }
    const t = title?.toLowerCase() || '';
    if (t && (t.includes(brand) || t === realTitle)) {
      score += 30;
      signals.push('brand-in-title');
    }
    if (bodyText(html).includes(brand)) {
      score += 10;
      signals.push('brand-in-body');
    }
    if (hasPasswordInput(html)) {
      score += 20;
      signals.push('login-form');
    }
    return { ...base, score, verdict: verdictFor(score), signals };
  });

  suspects.sort((a, b) => b.score - a.score);
  return {
    brand,
    domain,
    fingerprint,
    candidates,
    registered: registered.length,
    checked: targets.length,
    suspects,
  };
};

export const handler = middleware(brandImpersonationHandler);
export default handler;
