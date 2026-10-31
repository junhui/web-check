import dns from 'dns/promises';
import middleware from './_common/middleware.js';
import { httpGet } from './_common/http.js';
import { parseTarget, baseDomain } from './_common/parse-target.js';

const MAX_NAMES = 50;
const CONCURRENCY = 10;
const FETCH_TIMEOUT = 5000;
const HOSTNAME_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;

// Services known to allow takeover, after can-i-take-over-xyz.
// cname: suffixes the CNAME target ends with; body: text on the unclaimed page;
// nxdomain: the service is claimable when the target itself does not resolve
const FINGERPRINTS = [
  { service: 'AWS S3', cname: ['amazonaws.com'], body: 'NoSuchBucket' },
  { service: 'GitHub Pages', cname: ['github.io'], body: "There isn't a GitHub Pages site here" },
  { service: 'Heroku', cname: ['herokuapp.com', 'herokudns.com'], body: 'No such app' },
  {
    service: 'Azure',
    cname: [
      'azurewebsites.net',
      'cloudapp.net',
      'cloudapp.azure.com',
      'trafficmanager.net',
      'blob.core.windows.net',
      'azureedge.net',
    ],
    nxdomain: true,
  },
  {
    service: 'Shopify',
    cname: ['myshopify.com'],
    body: 'Sorry, this shop is currently unavailable',
  },
  { service: 'Fastly', cname: ['fastly.net'], body: 'Fastly error: unknown domain' },
  { service: 'Netlify', cname: ['netlify.app', 'netlify.com'], body: 'Not Found - Request ID' },
  {
    service: 'Pantheon',
    cname: ['pantheonsite.io'],
    body: 'The gods are wise, but do not know of the site which you seek',
  },
  { service: 'Zendesk', cname: ['zendesk.com'], body: 'Help Center Closed' },
  { service: 'Ghost', cname: ['ghost.io'], body: 'Domain error' },
  { service: 'Surge.sh', cname: ['surge.sh'], body: 'project not found' },
  { service: 'Bitbucket', cname: ['bitbucket.io'], body: 'Repository not found' },
  {
    service: 'Unbounce',
    cname: ['unbouncepages.com'],
    body: 'The requested URL was not found on this server',
  },
  {
    service: 'Tumblr',
    cname: ['domains.tumblr.com'],
    body: "Whatever you were looking for doesn't currently exist at this address",
  },
  {
    service: 'HelpScout',
    cname: ['helpscoutdocs.com'],
    body: 'No settings were found for this company',
  },
  { service: 'Readme.io', cname: ['readme.io'], body: 'Project doesnt exist... yet!' },
  { service: 'Wordpress.com', cname: ['wordpress.com'], body: 'Do you want to register' },
  {
    service: 'Agile CRM',
    cname: ['agilecrm.com'],
    body: 'Sorry, this page is no longer available.',
  },
  { service: 'Strikingly', cname: ['s.strikinglydns.com'], body: 'PAGE NOT FOUND' },
  { service: 'Uptimerobot', cname: ['stats.uptimerobot.com'], body: 'page not found' },
];

const matchService = (cname) =>
  FINGERPRINTS.find((f) => f.cname.some((s) => cname === s || cname.endsWith(`.${s}`)));

// Same crt.sh source as subdomains.js, capped to keep the check quick
const fetchSubdomains = async (domain) => {
  const res = await httpGet('https://crt.sh/', {
    params: { q: `%.${domain}`, output: 'json' },
    headers: { Accept: 'application/json' },
    timeout: 8000,
  });
  if (!Array.isArray(res.data)) return [];
  const names = res.data
    .flatMap((row) => String(row?.name_value ?? '').split('\n'))
    .map((n) => n.trim().toLowerCase().replace(/^\*\./, ''))
    .filter((n) => n.endsWith(`.${domain}`) && HOSTNAME_RE.test(n));
  return [...new Set(names)].slice(0, MAX_NAMES);
};

// Run fn over items with at most `limit` in flight
const mapLimit = async (items, limit, fn) => {
  const out = new Array(items.length);
  let i = 0;
  const worker = async () => {
    while (i < items.length) {
      const idx = i++;
      out[idx] = await fn(items[idx]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
};

const isNxdomain = async (host) => {
  try {
    await dns.lookup(host);
    return false;
  } catch (e) {
    return e.code === 'ENOTFOUND';
  }
};

const fetchBody = async (host) => {
  for (const proto of ['https', 'http']) {
    try {
      const res = await httpGet(`${proto}://${host}/`, {
        timeout: FETCH_TIMEOUT,
        validateStatus: () => true,
      });
      return String(res.data ?? '');
    } catch {
      /* try next protocol */
    }
  }
  return '';
};

const checkName = async (subdomain) => {
  const cname = (await dns.resolveCname(subdomain).catch(() => []))[0]?.toLowerCase();
  if (!cname) return null;
  const fp = matchService(cname);
  if (await isNxdomain(cname)) {
    return {
      subdomain,
      cname,
      service: fp?.service || 'Unknown',
      evidence: 'Dangling CNAME: target is NXDOMAIN',
    };
  }
  if (fp?.body) {
    const body = await fetchBody(subdomain);
    if (body.includes(fp.body)) {
      return { subdomain, cname, service: fp.service, evidence: `Response contains "${fp.body}"` };
    }
  }
  return null;
};

const takeoverHandler = async (url) => {
  const { hostname } = parseTarget(url);
  const domain = baseDomain(hostname);
  if (!domain.includes('.') || /^[\d.:]+$/.test(domain)) {
    return { skipped: 'Takeover checks only apply to domain names' };
  }
  const subs = await fetchSubdomains(domain).catch(() => []);
  const names = [...new Set([hostname, ...subs])].slice(0, MAX_NAMES);
  const results = await mapLimit(names, CONCURRENCY, (n) => checkName(n).catch(() => null));
  return { checked: names.length, vulnerable: results.filter(Boolean) };
};

export const handler = middleware(takeoverHandler);
export default handler;
