import net from 'net';
import middleware from './_common/middleware.js';
import { httpGet } from './_common/http.js';
import { parseTarget, baseDomain } from './_common/parse-target.js';
import { upstreamError } from './_common/upstream.js';

const BASE = 'https://urlscan.io';
const SEARCH_SIZE = 20;

// Optional key only raises rate limits for search; result API needs it though
const authHeaders = () =>
  process.env.URLSCAN_API_KEY ? { 'API-Key': process.env.URLSCAN_API_KEY } : {};

// Drop query strings and fragments, other people's scans can carry signed tokens
const stripQuery = (u) => (u ? u.split(/[?#]/)[0] : null);

const mapScan = (r) => {
  const uuid = r._id || r.task?.uuid;
  return {
    uuid,
    time: r.task?.time || null,
    url: stripQuery(r.task?.url),
    pageUrl: stripQuery(r.page?.url),
    ip: r.page?.ip || null,
    country: r.page?.country || null,
    asn: r.page?.asn || null,
    asnname: r.page?.asnname || null,
    server: r.page?.server || null,
    title: r.page?.title || null,
    status: r.page?.status ? Number(r.page.status) || r.page.status : null,
    screenshot: `${BASE}/screenshots/${uuid}.png`,
    reportUrl: `${BASE}/result/${uuid}/`,
    ...(r.verdicts?.malicious !== undefined ? { malicious: !!r.verdicts.malicious } : {}),
  };
};

// Result API needs a key (returns 403 "not logged in" anonymously), so verdicts are best-effort
const fetchVerdicts = async (uuid) => {
  if (!process.env.URLSCAN_API_KEY) {
    return {
      available: false,
      reason: 'Set URLSCAN_API_KEY to include verdicts of the newest scan',
    };
  }
  try {
    const res = await httpGet(`${BASE}/api/v1/result/${uuid}/`, {
      headers: authHeaders(),
      timeout: 8000,
    });
    const o = res.data?.verdicts?.overall || {};
    const lists = res.data?.lists || {};
    const count = (k) => (Array.isArray(lists[k]) ? lists[k].length : 0);
    return {
      available: true,
      uuid,
      score: o.score ?? null,
      malicious: !!o.malicious,
      categories: o.categories || [],
      brands: o.brands || [],
      tags: o.tags || [],
      counts: {
        ips: count('ips'),
        domains: count('domains'),
        countries: count('countries'),
        certificates: count('certificates'),
      },
    };
  } catch (error) {
    const status = error.response?.status;
    return {
      available: false,
      reason:
        status === 429
          ? 'urlscan.io result API rate-limited'
          : `Result fetch failed${status ? ` (HTTP ${status})` : ''}`,
    };
  }
};

// Read-only lookup of existing public scans; never submits a new scan (that would publish the target)
const urlscanHandler = async (url) => {
  const { hostname } = parseTarget(url);
  const isIp = net.isIP(hostname);
  const domain = isIp ? hostname : baseDomain(hostname);
  const q = isIp
    ? `page.ip:"${hostname}"`
    : `task.apexDomain:${domain} OR page.apexDomain:${domain}`;
  try {
    const res = await httpGet(
      `${BASE}/api/v1/search/?q=${encodeURIComponent(q)}&size=${SEARCH_SIZE}`,
      { headers: authHeaders(), timeout: 10000 },
    );
    const results = res.data?.results || [];
    if (!results.length) return { skipped: `No public urlscan.io scans found for ${domain}` };
    // Search is newest-first by default, sort defensively anyway
    const scans = results.map(mapScan).sort((a, b) => (b.time || '').localeCompare(a.time || ''));
    const verdicts = await fetchVerdicts(scans[0].uuid);
    return { domain, total: res.data?.total ?? scans.length, scans, verdicts };
  } catch (error) {
    return upstreamError(error, 'urlscan.io');
  }
};

export const handler = middleware(urlscanHandler);
export default handler;
