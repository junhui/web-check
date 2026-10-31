import dns from 'dns/promises';
import net from 'net';
import middleware from './_common/middleware.js';
import { httpGet } from './_common/http.js';
import { parseTarget } from './_common/parse-target.js';
import { upstreamError } from './_common/upstream.js';

const MAX_RESULTS = 100;

const reverseIpHandler = async (url) => {
  const { hostname } = parseTarget(url);
  let ip = hostname;
  if (!net.isIP(hostname)) {
    try {
      ip = (await dns.resolve4(hostname))[0];
    } catch (error) {
      return upstreamError(error, 'DNS');
    }
  }

  let body;
  try {
    const res = await httpGet('https://api.hackertarget.com/reverseiplookup/', {
      params: { q: ip },
      timeout: 10000,
    });
    body = typeof res.data === 'string' ? res.data.trim() : '';
  } catch (error) {
    return upstreamError(error, 'Reverse IP lookup');
  }

  // HackerTarget reports problems as plain text with a 200
  if (/api count exceeded|quota/i.test(body))
    return { error: 'Reverse IP lookup rate-limited by upstream' };
  if (/^error|invalid/i.test(body))
    return { error: `Reverse IP lookup failed: ${body.slice(0, 120)}` };
  if (!body || /no dns a records found/i.test(body)) return { ip, count: 0, domains: [] };

  const domains = [
    ...new Set(
      body
        .split('\n')
        .map((l) => l.trim().toLowerCase())
        .filter(Boolean),
    ),
  ];
  return {
    ip,
    count: domains.length,
    truncated: domains.length > MAX_RESULTS,
    domains: domains.slice(0, MAX_RESULTS),
  };
};

export const handler = middleware(reverseIpHandler);
export default handler;
