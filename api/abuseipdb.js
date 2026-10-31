import net from 'net';
import dns from 'dns/promises';
import middleware from './_common/middleware.js';
import { httpGet } from './_common/http.js';
import { parseTarget } from './_common/parse-target.js';
import { requireEnv, upstreamError } from './_common/upstream.js';

// Server-side AbuseIPDB v2 check so the API key never touches the client
const abuseIpDbHandler = async (url) => {
  const auth = requireEnv('ABUSEIPDB_API_KEY', 'AbuseIPDB');
  if (auth.skipped) return auth;
  const { hostname } = parseTarget(url);
  let ip = hostname;
  try {
    if (!net.isIP(ip)) ip = (await dns.lookup(hostname)).address;
    const res = await httpGet('https://api.abuseipdb.com/api/v2/check', {
      params: { ipAddress: ip, maxAgeInDays: 90 },
      headers: { Key: auth.value, Accept: 'application/json' },
      timeout: 15000,
    });
    const d = res.data?.data || {};
    return {
      ip,
      abuseConfidenceScore: d.abuseConfidenceScore ?? null,
      totalReports: d.totalReports ?? 0,
      lastReportedAt: d.lastReportedAt || null,
      isp: d.isp || null,
      usageType: d.usageType || null,
      isTor: Boolean(d.isTor),
    };
  } catch (error) {
    return upstreamError(error, 'AbuseIPDB');
  }
};

export const handler = middleware(abuseIpDbHandler);
export default handler;
