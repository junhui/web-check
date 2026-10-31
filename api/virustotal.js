import net from 'net';
import middleware from './_common/middleware.js';
import { httpGet } from './_common/http.js';
import { parseTarget, baseDomain } from './_common/parse-target.js';
import { requireEnv, upstreamError } from './_common/upstream.js';

const FLAGGED = ['malicious', 'suspicious'];

// Server-side VirusTotal v3 domain report so the API key never touches the client
const virusTotalHandler = async (url) => {
  const auth = requireEnv('VT_API_KEY', 'VirusTotal');
  if (auth.skipped) return auth;
  const { hostname } = parseTarget(url);
  if (net.isIP(hostname)) return { skipped: 'VirusTotal domain report needs a domain, not an IP' };
  const domain = baseDomain(hostname);
  try {
    const res = await httpGet(
      `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`,
      { headers: { 'x-apikey': auth.value }, timeout: 15000 },
    );
    const attrs = res.data?.data?.attributes || {};
    const flaggedBy = Object.entries(attrs.last_analysis_results || {})
      .filter(([, r]) => FLAGGED.includes(r?.category))
      .map(([engine, r]) => ({ engine, category: r.category, result: r.result || null }));
    return {
      domain,
      lastAnalysisStats: attrs.last_analysis_stats || null,
      lastAnalysisDate: attrs.last_analysis_date
        ? new Date(attrs.last_analysis_date * 1000).toISOString()
        : null,
      reputation: attrs.reputation ?? null,
      categories: attrs.categories || {},
      flaggedBy,
    };
  } catch (error) {
    return upstreamError(error, 'VirusTotal');
  }
};

export const handler = middleware(virusTotalHandler);
export default handler;
