import net from 'net';
import dns from 'dns/promises';
import middleware from './_common/middleware.js';
import { httpGet } from './_common/http.js';
import { parseTarget } from './_common/parse-target.js';
import { requireEnv, upstreamError } from './_common/upstream.js';

// Server-side Censys host lookup so the API credentials never touch the client
const censysHandler = async (url) => {
  const id = requireEnv('CENSYS_API_ID', 'Censys');
  if (id.skipped) return id;
  const secret = requireEnv('CENSYS_API_SECRET', 'Censys');
  if (secret.skipped) return secret;
  const { hostname } = parseTarget(url);
  let ip = hostname;
  try {
    if (!net.isIP(ip)) ip = (await dns.lookup(hostname)).address;
    const res = await httpGet(`https://search.censys.io/api/v2/hosts/${encodeURIComponent(ip)}`, {
      auth: { username: id.value, password: secret.value },
      headers: { Accept: 'application/json' },
      timeout: 15000,
    });
    const r = res.data?.result || {};
    const as = r.autonomous_system;
    return {
      ip,
      services: (r.services || []).map((s) => ({
        port: s.port,
        transport: s.transport_protocol || null,
        serviceName: s.service_name || null,
        software: (s.software || []).map((sw) =>
          [sw.vendor, sw.product, sw.version].filter(Boolean).join(' '),
        ),
      })),
      autonomousSystem: as
        ? { asn: as.asn, name: as.name || null, bgpPrefix: as.bgp_prefix || null }
        : null,
      country: r.location?.country || null,
    };
  } catch (error) {
    return upstreamError(error, 'Censys');
  }
};

export const handler = middleware(censysHandler);
export default handler;
