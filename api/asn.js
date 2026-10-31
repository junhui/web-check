import dns from 'dns/promises';
import net from 'net';
import middleware from './_common/middleware.js';
import { httpGet, APP_UA } from './_common/http.js';
import { parseTarget } from './_common/parse-target.js';
import { upstreamError } from './_common/upstream.js';

const RIPE = 'https://stat.ripe.net/data';

const ripe = async (endpoint, params) => {
  const res = await httpGet(`${RIPE}/${endpoint}/data.json`, {
    params: { ...params, sourceapp: 'web-check' },
    headers: { 'user-agent': APP_UA },
    timeout: 15000,
  });
  return res.data?.data || {};
};

const asnHandler = async (url) => {
  const { hostname } = parseTarget(url);
  let ip = hostname;
  if (!net.isIP(hostname)) {
    try {
      ip = (await dns.lookup(hostname)).address;
    } catch (error) {
      return upstreamError(error, 'DNS');
    }
  }

  try {
    const info = await ripe('network-info', { resource: ip });
    const asn = info.asns?.[0];
    const prefix = info.prefix;
    if (!asn) return { ip, skipped: 'No ASN announces this IP' };

    const [overview, rpki] = await Promise.all([
      ripe('as-overview', { resource: `AS${asn}` }).catch(() => ({})),
      prefix ? ripe('rpki-validation', { resource: `AS${asn}`, prefix }).catch(() => ({})) : {},
    ]);
    return {
      ip,
      asn: Number(asn),
      holder: overview.holder || null,
      prefix: prefix || null,
      announced: overview.announced ?? null,
      rpki: {
        status: rpki.status || 'unknown',
        validatingRoas: (rpki.validating_roas || []).map(
          ({ origin, prefix: p, max_length, validity }) => ({
            origin,
            prefix: p,
            maxLength: max_length,
            validity,
          }),
        ),
      },
    };
  } catch (error) {
    return upstreamError(error, 'RIPEstat');
  }
};

export const handler = middleware(asnHandler);
export default handler;
