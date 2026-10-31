import middleware from './_common/middleware.js';
import { httpGet } from './_common/http.js';
import { parseTarget } from './_common/parse-target.js';

const MAX_MX = 5;

// Query Google's public DNS JSON API, as in dnssec.js
const queryDns = async (name, type) => {
  const res = await httpGet('https://dns.google/resolve', {
    params: { name, type, do: 'true' },
    headers: { Accept: 'application/dns-json' },
    timeout: 6000,
  });
  return res.data || {};
};

// TLSA type is 52; DoH answers carry it as "usage selector matching data"
const lookupTlsa = async (name) => {
  const data = await queryDns(name, 'TLSA');
  const records = (data.Answer || []).filter((a) => a.type === 52).map((a) => a.data);
  return { name, present: records.length > 0, dnssecValidated: !!data.AD, records };
};

const daneHandler = async (url) => {
  const { hostname } = parseTarget(url);
  const mx = await queryDns(hostname, 'MX');
  const mxHosts = (mx.Answer || [])
    .filter((a) => a.type === 15)
    .map((a) => a.data.split(' ').pop().replace(/\.$/, ''))
    .filter(Boolean)
    .slice(0, MAX_MX);

  const [https, ...smtp] = await Promise.all([
    lookupTlsa(`_443._tcp.${hostname}`),
    ...mxHosts.map((h) =>
      lookupTlsa(`_25._tcp.${h}`).catch(() => ({
        name: `_25._tcp.${h}`,
        present: false,
        error: true,
      })),
    ),
  ]);
  return {
    https,
    smtp,
    hasDane: https.present || smtp.some((s) => s.present),
  };
};

export const handler = middleware(daneHandler);
export default handler;
