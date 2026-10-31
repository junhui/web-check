import net from 'net';
import middleware from './_common/middleware.js';
import { APP_UA, httpGet } from './_common/http.js';
import { parseTarget, baseDomain } from './_common/parse-target.js';
import { upstreamError } from './_common/upstream.js';

const TIMEOUT = 10000;
const BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
// How long the IANA bootstrap file stays cached in memory
const BOOTSTRAP_TTL = 24 * 60 * 60 * 1000;

let bootstrap = { map: null, fetchedAt: 0 };

// Fetch IANA's TLD -> RDAP server map, cached in memory
const getBootstrap = async () => {
  if (bootstrap.map && Date.now() - bootstrap.fetchedAt < BOOTSTRAP_TTL) return bootstrap.map;
  const res = await httpGet(BOOTSTRAP_URL, { headers: { 'User-Agent': APP_UA }, timeout: TIMEOUT });
  const map = new Map();
  for (const [tlds, urls] of res.data?.services || []) {
    for (const tld of tlds) map.set(tld.toLowerCase(), urls);
  }
  bootstrap = { map, fetchedAt: Date.now() };
  return map;
};

// Find the RDAP base URL for a domain, matching the longest TLD label suffix
const findServer = (map, domain) => {
  const labels = domain.toLowerCase().split('.');
  for (let i = 1; i < labels.length; i++) {
    const urls = map.get(labels.slice(i).join('.'));
    if (urls?.length) return urls.find((u) => u.startsWith('https')) || urls[0];
  }
  return null;
};

// Read a single property out of a jCard (vcardArray) entry
const vcardField = (entity, name) => {
  const props = entity?.vcardArray?.[1];
  if (!Array.isArray(props)) return undefined;
  return props.find((p) => p[0] === name);
};

// Keep only non-personal details of an entity: name/org and country, never email/phone/street
const safeEntity = (entity) => {
  const fn = vcardField(entity, 'fn')?.[3];
  const org = vcardField(entity, 'org')?.[3];
  const adr = vcardField(entity, 'adr');
  const country = adr?.[1]?.cc || (Array.isArray(adr?.[3]) ? adr[3][6] : undefined) || undefined;
  return {
    roles: entity.roles || [],
    organization: (Array.isArray(org) ? org.join(' ') : org) || undefined,
    country: country || undefined,
    // Registrar names are public business data, personal names are not
    ...(entity.roles?.includes('registrar') && fn ? { name: fn } : {}),
  };
};

const flattenEntities = (entities = []) =>
  entities.flatMap((e) => [e, ...flattenEntities(e.entities)]);

const eventDate = (events, action) => events?.find((e) => e.eventAction === action)?.eventDate;

const rdapHandler = async (url) => {
  const { hostname } = parseTarget(url);
  if (net.isIP(hostname)) return { skipped: 'RDAP domain lookup does not apply to IP addresses' };
  const domain = baseDomain(hostname);

  let server;
  try {
    server = findServer(await getBootstrap(), domain);
  } catch (error) {
    return upstreamError(error, 'IANA RDAP bootstrap');
  }
  if (!server) return { skipped: `No RDAP server is registered for the TLD of ${domain}` };

  let data;
  try {
    const base = server.endsWith('/') ? server : `${server}/`;
    const res = await httpGet(`${base}domain/${encodeURIComponent(domain)}`, {
      headers: { Accept: 'application/rdap+json', 'User-Agent': APP_UA },
      timeout: TIMEOUT,
    });
    data = typeof res.data === 'string' ? JSON.parse(res.data) : res.data;
  } catch (error) {
    return upstreamError(error, 'RDAP');
  }

  const entities = flattenEntities(data.entities);
  const registrarEntity = entities.find((e) => e.roles?.includes('registrar'));
  const ianaId = registrarEntity?.publicIds?.find((p) => /iana/i.test(p.type))?.identifier;
  const registrant = entities.find((e) => e.roles?.includes('registrant'));

  return {
    domain: data.ldhName?.toLowerCase() || domain,
    rdapServer: server,
    registrar: registrarEntity
      ? { name: vcardField(registrarEntity, 'fn')?.[3] || null, ianaId: ianaId || null }
      : null,
    registrant: registrant ? safeEntity(registrant) : null,
    status: data.status || [],
    events: {
      registration: eventDate(data.events, 'registration') || null,
      expiration: eventDate(data.events, 'expiration') || null,
      lastChanged: eventDate(data.events, 'last changed') || null,
    },
    nameservers: [
      ...new Set(
        (data.nameservers || [])
          .map((n) => n.ldhName?.toLowerCase().replace(/\.$/, ''))
          .filter(Boolean),
      ),
    ],
    dnssecSigned: Boolean(data.secureDNS?.delegationSigned),
  };
};

export const handler = middleware(rdapHandler);
export default handler;
