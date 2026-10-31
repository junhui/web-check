import net from 'net';
import middleware from './_common/middleware.js';
import { parseTarget, baseDomain } from './_common/parse-target.js';
import * as store from './_common/leak-store.js';

const MAX_NOTE = 200;

const getQuery = (request) => request?.query || request?.queryStringParameters || {};

// Triage a saved finding: ?url=domain&id=<fingerprint>&status=<status>&note=<text>
const leakStatusHandler = async (url, request) => {
  const { hostname } = parseTarget(url);
  if (net.isIP(hostname)) return { error: 'Leak history needs a domain name, not an IP address' };
  const domain = baseDomain(hostname).toLowerCase();
  const { id, status, note } = getQuery(request);
  if (typeof id !== 'string' || !/^[a-f0-9]{64}$/.test(id)) return { error: 'Invalid finding id' };
  if (!store.STATUSES.includes(status)) {
    return { error: `Invalid status. Valid: ${store.STATUSES.join(', ')}` };
  }
  if (note !== undefined && (typeof note !== 'string' || note.length > MAX_NOTE)) {
    return { error: `Note must be text under ${MAX_NOTE} chars` };
  }
  if (!store.isEnabled()) return { enabled: false, message: store.disabledMessage() };
  const finding = store.setStatus(id, status, note?.trim(), domain);
  if (!finding) return { error: 'Finding not found for this domain' };
  return { enabled: true, finding };
};

export const handler = middleware(leakStatusHandler);
export default handler;
