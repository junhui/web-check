import net from 'net';
import middleware from './_common/middleware.js';
import { parseTarget, baseDomain } from './_common/parse-target.js';
import * as store from './_common/leak-store.js';

const getQuery = (request) => request?.query || request?.queryStringParameters || {};

// Saved leak hunt findings and recent runs for a domain
const leakFindingsHandler = async (url, request) => {
  const { hostname } = parseTarget(url);
  if (net.isIP(hostname)) return { error: 'Leak history needs a domain name, not an IP address' };
  const domain = baseDomain(hostname).toLowerCase();
  const { status } = getQuery(request);
  if (status && !store.STATUSES.includes(status)) {
    return { error: `Invalid status. Valid: ${store.STATUSES.join(', ')}` };
  }
  if (!store.isEnabled()) {
    return { enabled: false, message: store.disabledMessage(), domain, findings: [], runs: [] };
  }
  return {
    enabled: true,
    domain,
    findings: store.listFindings(domain, { status }),
    runs: store.listRuns(domain, 20),
  };
};

export const handler = middleware(leakFindingsHandler);
export default handler;
