import middleware from './_common/middleware.js';
import { httpGet } from './_common/http.js';
import { upstreamError } from './_common/upstream.js';

const EVIL = 'https://evil.example';

const probe = async (url, origin) => {
  const { status, headers } = await httpGet(url, {
    headers: { origin },
    timeout: 8000,
    validateStatus: () => true,
  });
  return {
    origin,
    status,
    allowOrigin: headers['access-control-allow-origin'] || null,
    allowCredentials: headers['access-control-allow-credentials'] === 'true',
  };
};

// Reflected arbitrary origins with credentials let any site read authenticated responses
const verdict = (evil, nul) => {
  const reflected = evil.allowOrigin === EVIL;
  const nullAllowed = nul.allowOrigin === 'null';
  const wildcard = evil.allowOrigin === '*';
  const creds = evil.allowCredentials || nul.allowCredentials;
  if ((reflected || nullAllowed) && creds) return 'high';
  if (reflected || nullAllowed) return 'medium';
  if (wildcard) return 'low';
  return 'none';
};

const corsHandler = async (url) => {
  try {
    const [evil, nul] = await Promise.all([probe(url, EVIL), probe(url, 'null')]);
    return {
      reflectsOrigin: evil.allowOrigin === EVIL,
      allowsNullOrigin: nul.allowOrigin === 'null',
      wildcard: evil.allowOrigin === '*',
      allowCredentials: evil.allowCredentials || nul.allowCredentials,
      severity: verdict(evil, nul),
      probes: [evil, nul],
    };
  } catch (error) {
    return upstreamError(error, 'CORS check');
  }
};

export const handler = middleware(corsHandler);
export default handler;
