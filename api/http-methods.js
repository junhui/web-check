import http from 'http';
import https from 'https';
import middleware from './_common/middleware.js';
import { UA } from './_common/http.js';

const TIMEOUT = 8000;
const RISKY = ['TRACE', 'PUT', 'DELETE', 'CONNECT'];

// Raw request, since fetch refuses TRACE and CONNECT
const request = (url, method) =>
  new Promise((resolve, reject) => {
    const lib = url.startsWith('https:') ? https : http;
    const req = lib.request(
      url,
      { method, headers: { 'user-agent': UA }, timeout: TIMEOUT },
      (res) => {
        let body = '';
        res.setEncoding('latin1');
        res.on('data', (c) => {
          if (body.length < 4096) body += c;
        });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
      },
    );
    req.on('timeout', () => req.destroy(new Error('Request timed out')));
    req.on('error', reject);
    req.end();
  });

const parseAllow = (headers) =>
  [headers.allow, headers['access-control-allow-methods']]
    .filter(Boolean)
    .join(',')
    .split(',')
    .map((m) => m.trim().toUpperCase())
    .filter(Boolean);

const httpMethodsHandler = async (url) => {
  const [options, trace] = await Promise.all([
    request(url, 'OPTIONS').catch((e) => ({ error: e.message })),
    request(url, 'TRACE').catch((e) => ({ error: e.message })),
  ]);
  if (options.error && trace.error) return { error: `Method probes failed: ${options.error}` };

  const allowed = [...new Set(options.headers ? parseAllow(options.headers) : [])];
  // TRACE only counts as enabled when the server echoes our request back
  const traceEnabled = trace.status === 200 && /^TRACE /m.test(trace.body || '');
  const risky = RISKY.filter((m) => allowed.includes(m) || (m === 'TRACE' && traceEnabled));

  return {
    allowed,
    optionsStatus: options.status ?? null,
    traceStatus: trace.status ?? null,
    traceEnabled,
    risky,
  };
};

export const handler = middleware(httpMethodsHandler);
export default handler;
