import middleware from './_common/middleware.js';
import { httpGet, isBotCheck, BOT_CHECK_ERROR } from './_common/http.js';
import { upstreamError } from './_common/upstream.js';

// Pull CSP from <meta http-equiv> tags
const metaPolicies = (html) =>
  [...String(html).matchAll(/<meta[^>]+http-equiv=["']?content-security-policy["']?[^>]*>/gi)]
    .map((m) => m[0].match(/content=["']([^"']*)["']/i)?.[1])
    .filter(Boolean);

const parsePolicy = (policy) => {
  const directives = {};
  for (const part of policy.split(';')) {
    const [name, ...values] = part.trim().split(/\s+/);
    if (name && !directives[name.toLowerCase()]) directives[name.toLowerCase()] = values;
  }
  return directives;
};

// Evaluate one policy, loosely following Google's CSP Evaluator checks
const evaluate = (d) => {
  const findings = [];
  const add = (severity, directive, issue) => findings.push({ severity, directive, issue });
  const scriptDir = d['script-src'] ? 'script-src' : d['default-src'] ? 'default-src' : null;
  const script = scriptDir ? d[scriptDir] : null;
  const hasNonceOrHash = script?.some((v) => /^'(nonce|sha\d+)-/.test(v));
  const strictDynamic = script?.includes("'strict-dynamic'");

  if (!script) add('high', 'script-src', 'No script-src or default-src, so any script can load');
  if (script) {
    if (script.includes("'unsafe-inline'") && !hasNonceOrHash)
      add('high', scriptDir, "'unsafe-inline' allows inline script injection");
    if (script.includes("'unsafe-eval'")) add('medium', scriptDir, "'unsafe-eval' allows eval()");
    if (!strictDynamic) {
      if (script.some((v) => v === '*' || /^https?:$/.test(v) || v === 'https:'))
        add('high', scriptDir, 'Wildcard or scheme-only source allows scripts from any host');
      if (script.some((v) => v.startsWith('http:')))
        add('medium', scriptDir, 'http: source allows scripts over plain HTTP');
    }
    if (script.includes('data:')) add('high', scriptDir, 'data: URIs allow arbitrary script');
  }
  const objectSrc = d['object-src'] || d['default-src'];
  if (!objectSrc) add('high', 'object-src', 'Missing object-src, plugins can run script');
  else if (objectSrc.includes('*')) add('medium', 'object-src', 'Wildcard object-src');
  if (!d['base-uri'])
    add('medium', 'base-uri', 'Missing base-uri, <base> injection can hijack relative URLs');
  if (!d['default-src']) add('low', 'default-src', 'No default-src fallback');
  if (!d['frame-ancestors'])
    add('low', 'frame-ancestors', 'No frame-ancestors, page may be framed (clickjacking)');
  for (const [name, values] of Object.entries(d)) {
    if (name !== scriptDir && values.includes('*')) add('low', name, 'Wildcard source');
  }
  return findings;
};

const cspEvalHandler = async (url) => {
  try {
    const response = await httpGet(url, { timeout: 10000, validateStatus: () => true });
    if (isBotCheck(response)) return BOT_CHECK_ERROR;
    const header = response.headers['content-security-policy'];
    const policies = [
      ...(header
        ? header.split(/,(?=\s*[a-z-]+\s)/i).map((p) => ({ source: 'header', policy: p.trim() }))
        : []),
      ...metaPolicies(response.data).map((p) => ({ source: 'meta', policy: p })),
    ];
    if (!policies.length) {
      return {
        policies: [],
        findings: [{ severity: 'high', directive: null, issue: 'No Content-Security-Policy set' }],
      };
    }
    return {
      policies: policies.map((p) => ({ ...p, findings: evaluate(parsePolicy(p.policy)) })),
      findings: policies.flatMap((p) =>
        evaluate(parsePolicy(p.policy)).map((f) => ({ ...f, source: p.source })),
      ),
    };
  } catch (error) {
    return upstreamError(error, 'CSP fetch');
  }
};

export const handler = middleware(cspEvalHandler);
export default handler;
