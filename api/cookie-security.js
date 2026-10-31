import middleware from './_common/middleware.js';
import { httpGet, isBotCheck, BOT_CHECK_ERROR } from './_common/http.js';
import { upstreamError } from './_common/upstream.js';

// Session-like names, where a missing HttpOnly matters most
const SESSION_NAME = /sess|sid|auth|token|login|jwt/i;

// Parse one Set-Cookie into its name and flags, dropping the value entirely
const parseCookie = (raw, isHttps) => {
  const [pair, ...attrs] = raw.split(';').map((s) => s.trim());
  const name = pair.split('=')[0];
  const flags = Object.fromEntries(
    attrs.map((a) => {
      const [k, v = true] = a.split('=');
      return [k.toLowerCase(), v];
    }),
  );
  const secure = 'secure' in flags;
  const httpOnly = 'httponly' in flags;
  const sameSite = typeof flags.samesite === 'string' ? flags.samesite : null;

  const issues = [];
  if (!secure && isHttps) issues.push('Missing Secure flag');
  if (!httpOnly)
    issues.push(
      SESSION_NAME.test(name) ? 'Session-like cookie missing HttpOnly' : 'Missing HttpOnly',
    );
  if (!sameSite) issues.push('No SameSite (browsers default to Lax)');
  else if (sameSite.toLowerCase() === 'none' && !secure)
    issues.push('SameSite=None without Secure is rejected');
  if (name.startsWith('__Secure-') && !secure) issues.push('__Secure- prefix without Secure');
  if (name.startsWith('__Host-') && (!secure || 'domain' in flags || flags.path !== '/'))
    issues.push('__Host- prefix rules not met');

  return {
    name,
    secure,
    httpOnly,
    sameSite,
    domain: flags.domain || null,
    path: flags.path || null,
    issues,
  };
};

const cookieSecurityHandler = async (url) => {
  try {
    const response = await httpGet(url, { timeout: 10000, validateStatus: () => true });
    if (isBotCheck(response)) return BOT_CHECK_ERROR;
    const raw = response.headers['set-cookie'] || [];
    if (!raw.length) return { skipped: 'No cookies set by this page' };
    const isHttps = new URL(response.url || url).protocol === 'https:';
    const cookies = raw.map((c) => parseCookie(c, isHttps));
    return { cookies, issueCount: cookies.reduce((n, c) => n + c.issues.length, 0) };
  } catch (error) {
    return upstreamError(error, 'Cookie fetch');
  }
};

export const handler = middleware(cookieSecurityHandler);
export default handler;
