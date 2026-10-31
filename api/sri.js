import middleware from './_common/middleware.js';
import { httpGet, isBotCheck, BOT_CHECK_ERROR } from './_common/http.js';
import { upstreamError } from './_common/upstream.js';

const attr = (tag, name) =>
  tag
    .match(new RegExp(`\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'))
    ?.slice(1)
    .find((v) => v !== undefined);

// External <script src> and stylesheet <link href> tags, as { type, url, integrity }
const externalResources = (html, base) => {
  const out = [];
  const collect = (tag, type, key) => {
    const ref = attr(tag, key);
    if (!ref) return;
    let abs;
    try {
      abs = new URL(ref, base);
    } catch {
      return;
    }
    if (!/^https?:$/.test(abs.protocol) || abs.origin === base.origin) return;
    out.push({ type, url: abs.href, integrity: attr(tag, 'integrity') || null });
  };
  for (const [tag] of html.matchAll(/<script\b[^>]*>/gi)) collect(tag, 'script', 'src');
  for (const [tag] of html.matchAll(/<link\b[^>]*>/gi)) {
    if (/stylesheet/i.test(attr(tag, 'rel') || '')) collect(tag, 'stylesheet', 'href');
  }
  return out;
};

const sriHandler = async (url) => {
  try {
    const response = await httpGet(url, { timeout: 10000 });
    if (isBotCheck(response)) return BOT_CHECK_ERROR;
    const resources = externalResources(String(response.data), new URL(response.url || url));
    const missing = resources.filter((r) => !r.integrity);
    return {
      total: resources.length,
      missingCount: missing.length,
      missing,
      protected: resources.filter((r) => r.integrity),
    };
  } catch (error) {
    return upstreamError(error, 'SRI fetch');
  }
};

export const handler = middleware(sriHandler);
export default handler;
