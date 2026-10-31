import middleware from './_common/middleware.js';
import { httpGet, isBotCheck, BOT_CHECK_ERROR } from './_common/http.js';
import { upstreamError } from './_common/upstream.js';
import { PATTERNS, mask } from './_common/leak-rules.js';

const MAX_SCRIPTS = 10;
const MAX_BYTES = 2 * 1024 * 1024;

const scan = (content, file) => {
  const out = [];
  for (const { type, re } of PATTERNS) {
    for (const [hit] of content.matchAll(re)) out.push({ type, file, masked: mask(hit) });
  }
  return out;
};

const sameOriginScripts = (html, base) => {
  const origin = new URL(base).origin;
  const srcs = [...html.matchAll(/<script\b[^>]*\ssrc\s*=\s*["']?([^"'\s>]+)/gi)]
    .map((m) => {
      try {
        return new URL(m[1], base);
      } catch {
        return null;
      }
    })
    .filter((u) => u?.origin === origin)
    .map((u) => u.href);
  return [...new Set(srcs)].slice(0, MAX_SCRIPTS);
};

const jsSecretsHandler = async (url) => {
  let html;
  let base;
  try {
    const response = await httpGet(url, { timeout: 10000 });
    if (isBotCheck(response)) return BOT_CHECK_ERROR;
    html = String(response.data).slice(0, MAX_BYTES);
    base = response.url || url;
  } catch (error) {
    return upstreamError(error, 'Page fetch');
  }

  const scripts = sameOriginScripts(html, base);
  const bodies = await Promise.all(
    scripts.map((src) =>
      httpGet(src, { timeout: 6000 })
        .then(({ data }) => String(data).slice(0, MAX_BYTES))
        .catch(() => ''),
    ),
  );

  const seen = new Set();
  const findings = [scan(html, base), ...scripts.map((s, i) => scan(bodies[i], s))]
    .flat()
    .filter((f) => {
      const key = `${f.type}|${f.file}|${f.masked}`;
      return seen.has(key) ? false : seen.add(key);
    });

  return { findings, scanned: scripts.length + 1 };
};

export const handler = middleware(jsSecretsHandler);
export default handler;
