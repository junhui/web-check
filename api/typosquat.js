import dns from 'dns';
import net from 'net';
import middleware from './_common/middleware.js';
import { parseTarget, baseDomain } from './_common/parse-target.js';

const MAX_CANDIDATES = 200;
const CONCURRENCY = 20;
const DNS_TIMEOUT = 2000;

const KEYBOARD = ['1234567890-', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm'];
const HOMOGLYPHS = {
  a: ['4'],
  b: ['d', '6'],
  d: ['b', 'cl'],
  e: ['3'],
  g: ['q', '9'],
  i: ['1', 'l'],
  l: ['1', 'i'],
  m: ['rn', 'nn'],
  o: ['0'],
  q: ['g'],
  s: ['5'],
  u: ['v'],
  w: ['vv'],
  z: ['2'],
};
export const TLDS = [
  'com',
  'net',
  'org',
  'co',
  'io',
  'info',
  'biz',
  'us',
  'app',
  'xyz',
  'online',
  'site',
];
const VALID_LABEL = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;

// Keys physically next to each letter on a QWERTY keyboard
const adjacentKeys = (c) => {
  const out = [];
  KEYBOARD.forEach((row, r) => {
    const i = row.indexOf(c);
    if (i < 0) return;
    for (const [dr, di] of [
      [0, -1],
      [0, 1],
      [-1, 0],
      [-1, 1],
      [1, -1],
      [1, 0],
    ]) {
      const ch = KEYBOARD[r + dr]?.[i + di];
      if (ch && ch !== '-') out.push(ch);
    }
  });
  return out;
};

// dnstwist-style permutations of the label (registrable part without its TLD)
export const permutations = (name) => {
  const out = new Set();
  const n = name.length;
  for (let i = 0; i < n; i++) {
    const pre = name.slice(0, i);
    const post = name.slice(i + 1);
    const c = name[i];
    out.add(pre + post); // omission
    out.add(pre + c + c + post); // repetition
    if (i < n - 1) out.add(pre + name[i + 1] + c + name.slice(i + 2)); // transposition
    adjacentKeys(c).forEach((k) => out.add(pre + k + post)); // replacement
    (HOMOGLYPHS[c] || []).forEach((h) => out.add(pre + h + post)); // homoglyph
    if (i > 0) out.add(`${pre}-${name.slice(i)}`); // hyphenation
    // bitsquat: single bit flips that still land on a valid hostname char
    for (const bit of [1, 2, 4, 8, 16]) {
      const f = String.fromCharCode(c.charCodeAt(0) ^ bit);
      if (/[a-z0-9]/.test(f)) out.add(pre + f + post);
    }
  }
  out.delete(name);
  return [...out].filter((l) => VALID_LABEL.test(l));
};

export const resolveWithTimeout = (resolver, method, host) =>
  new Promise((resolve) => {
    const t = setTimeout(() => resolve([]), DNS_TIMEOUT);
    resolver[method](host, (err, res) => {
      clearTimeout(t);
      resolve(err ? [] : res);
    });
  });

export const mapLimit = async (items, limit, fn) => {
  const out = new Array(items.length);
  let i = 0;
  const worker = async () => {
    while (i < items.length) {
      const idx = i++;
      out[idx] = await fn(items[idx]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
};

const typosquatHandler = async (url) => {
  const { hostname } = parseTarget(url);
  if (net.isIP(hostname)) return { skipped: 'Typosquat checks only apply to domain names' };
  const domain = baseDomain(hostname);
  const dot = domain.indexOf('.');
  if (dot < 1) return { skipped: 'Could not resolve a registrable domain' };
  const label = domain.slice(0, dot);
  const tld = domain.slice(dot + 1);

  // Mix TLD swaps in first so they survive the cap, then label permutations
  const tldSwaps = TLDS.filter((t) => t !== tld).map((t) => `${label}.${t}`);
  const labelSwaps = permutations(label).map((l) => `${l}.${tld}`);
  const candidates = [...new Set([...tldSwaps, ...labelSwaps])].slice(0, MAX_CANDIDATES);

  const resolver = new dns.Resolver({ timeout: DNS_TIMEOUT, tries: 1 });
  const results = await mapLimit(candidates, CONCURRENCY, async (d) => {
    const ips = await resolveWithTimeout(resolver, 'resolve4', d);
    if (!ips.length) return null;
    const mx = await resolveWithTimeout(resolver, 'resolveMx', d);
    return { domain: d, ips, hasMx: mx.length > 0 };
  });
  const registered = results.filter(Boolean);
  return { domain, checked: candidates.length, count: registered.length, registered };
};

export const handler = middleware(typosquatHandler);
export default handler;
