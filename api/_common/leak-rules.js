// Secret patterns shared with the js-secrets check
export const PATTERNS = [
  { type: 'AWS access key ID', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { type: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { type: 'Stripe live secret key', re: /\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b/g },
  {
    type: 'GitHub token',
    re: /\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b|\bgithub_pat_[0-9A-Za-z_]{60,}\b/g,
  },
  { type: 'Slack token', re: /\bxox[abposr]-[0-9A-Za-z-]{10,}\b/g },
  {
    type: 'Private key',
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----/g,
  },
  { type: 'JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
];

// Never return the secret itself, just enough to recognise it
export const mask = (s) => `${s.slice(0, 4)}****`;

// Hostname patterns that suggest internal infrastructure, override with LEAK_INTERNAL_HOSTS
const DEFAULT_INTERNAL = ['*.newegg.org', '*.newegg.local', '*.corp.*'];

const escapeRe = (s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&');

// Turn '*.corp.*' style globs into one hostname regex
const internalHostRe = () => {
  const list = (process.env.LEAK_INTERNAL_HOSTS || DEFAULT_INTERNAL.join(','))
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const parts = list.map((g) => escapeRe(g).replace(/\*/g, '[a-z0-9-]+(?:\\.[a-z0-9-]+)*'));
  return new RegExp(`\\b(?:${parts.join('|')})\\b`, 'gi');
};

export const SENSITIVE_EXT = /\.(?:sql|bak|env|log|config|pem|key|zip|tar\.gz|dump|xlsx?|csv)$/i;
// Param names that almost always carry a credential
export const STRONG_PARAMS = [
  'token',
  'api_key',
  'apikey',
  'secret',
  'password',
  'passwd',
  'access_token',
  'auth',
  'session',
  'sessionid',
  'private_key',
  'client_secret',
];
// Generic names (product keys, OAuth codes...), only flagged when the value looks secret
export const WEAK_PARAMS = ['key', 'sig', 'signature', 'code'];
export const SENSITIVE_PARAMS = [...STRONG_PARAMS, ...WEAK_PARAMS];

// Long, mixed letters and digits, or a long hex/base64 blob
export const looksSecret = (value) => {
  const v = String(value || '');
  if (v.length >= 20 && /[a-z]/i.test(v) && /\d/.test(v)) return true;
  return /^[a-f0-9]{32,}$/i.test(v) || /^[A-Za-z0-9+/_-]{32,}={0,2}$/.test(v);
};

const SECRET_IDS = {
  'AWS access key ID': ['aws-key', 'critical'],
  'Google API key': ['gcp-key', 'high'],
  'Stripe live secret key': ['stripe-live', 'critical'],
  'GitHub token': ['github-token', 'critical'],
  'Slack token': ['slack-token', 'high'],
  'Private key': ['private-key', 'critical'],
  JWT: ['jwt', 'medium'],
};

// Rules: { id, label, severity, regex, keep } - keep=true means the match isn't a secret
export const RULES = [
  ...PATTERNS.map(({ type, re }) => ({
    id: SECRET_IDS[type][0],
    label: type,
    severity: SECRET_IDS[type][1],
    regex: re,
  })),
  {
    id: 'azure-key',
    label: 'Azure storage key / connection string',
    severity: 'critical',
    regex: /AccountKey=[A-Za-z0-9+/=]{40,}|\bSharedAccessSignature=[^\s"';]{20,}/g,
  },
  {
    id: 'password',
    label: 'Password assignment',
    severity: 'high',
    regex: /\b(?:password|passwd|pwd)["']?\s*[:=]\s*["']?[^\s"',;<>]{4,}/gi,
  },
  {
    id: 'db-connection',
    label: 'DB connection string with credentials',
    severity: 'critical',
    regex:
      /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mssql|redis|amqp):\/\/[^\s:/@"']+:[^\s@"']+@[^\s"'<>]+|\bjdbc:[a-z0-9]+:[^\s"'<>]*(?:password|user)=[^\s"'<>;&]+/gi,
  },
  {
    id: 'smtp-creds',
    label: 'SMTP credentials',
    severity: 'high',
    regex:
      /\bsmtps?:\/\/[^\s:/@"']+:[^\s@"']+@[^\s"'<>]+|\b(?:smtp|mail)_?pass(?:word)?["']?\s*[:=]\s*["']?[^\s"',;<>]{4,}/gi,
  },
  {
    id: 'internal-host',
    label: 'Internal hostname',
    severity: 'medium',
    regex: null,
    keep: true,
  },
  {
    id: 'private-ip',
    label: 'Private IP address',
    severity: 'low',
    regex:
      /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g,
    keep: true,
  },
  {
    id: 'sensitive-file',
    label: 'Sensitive file type',
    severity: 'medium',
    regex:
      /\bhttps?:\/\/[^\s"'<>?#]+\.(?:sql|bak|env|log|config|pem|key|zip|tar\.gz|dump|xlsx?|csv)(?=[?#\s"'<>]|$)/gi,
    keep: true,
  },
  {
    id: 'sensitive-param',
    label: 'Sensitive URL parameter',
    severity: 'high',
    regex: new RegExp(`[?&](?:${STRONG_PARAMS.join('|')})=[^&\\s"'<>#]{4,}`, 'gi'),
  },
  {
    id: 'sensitive-param',
    label: 'Sensitive URL parameter',
    severity: 'medium',
    regex: new RegExp(`[?&](?:${WEAK_PARAMS.join('|')})=([^&\\s"'<>#]{20,})`, 'gi'),
    test: (m) => looksSecret(m[1]),
  },
];

const RANK = { critical: 4, high: 3, medium: 2, low: 1 };
export const worst = (list) =>
  list.reduce((a, b) => ((RANK[b] || 0) > (RANK[a] || 0) ? b : a), list[0] || null);
export const severityRank = (s) => RANK[s] || 0;

const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const PHONE_RE =
  /(?<![\w.])(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{3}\)\s?|\d{3}[\s.-])\d{3}[\s.-]\d{4}(?![\w.])/g;
const ADDRESS_RE =
  /\b\d{1,5}\s+(?:[A-Z][a-z]+\s){1,3}(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Dr|Drive|Ln|Lane|Way|Ct)\b\.?/g;

// Replace emails, phones and street addresses with labels, counting each type
export const maskPII = (text, counts = { emails: 0, phones: 0, addresses: 0 }) => {
  const out = String(text ?? '')
    .replace(EMAIL_RE, () => (counts.emails++, '[email]'))
    .replace(PHONE_RE, () => (counts.phones++, '[phone]'))
    .replace(ADDRESS_RE, () => (counts.addresses++, '[address]'));
  return { text: out, counts };
};

// Mask the value part of key=value / key: value secrets, else the first 4 chars
const maskSecret = (hit) => {
  const kv = hit.match(/^(.*?[:=]\s*["']?)(.+)$/s);
  if (kv && !/:\/\//.test(hit.slice(0, kv[1].length + 3))) return kv[1] + mask(kv[2]);
  const creds = hit.match(/^([a-z+]+:\/\/)([^@]+)@(.*)$/i);
  if (creds) return `${creds[1]}****@${creds[3]}`;
  return mask(hit);
};

// Mask sensitive query param values in a URL, leaving the rest intact
export const maskUrl = (raw) => {
  try {
    const u = new URL(raw);
    for (const k of [...u.searchParams.keys()]) {
      if (SENSITIVE_PARAMS.includes(k.toLowerCase())) {
        u.searchParams.set(k, mask(u.searchParams.get(k) || ''));
      }
    }
    return maskPII(u.href.replace(/%2A/g, '*')).text;
  } catch {
    return maskPII(raw).text;
  }
};

const SNIPPET = 200;

// Scan text for leak rules; returns { rules, severity, snippet } with secrets and PII masked
export const scan = (text, ctx = {}) => {
  const src = String(text ?? '').slice(0, 20000);
  // Count (never keep) PII across the whole text, for the summary
  if (ctx.piiCounts) maskPII(src, ctx.piiCounts);
  const hits = [];
  const rules = RULES.map((r) =>
    r.id === 'internal-host' ? { ...r, regex: internalHostRe() } : r,
  );
  for (const rule of rules) {
    for (const m of src.matchAll(rule.regex)) {
      if (rule.test && !rule.test(m)) continue;
      hits.push({ rule, index: m.index, text: m[0] });
    }
  }
  if (!hits.length) return { rules: [], severity: null, snippet: '' };
  // Snippet: a window around the first (worst) hit
  hits.sort((a, b) => RANK[b.rule.severity] - RANK[a.rule.severity] || a.index - b.index);
  const first = hits[0];
  const from = Math.max(0, first.index - SNIPPET / 2);
  let snippet = src.slice(from, from + SNIPPET);
  // Mask every secret overlapping the window
  for (const h of hits) {
    if (h.rule.keep) continue;
    if (h.index + h.text.length < from || h.index > from + SNIPPET) continue;
    snippet = snippet.split(h.text).join(maskSecret(h.text));
    // Partial overlaps at the window edges: mask whatever part of the secret is visible
    const head = h.text.slice(0, Math.max(0, from + SNIPPET - h.index));
    const tail = h.text.slice(Math.max(0, from - h.index));
    for (const part of [head, tail]) {
      if (part.length > 4) snippet = snippet.split(part).join(mask(part));
    }
  }
  const { text: clean } = maskPII(snippet);
  const ids = [...new Set(hits.map((h) => h.rule.id))];
  return {
    rules: ids,
    severity: worst(hits.map((h) => h.rule.severity)),
    snippet: clean.replace(/\s+/g, ' ').trim(),
  };
};

export const ruleLabel = (id) => RULES.find((r) => r.id === id)?.label || id;
