import crypto from 'crypto';
import middleware from './_common/middleware.js';
import { UA } from './_common/http.js';

const TIMEOUT = 6000;

// Each path needs a content signature, so soft-404 pages and catch-all routes don't match
const PROBES = [
  { path: '/.git/HEAD', evidence: 'Git HEAD ref', test: (b) => /^ref: refs\//.test(b) },
  {
    path: '/.git/config',
    evidence: 'Git config [core] section',
    test: (b) => b.includes('[core]'),
  },
  {
    path: '/.env',
    evidence: 'KEY=VALUE environment lines',
    test: (b) => !/<html|<body/i.test(b) && (b.match(/^[A-Z][A-Z0-9_]{2,}=.*/gm) || []).length >= 2,
  },
  { path: '/.DS_Store', evidence: 'DS_Store Bud1 magic', test: (b) => b.slice(4, 8) === 'Bud1' },
  {
    path: '/.svn/entries',
    evidence: 'SVN entries file',
    test: (b) => /^\d+\s*$/m.test(b.split('\n')[0]) || b.includes('<wc-entries'),
  },
  {
    path: '/.htpasswd',
    evidence: 'user:hash lines',
    test: (b) => /^[\w.-]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|[./0-9A-Za-z]{13}$)/m.test(b),
  },
  {
    path: '/server-status',
    evidence: 'Apache Server Status page',
    test: (b) => b.includes('Apache Server Status'),
  },
  {
    path: '/phpinfo.php',
    evidence: 'phpinfo() output',
    test: (b) => /PHP Version/.test(b) && /phpinfo/i.test(b),
  },
  { path: '/backup.zip', evidence: 'ZIP magic bytes', test: (b) => b.startsWith('PK\u0003\u0004') },
  { path: '/backup.sql', evidence: 'SQL dump statements', test: (b) => isSqlDump(b) },
  { path: '/db.sql', evidence: 'SQL dump statements', test: (b) => isSqlDump(b) },
  {
    path: '/wp-config.php.bak',
    evidence: 'WordPress DB constants',
    test: (b) => b.includes('define(') && b.includes('DB_PASSWORD'),
  },
];

const isSqlDump = (b) =>
  !/<html/i.test(b) && /(CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump)/i.test(b);

// Read bodies as latin1 so binary magic bytes survive
const fetchRaw = async (url) => {
  const res = await fetch(url, {
    redirect: 'manual',
    headers: { 'user-agent': UA, range: 'bytes=0-65535' },
    signal: AbortSignal.timeout(TIMEOUT),
  });
  const buf = Buffer.from(await res.arrayBuffer());
  return { status: res.status, body: buf.subarray(0, 65536).toString('latin1') };
};

const exposedFilesHandler = async (url) => {
  const origin = new URL(url).origin;
  // Fingerprint the site's 404, so a 200 catch-all returning the same page is ignored
  let notFound;
  try {
    notFound = await fetchRaw(`${origin}/${crypto.randomBytes(8).toString('hex')}.txt`);
  } catch (error) {
    return { error: `Could not reach site: ${error.message}` };
  }

  const results = await Promise.all(
    PROBES.map(async (probe) => {
      try {
        const { status, body } = await fetchRaw(origin + probe.path);
        if (status < 200 || status >= 300) return null;
        if (notFound.status === status && Math.abs(notFound.body.length - body.length) < 32)
          return null;
        return probe.test(body) ? { path: probe.path, status, evidence: probe.evidence } : null;
      } catch {
        return null;
      }
    }),
  );

  return { exposed: results.filter(Boolean), checked: PROBES.length };
};

export const handler = middleware(exposedFilesHandler);
export default handler;
