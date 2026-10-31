import net from 'net';
import { execFile } from 'child_process';
import middleware from './_common/middleware.js';
import { parseTarget } from './_common/parse-target.js';
import { httpGet } from './_common/http.js';
import { runJob } from './_common/jobs.js';

// Long enough for a -sV service scan (host timeout below plus process overhead)
const LOCAL_TIMEOUT = 190000;
// How long a request waits for the scan before replying { pending: true }
const WAIT_BEFORE_PENDING = 10000;
// How long finished results stay cached for repeat requests
const RESULT_TTL = 10 * 60 * 1000;

// Scan modes, each maps to the nmap port-selection args
const MODES = {
  quick: { description: 'Top 100 most common ports', args: ['-F'] },
  common: {
    description: 'Hand-picked common service ports',
    args: ['-p', '21,22,23,25,53,80,110,143,443,445,465,587,993,995,3306,3389,5432,6379,8080,8443'],
  },
  web: {
    description: 'HTTP/HTTPS and common web app ports',
    args: ['-p', '80,81,443,591,3000,5000,8000,8008,8080,8081,8443,8888,9000,9443'],
  },
  database: {
    description: 'Common database and cache ports',
    args: ['-p', '1433,1521,3306,5432,5984,6379,7000,7001,9042,9200,9300,11211,27017,28017'],
  },
  full: { description: 'Top 1000 most common ports', args: ['--top-ports', '1000'] },
};

const COMMON_PORTS = MODES.common.args;

// Service detection on the common ports, then a CVE lookup per detected product+version
MODES.services = {
  description: 'Common ports with service/version detection and known CVEs',
  args: [...COMMON_PORTS, '-sV', '--version-light'],
  hostTimeout: '180s',
  cves: true,
};

const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
// NVD allows 5 requests per 30s without a key, 50 with one
const NVD_DELAY = () => (process.env.NVD_API_KEY ? 700 : 6500);
const NVD_TIMEOUT = 15000;

const DEFAULT_MODE = 'quick';

// Read the mode query param, from either Vercel/Node or Netlify style requests
const getMode = (request) => {
  const query = request?.query || request?.queryStringParameters || {};
  return (query.mode || DEFAULT_MODE).toLowerCase();
};

// Split nmap's version-info field (e.g. "nginx 1.18.0 (Ubuntu)") into product and version
const parseVersionInfo = (info) => {
  if (!info) return { product: null, version: null };
  // -oG replaces "/" inside fields with "|"
  const clean = info.replace(/\|/g, '/').trim();
  const m = clean.match(/^(.*?)\s+v?(\d[\w.\-:+~]*)(?:\s|$)/);
  if (!m) return { product: clean || null, version: null };
  return { product: m[1].trim() || null, version: m[2] };
};

// Parse nmap greppable (-oG) output into [{port, protocol, state, service, ...version}]
const parsePorts = (stdout) => {
  const line = stdout.split('\n').find((l) => l.includes('Ports:'));
  if (!line) return [];
  const portsField = line.split('Ports:')[1].split('\t')[0];
  return portsField
    .split(',')
    .map((entry) => entry.trim().split('/'))
    .filter((parts) => parts.length >= 5)
    .map(([port, state, protocol, , service, , versionInfo]) => ({
      port: Number(port),
      protocol,
      state,
      service: service || null,
      ...(versionInfo ? { versionInfo, ...parseVersionInfo(versionInfo) } : {}),
    }));
};

// Run the system nmap binary via execFile (no shell, no injection)
// -sT is a TCP connect scan, so no root privileges are needed
const runNmap = (ip, modeArgs, hostTimeout = '110s') =>
  new Promise((resolve, reject) => {
    const args = ['-sT', '-Pn', '-n', '--open', '-T4', '--host-timeout', hostTimeout, ...modeArgs];
    if (net.isIPv6(ip)) args.push('-6');
    args.push('-oG', '-', ip);
    execFile('nmap', args, { timeout: LOCAL_TIMEOUT }, (err, stdout) =>
      err ? reject(err) : resolve(parsePorts(stdout)),
    );
  });

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Pull the highest-priority CVSS score from an NVD CVE record
const cvssOf = (metrics = {}) => {
  for (const key of ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']) {
    const list = metrics[key];
    if (!list?.length) continue;
    const m = list.find((x) => x.type === 'Primary') || list[0];
    return {
      score: m.cvssData?.baseScore ?? null,
      severity: m.cvssData?.baseSeverity || m.baseSeverity || null,
    };
  }
  return { score: null, severity: null };
};

// Query NVD for CVEs matching a product+version keyword
const lookupCves = async (product, version) => {
  const headers = process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {};
  const res = await httpGet(NVD_URL, {
    params: { keywordSearch: `${product} ${version}`, resultsPerPage: 5 },
    headers,
    timeout: NVD_TIMEOUT,
  });
  return (res.data?.vulnerabilities || []).map(({ cve }) => ({
    id: cve.id,
    ...cvssOf(cve.metrics),
  }));
};

// Attach cves (or cveError) to each open port with a known product and version, rate-limited
const attachCves = async (ports) => {
  const cache = new Map();
  let first = true;
  for (const p of ports) {
    if (!p.product || !p.version) continue;
    const key = `${p.product} ${p.version}`.toLowerCase();
    if (!cache.has(key)) {
      if (!first) await sleep(NVD_DELAY());
      first = false;
      try {
        cache.set(key, { cves: await lookupCves(p.product, p.version) });
      } catch (err) {
        const status = err.response?.status;
        cache.set(key, {
          cveError: `NVD lookup failed${status ? ` (HTTP ${status})` : `: ${err.message}`}`,
        });
      }
    }
    Object.assign(p, cache.get(key));
  }
  return ports;
};

const isMissingBinary = (err) =>
  err?.code === 'ENOENT' || /command not found|not installed/i.test(err?.message || '');

// Build the response body for a finished (or failed) scan
const scan = async (ip, mode) => {
  const start = Date.now();
  let ports;
  try {
    ports = await runNmap(ip, MODES[mode].args, MODES[mode].hostTimeout);
  } catch (err) {
    if (isMissingBinary(err)) {
      return {
        skipped:
          'Nmap is not installed in this environment. ' +
          'Install via your package manager, or run web-check via Docker.',
      };
    }
    return { error: `Nmap scan failed: ${err.message}` };
  }
  let openPorts = ports.filter((p) => p.state === 'open');
  if (MODES[mode].cves) openPorts = await attachCves(openPorts);
  return {
    ip,
    mode,
    modeDescription: MODES[mode].description,
    openPorts,
    timeTaken: Date.now() - start,
  };
};

const nmapHandler = async (url, request) => {
  const { hostname: ip } = parseTarget(url);
  if (!net.isIP(ip)) {
    return { error: `Nmap check requires an IP address, but got: ${ip}` };
  }
  const mode = getMode(request);
  if (!MODES[mode]) {
    return { error: `Unknown mode "${mode}". Valid modes: ${Object.keys(MODES).join(', ')}` };
  }
  // Wait briefly for quick scans, otherwise tell the client to poll again
  const result = await runJob(`nmap|${ip}|${mode}`, () => scan(ip, mode), {
    waitMs: WAIT_BEFORE_PENDING,
    ttlMs: RESULT_TTL,
  });
  if (!result.pending) return result;
  return { pending: true, ip, mode, elapsed: result.elapsed };
};

export const handler = middleware(nmapHandler);
export default handler;
