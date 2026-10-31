import net from 'net';
import tls from 'tls';
import middleware from './_common/middleware.js';
import { httpGet } from './_common/http.js';
import { parseTarget, baseDomain } from './_common/parse-target.js';

const DAY = 86400000;
const RECENT_DAYS = 90;

// Grab the leaf certificate presented on host:port
const getCert = (host, port) =>
  new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host, port, rejectUnauthorized: false, ...(net.isIP(host) ? {} : { servername: host }) },
      () => {
        const cert = socket.getPeerCertificate();
        socket.end();
        if (!cert || !cert.valid_to) reject(new Error('No certificate presented by the server'));
        else resolve(cert);
      },
    );
    socket.setTimeout(8000, () => {
      socket.destroy();
      reject(new Error('TLS connection timed out'));
    });
    socket.on('error', (e) => reject(new Error(`TLS connection failed: ${e.reason || e.message}`)));
  });

const statusFor = (days) =>
  days < 0 ? 'expired' : days < 7 ? 'critical' : days < 30 ? 'warning' : 'ok';

// Count certificates logged in CT for the domain over the last 90 days, by issuer
const recentIssuers = async (domain) => {
  const res = await httpGet('https://crt.sh/', {
    params: { q: domain, output: 'json', exclude: 'expired' },
    headers: { Accept: 'application/json' },
    timeout: 10000,
  });
  if (!Array.isArray(res.data)) return null;
  const since = Date.now() - RECENT_DAYS * DAY;
  const counts = {};
  let total = 0;
  for (const row of res.data) {
    if (new Date(`${row.not_before}Z`).getTime() < since) continue;
    const issuer =
      /O=([^,]+)/.exec(row.issuer_name || '')?.[1]?.replace(/"/g, '') ||
      row.issuer_name ||
      'Unknown';
    counts[issuer] = (counts[issuer] || 0) + 1;
    total++;
  }
  return { days: RECENT_DAYS, total, byIssuer: counts };
};

const certExpiryHandler = async (url) => {
  const { hostname, port } = parseTarget(url);
  const [cert, recent] = await Promise.all([
    getCert(hostname, Number(port) || 443),
    net.isIP(hostname) ? null : recentIssuers(baseDomain(hostname)).catch(() => null),
  ]);
  const validTo = new Date(cert.valid_to);
  const daysRemaining = Math.floor((validTo.getTime() - Date.now()) / DAY);
  return {
    subject: cert.subject?.CN || null,
    issuer: cert.issuer?.O || cert.issuer?.CN || null,
    validFrom: new Date(cert.valid_from).toISOString(),
    validTo: validTo.toISOString(),
    daysRemaining,
    status: statusFor(daysRemaining),
    recentCertificates: recent,
  };
};

export const handler = middleware(certExpiryHandler);
export default handler;
