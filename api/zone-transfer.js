import dns from 'dns/promises';
import net from 'net';
import middleware from './_common/middleware.js';
import { parseTarget, baseDomain } from './_common/parse-target.js';

const AXFR_TIMEOUT = 8000;
const MAX_BYTES = 2 * 1024 * 1024;
const MAX_NAMES = 20;
const TYPE_AXFR = 252;
const TYPE_SOA = 6;

// Encode a DNS name as length-prefixed labels
const encodeName = (name) =>
  Buffer.concat([
    ...name
      .split('.')
      .filter(Boolean)
      .map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])),
    Buffer.from([0]),
  ]);

// A single AXFR query, framed with the 2-byte TCP length prefix
const buildQuery = (zone) => {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(Math.floor(Math.random() * 0xffff), 0);
  header.writeUInt16BE(1, 4); // QDCOUNT
  const q = Buffer.concat([header, encodeName(zone), Buffer.from([0, TYPE_AXFR, 0, 1])]);
  const len = Buffer.alloc(2);
  len.writeUInt16BE(q.length);
  return Buffer.concat([len, q]);
};

// Read a (possibly compressed) name, returning it and the offset after it
const readName = (buf, offset) => {
  const labels = [];
  let pos = offset;
  let end = null;
  for (let hops = 0; hops < 64; hops++) {
    const len = buf[pos];
    if (len === undefined) throw new Error('Truncated name');
    if ((len & 0xc0) === 0xc0) {
      if (end === null) end = pos + 2;
      pos = buf.readUInt16BE(pos) & 0x3fff;
    } else if (len === 0) {
      return { name: labels.join('.'), next: end ?? pos + 1 };
    } else {
      labels.push(buf.toString('ascii', pos + 1, pos + 1 + len));
      pos += len + 1;
    }
  }
  throw new Error('Name pointer loop');
};

// Parse one DNS message, returning rcode and answer records (name + type)
const parseMessage = (msg) => {
  const rcode = msg.readUInt16BE(2) & 0x0f;
  const qd = msg.readUInt16BE(4);
  const an = msg.readUInt16BE(6);
  let pos = 12;
  for (let i = 0; i < qd; i++) pos = readName(msg, pos).next + 4;
  const records = [];
  for (let i = 0; i < an; i++) {
    const { name, next } = readName(msg, pos);
    const type = msg.readUInt16BE(next);
    const rdlen = msg.readUInt16BE(next + 8);
    records.push({ name, type });
    pos = next + 10 + rdlen;
  }
  return { rcode, records };
};

// Attempt AXFR against one server; resolves once the closing SOA arrives or the server refuses
const tryAxfr = (ip, zone) =>
  new Promise((resolve) => {
    let buf = Buffer.alloc(0);
    let soaCount = 0;
    const records = [];
    const finish = (result) => {
      socket.destroy();
      resolve(result);
    };
    const socket = net.connect({ host: ip, port: 53 });
    socket.setTimeout(AXFR_TIMEOUT, () =>
      finish(
        records.length
          ? { allowed: true, partial: true, records }
          : { allowed: false, reason: 'Timed out' },
      ),
    );
    socket.on('error', (e) => finish({ allowed: false, reason: e.code || e.message }));
    socket.on('close', () =>
      finish(
        records.length
          ? { allowed: true, records }
          : { allowed: false, reason: 'Connection closed' },
      ),
    );
    socket.on('connect', () => socket.write(buildQuery(zone)));
    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length > MAX_BYTES) return finish({ allowed: true, partial: true, records });
      try {
        while (buf.length >= 2 && buf.length >= 2 + buf.readUInt16BE(0)) {
          const len = buf.readUInt16BE(0);
          const { rcode, records: rr } = parseMessage(buf.subarray(2, 2 + len));
          buf = buf.subarray(2 + len);
          if (rcode !== 0) return finish({ allowed: false, reason: `Refused (rcode ${rcode})` });
          if (!rr.length && !records.length)
            return finish({ allowed: false, reason: 'Empty response' });
          for (const r of rr) {
            records.push(r);
            if (r.type === TYPE_SOA) soaCount++;
          }
          if (soaCount >= 2) return finish({ allowed: true, records });
        }
      } catch (e) {
        finish({ allowed: records.length > 0, records, reason: `Parse error: ${e.message}` });
      }
    });
  });

const checkNameserver = async (nameserver, zone) => {
  const ip = (await dns.resolve4(nameserver).catch(() => []))[0];
  if (!ip)
    return { nameserver, allowed: false, recordCount: 0, reason: 'Could not resolve nameserver' };
  const { allowed, records = [], reason, partial } = await tryAxfr(ip, zone);
  return {
    nameserver,
    ip,
    allowed,
    recordCount: records.length,
    ...(partial && { partial }),
    ...(allowed && { sampleNames: [...new Set(records.map((r) => r.name))].slice(0, MAX_NAMES) }),
    ...(!allowed && reason && { reason }),
  };
};

const zoneTransferHandler = async (url) => {
  const { hostname } = parseTarget(url);
  if (net.isIP(hostname)) return { skipped: 'Zone transfer checks only apply to domain names' };
  const zone = baseDomain(hostname);
  const nameservers = await dns.resolveNs(zone).catch(() => []);
  if (!nameservers.length) return { skipped: `No NS records found for ${zone}` };
  const results = await Promise.all(nameservers.slice(0, 8).map((ns) => checkNameserver(ns, zone)));
  return { zone, vulnerable: results.some((r) => r.allowed), nameservers: results };
};

export const handler = middleware(zoneTransferHandler);
export default handler;
