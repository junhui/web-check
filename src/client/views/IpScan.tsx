import { useEffect, useRef, useState } from 'react';
import styled from '@emotion/styled';
import colors from 'client/styles/colors';
import { Card, Note } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';
import type { Status } from 'client/components/misc/Icon';

const apiBase = (import.meta.env.PUBLIC_API_ENDPOINT || '/api') as string;

// Mirrors the modes in api/nmap.js
const MODES = [
  { id: 'quick', label: 'Quick', info: 'Top 100 ports' },
  { id: 'common', label: 'Common', info: '20 well-known service ports' },
  { id: 'web', label: 'Web', info: 'HTTP/HTTPS and app server ports' },
  { id: 'database', label: 'Database', info: 'SQL, NoSQL and cache ports' },
  { id: 'full', label: 'Full', info: 'Top 1000 ports, slowest' },
  { id: 'services', label: 'Services', info: 'Common ports with version + CVE lookup' },
];

const POLL_DELAY = 5000;
const MAX_POLLS = 60;

const isIp = (v: string) =>
  /^(\d{1,3}\.){3}\d{1,3}$/.test(v) || (v.includes(':') && /^[0-9a-f:]+$/i.test(v));

const SEVERITY: Record<string, Status> = {
  CRITICAL: 'error',
  HIGH: 'error',
  MEDIUM: 'warning',
  LOW: 'info',
};

const Form = styled.form`
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  margin-bottom: 1.5rem;
  input,
  select,
  button {
    font-family: var(--font-mono);
    font-size: 1rem;
    padding: 0.6rem 0.8rem;
    border-radius: 4px;
    border: 1px solid ${colors.primaryTransparent};
    background: ${colors.backgroundRaised};
    color: ${colors.textColor};
  }
  input {
    flex: 1 1 14rem;
    min-width: 0;
  }
  button {
    cursor: pointer;
    background: ${colors.primaryIncreasedContrast};
    color: ${colors.background};
    border: none;
    &:disabled {
      opacity: 0.6;
      cursor: wait;
    }
  }
`;

const IpScan = (): JSX.Element => {
  // Prefill from ?ip=, as linked from the Open Ports card
  const [ip, setIp] = useState(() => new URLSearchParams(window.location.search).get('ip') || '');
  const [mode, setMode] = useState('quick');
  const [status, setStatus] = useState('');
  const [result, setResult] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const abort = useRef<AbortController | null>(null);

  useEffect(() => () => abort.current?.abort(), []);

  // Re-request while the API says the scan is still pending
  const scan = async (e: { preventDefault: () => void }) => {
    e.preventDefault();
    const target = ip.trim();
    if (!isIp(target)) return setStatus('Enter a valid IPv4 or IPv6 address');
    abort.current?.abort();
    const controller = new AbortController();
    abort.current = controller;
    setBusy(true);
    setResult(null);
    try {
      const query = `nmap?url=${encodeURIComponent(target)}&mode=${mode}`;
      for (let i = 0; i < MAX_POLLS; i++) {
        setStatus(i ? `Scanning... (${i * (POLL_DELAY / 1000) + 10}s)` : 'Scanning...');
        const res = await fetch(`${apiBase}/${query}`, { signal: controller.signal });
        const body = await res.json();
        if (!body.pending) {
          setResult(body);
          setStatus('');
          return;
        }
        await new Promise((r) => setTimeout(r, POLL_DELAY));
      }
      setStatus('Timed out waiting for scan results');
    } catch (err: any) {
      if (err.name !== 'AbortError') setStatus(`Request failed: ${err.message}`);
    } finally {
      setBusy(false);
    }
  };

  const ports = result?.openPorts || [];
  return (
    <>
      <Form onSubmit={scan}>
        <input
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          placeholder="IP address, e.g. 203.0.113.10"
          aria-label="IP address"
        />
        <select value={mode} onChange={(e) => setMode(e.target.value)} aria-label="Scan mode">
          {MODES.map((m) => (
            <option key={m.id} value={m.id}>
              {m.label} - {m.info}
            </option>
          ))}
        </select>
        <button type="submit" disabled={busy}>
          {busy ? 'Scanning' : 'Scan'}
        </button>
      </Form>
      {status && <p>{status}</p>}
      {result && (
        <Card heading={`Port scan: ${result.ip || ip}`}>
          {(result.error || result.skipped) && <p>{result.error || result.skipped}</p>}
          {result.openPorts && (
            <>
              <Row lbl="Mode" val={result.modeDescription} />
              <Row lbl="Open ports" val={ports.length || 'None'} />
              {ports.map((p: any) => (
                <div key={`${p.port}/${p.protocol}`}>
                  <Row
                    lbl={`${p.port}/${p.protocol}`}
                    val={[p.service, p.product, p.version].filter(Boolean).join(' ') || 'unknown'}
                    title={p.versionInfo}
                  />
                  {(p.cves || []).map((c: any) => (
                    <Row
                      key={c.id}
                      lbl={c.id}
                      val={c.score ? `${c.severity} ${c.score}` : c.severity}
                      link={`https://nvd.nist.gov/vuln/detail/${c.id}`}
                      status={SEVERITY[c.severity] || 'info'}
                    />
                  ))}
                </div>
              ))}
              <Note>Finished in {Math.round(result.timeTaken / 1000)}s</Note>
            </>
          )}
        </Card>
      )}
    </>
  );
};

export default IpScan;
