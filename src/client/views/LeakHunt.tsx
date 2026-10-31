import { useEffect, useRef, useState } from 'react';
import styled from '@emotion/styled';
import colors from 'client/styles/colors';
import { Card, Note } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';
import type { Status } from 'client/components/misc/Icon';

const apiBase = (import.meta.env.PUBLIC_API_ENDPOINT || '/api') as string;

// Mirrors the sources in api/leak-hunt.js
const SOURCES = [
  { id: 'wayback', label: 'Wayback Machine' },
  { id: 'commoncrawl', label: 'Common Crawl' },
  { id: 'crtsh', label: 'crt.sh' },
  { id: 'github', label: 'GitHub code' },
  { id: 'google', label: 'Google API' },
  { id: 'brave', label: 'Brave API' },
  { id: 'postman', label: 'Postman pages' },
];

// Mirrors the rule labels in api/_common/leak-rules.js
const RULE_LABELS: Record<string, string> = {
  'aws-key': 'AWS key',
  'gcp-key': 'Google API key',
  'azure-key': 'Azure key',
  'stripe-live': 'Stripe live key',
  'slack-token': 'Slack token',
  'github-token': 'GitHub token',
  'private-key': 'Private key',
  jwt: 'JWT',
  password: 'Password',
  'db-connection': 'DB connection string',
  'smtp-creds': 'SMTP credentials',
  'internal-host': 'Internal hostname',
  'private-ip': 'Private IP',
  'sensitive-file': 'Sensitive file',
  'sensitive-param': 'Sensitive URL param',
  'keyword-mention': 'Keyword mention',
};

const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const SEVERITY_STATUS: Record<string, Status> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'info',
};
const SOURCE_STATUS: Record<string, Status> = { ok: 'pass', skipped: 'info', error: 'error' };

const POLL_DELAY = 5000;
const MAX_POLLS = 40;

const Form = styled.form`
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  margin-bottom: 1.5rem;
  input[type='text'],
  button {
    font-family: var(--font-mono);
    font-size: 1rem;
    padding: 0.6rem 0.8rem;
    border-radius: 4px;
    border: 1px solid ${colors.primaryTransparent};
    background: ${colors.backgroundRaised};
    color: ${colors.textColor};
  }
  input[type='text'] {
    flex: 1 1 14rem;
    min-width: 0;
  }
  fieldset {
    flex: 1 1 100%;
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem 1rem;
    border: none;
    padding: 0;
    margin: 0;
  }
  label {
    cursor: pointer;
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

const Stack = styled.div`
  display: grid;
  gap: 1rem;
`;

const Snippet = styled.code`
  display: block;
  margin: 0.25rem 0 0.75rem;
  padding: 0.4rem 0.6rem;
  font-size: 0.8rem;
  background: ${colors.background};
  border-radius: 4px;
  white-space: pre-wrap;
`;

const Meta = styled.small`
  display: block;
  color: ${colors.textColorTertiary};
`;

const Finding = styled.div`
  padding: 0.5rem 0;
  border-bottom: 1px solid ${colors.primaryTransparent};
  a {
    color: ${colors.primaryIncreasedContrast};
    word-break: break-all;
  }
`;

const ruleLabels = (rules: string[] = []) => rules.map((r) => RULE_LABELS[r] || r).join(', ');

const LeakHunt = (): JSX.Element => {
  // Prefill from ?domain=
  const [domain, setDomain] = useState(
    () => new URLSearchParams(window.location.search).get('domain') || '',
  );
  const [keywords, setKeywords] = useState(() =>
    domain ? `${domain.split('.')[0]}, ${domain}` : '',
  );
  const [selected, setSelected] = useState(() => SOURCES.map((s) => s.id));
  const [status, setStatus] = useState('');
  const [progress, setProgress] = useState<Record<string, string> | null>(null);
  const [result, setResult] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const abort = useRef<AbortController | null>(null);

  useEffect(() => () => abort.current?.abort(), []);

  const toggle = (id: string) =>
    setSelected((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]));

  // Re-request while the API says the hunt is still pending
  const run = async (e: { preventDefault: () => void }) => {
    e.preventDefault();
    const target = domain.trim();
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(target)) return setStatus('Enter a valid domain name');
    if (!selected.length) return setStatus('Pick at least one source');
    abort.current?.abort();
    const controller = new AbortController();
    abort.current = controller;
    setBusy(true);
    setResult(null);
    setProgress(null);
    const params = new URLSearchParams({ url: target, sources: selected.join(',') });
    if (keywords.trim()) params.set('keywords', keywords.trim());
    try {
      for (let i = 0; i < MAX_POLLS; i++) {
        setStatus(i ? `Hunting... (${i * (POLL_DELAY / 1000) + 10}s)` : 'Hunting...');
        const res = await fetch(`${apiBase}/leak-hunt?${params}`, { signal: controller.signal });
        const body = await res.json();
        if (!body.pending) {
          setResult(body);
          setStatus('');
          return;
        }
        setProgress(body.progress || null);
        await new Promise((r) => setTimeout(r, POLL_DELAY));
      }
      setStatus('Timed out waiting for results');
    } catch (err: any) {
      if (err.name !== 'AbortError') setStatus(`Request failed: ${err.message}`);
    } finally {
      setBusy(false);
    }
  };

  const findings: any[] = result?.findings || [];
  const pii = result?.summary?.piiCounts || {};
  return (
    <>
      <Form onSubmit={run}>
        <input
          type="text"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="Domain, e.g. example.com"
          aria-label="Domain"
        />
        <input
          type="text"
          value={keywords}
          onChange={(e) => setKeywords(e.target.value)}
          placeholder="Keywords, comma separated (default: domain name)"
          aria-label="Keywords"
        />
        <button type="submit" disabled={busy}>
          {busy ? 'Running' : 'Run'}
        </button>
        <fieldset>
          {SOURCES.map((s) => (
            <label key={s.id}>
              <input
                type="checkbox"
                checked={selected.includes(s.id)}
                onChange={() => toggle(s.id)}
              />{' '}
              {s.label}
            </label>
          ))}
        </fieldset>
      </Form>
      {status && <p>{status}</p>}
      {busy && progress && (
        <Card heading="Progress">
          {Object.entries(progress).map(([name, state]) => (
            <Row key={name} lbl={name} val={state} />
          ))}
        </Card>
      )}
      {result && (result.error || result.skipped) && (
        <Card heading="Leak hunt">
          <p>{result.error || result.skipped}</p>
        </Card>
      )}
      {result?.findings && (
        <Stack>
          <Card heading={`Leak hunt: ${result.domain}`}>
            <Row lbl="Keywords" val={result.keywords.join(', ')} />
            {SEVERITIES.map((s) => (
              <Row
                key={s}
                lbl={s[0].toUpperCase() + s.slice(1)}
                val={result.summary[s]}
                status={result.summary[s] ? SEVERITY_STATUS[s] : undefined}
              />
            ))}
            <Row lbl="Emails seen (masked)" val={pii.emails || 0} />
            <Row lbl="Phone numbers seen (masked)" val={pii.phones || 0} />
            <h4>Sources</h4>
            {Object.entries(result.sources).map(([name, s]: [string, any]) => (
              <Row
                key={name}
                lbl={name}
                val={`${s.status}${s.status === 'ok' ? ` (${s.count})` : ''}${s.message ? `: ${s.message}` : ''}`}
                status={SOURCE_STATUS[s.status]}
              />
            ))}
            <Note>Finished in {Math.round(result.timeTaken / 1000)}s</Note>
          </Card>
          <Card heading={`Findings (${findings.length})`}>
            {!findings.length && <p>No potential leaks found in the selected sources.</p>}
            {SEVERITIES.map((sev) => {
              const group = findings.filter((f) => f.severity === sev);
              if (!group.length) return null;
              return (
                <div key={sev}>
                  <h4>
                    {sev[0].toUpperCase() + sev.slice(1)} ({group.length})
                  </h4>
                  {group.map((f) => (
                    <Finding key={f.id}>
                      <a href={f.url} target="_blank" rel="noreferrer">
                        {f.title}
                      </a>
                      <Meta>
                        {f.source}
                        {f.owner ? ` / owner: ${f.owner}` : ''}
                        {f.foundAt ? ` / ${f.foundAt}` : ''} / {ruleLabels(f.rules)}
                      </Meta>
                      {f.snippet && <Snippet>{f.snippet}</Snippet>}
                    </Finding>
                  ))}
                </div>
              );
            })}
            <Note>
              Values are masked. Rotate any secret you confirm, and only assess assets you are
              authorised to.
            </Note>
          </Card>
          <Card heading="Manual search links">
            {(result.links || []).map((l: any) => (
              <Row key={l.url} lbl={l.engine} val={l.title} link={l.url} />
            ))}
          </Card>
        </Stack>
      )}
    </>
  );
};

export default LeakHunt;
