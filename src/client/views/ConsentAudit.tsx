import { useEffect, useRef, useState } from 'react';
import styled from '@emotion/styled';
import colors from 'client/styles/colors';
import { Card, Note } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';
import type { Status } from 'client/components/misc/Icon';

const apiBase = (import.meta.env.PUBLIC_API_ENDPOINT || '/api') as string;

// Mirrors MODES in api/consent-audit.js
const MODES = [
  { id: 'baseline', label: 'Baseline (no interaction)' },
  { id: 'accept-all', label: 'Accept all' },
  { id: 'opt-out', label: 'Do Not Sell opt-out' },
  { id: 'gpc', label: 'GPC signal' },
  { id: 'deny-MARKETING', label: 'Deny marketing' },
  { id: 'deny-ANALYTICS', label: 'Deny analytics' },
  { id: 'deny-PERSONALIZATION', label: 'Deny personalization' },
];
// Modes where the visitor asked not to be tracked or sold to
const OPTED_OUT = (m: string) => m === 'opt-out' || m === 'gpc' || m.startsWith('deny-');

const STATES = ['CA', 'CO', 'CT', 'VA', 'TX', 'OR', 'UT', 'MT', 'FL', 'NY', 'WA', 'NJ', 'DE'];
const MODE_STATUS: Record<string, Status> = {
  ok: 'pass',
  partial: 'warning',
  blocked: 'error',
  error: 'error',
  skipped: 'info',
};

const POLL_DELAY = 5000;
const MAX_POLLS = 110;

const Form = styled.form`
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  margin-bottom: 1.5rem;
  input[type='text'],
  textarea,
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
  input[type='text'] {
    flex: 1 1 18rem;
    min-width: 0;
  }
  textarea {
    flex: 1 1 100%;
    min-height: 5rem;
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

const Toolbar = styled.div`
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  align-items: center;
  margin-bottom: 0.75rem;
  input[type='search'] {
    font-family: var(--font-mono);
    padding: 0.3rem 0.5rem;
    border-radius: 4px;
    border: 1px solid ${colors.primaryTransparent};
    background: ${colors.background};
    color: ${colors.textColor};
  }
`;

const TableWrap = styled.div`
  overflow-x: auto;
  table {
    border-collapse: collapse;
    font-size: 0.8rem;
    width: 100%;
  }
  th,
  td {
    padding: 0.25rem 0.4rem;
    border-bottom: 1px solid ${colors.primaryTransparent};
    text-align: center;
    white-space: nowrap;
  }
  th:first-of-type,
  td:first-of-type {
    text-align: left;
    white-space: normal;
    word-break: break-all;
    min-width: 14rem;
  }
  td.hit {
    color: ${colors.success};
    font-weight: bold;
  }
  td.hit.flag {
    color: ${colors.warning};
  }
  td.miss {
    color: ${colors.textColorTertiary};
  }
`;

const Tag = styled.span<{ tone?: string }>`
  display: inline-block;
  margin-left: 0.3rem;
  padding: 0 0.3rem;
  border-radius: 3px;
  font-size: 0.65rem;
  font-weight: bold;
  vertical-align: middle;
  background: ${(p) => p.tone || colors.primary};
  color: ${colors.background};
`;

const Tabs = styled.div`
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
  margin-bottom: 0.75rem;
  button {
    font-family: var(--font-mono);
    font-size: 0.8rem;
    padding: 0.3rem 0.6rem;
    border-radius: 4px;
    cursor: pointer;
    border: 1px solid ${colors.primaryTransparent};
    background: ${colors.background};
    color: ${colors.textColor};
    &[aria-selected='true'] {
      background: ${colors.primaryIncreasedContrast};
      color: ${colors.background};
    }
  }
`;

const List = styled.ul`
  margin: 0.25rem 0 0.75rem;
  padding-left: 1.2rem;
  font-size: 0.8rem;
  word-break: break-all;
`;

const Blocked = styled.p`
  color: ${colors.error};
  font-weight: bold;
`;

const short = (m: string) =>
  m.startsWith('deny-') ? `deny ${m.slice(5).toLowerCase()}` : m.replace('-', ' ');

const consentText = (c: any) =>
  c
    ? Object.entries(c)
        .map(([k, v]) => `${k}=${v}`)
        .join(', ')
    : 'n/a';

const fmtFact = (v: any) => {
  if (Array.isArray(v)) return v.join(', ') || '(none)';
  if (typeof v === 'boolean') return v ? 'yes' : 'no';
  return v ?? 'n/a';
};

const differs = (presentIn: string[], modes: string[]) =>
  presentIn.length > 0 && presentIn.length < modes.length;
const inOptedOut = (presentIn: string[]) => presentIn.some(OPTED_OUT);

const ConsentAudit = (): JSX.Element => {
  const [site, setSite] = useState(
    () => new URLSearchParams(window.location.search).get('url') || 'https://www.newegg.com',
  );
  const [selected, setSelected] = useState(() => MODES.map((m) => m.id));
  const [pages, setPages] = useState('');
  const [usState, setUsState] = useState('');
  const [status, setStatus] = useState('');
  const [progress, setProgress] = useState<Record<string, string> | null>(null);
  const [result, setResult] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const abort = useRef<AbortController | null>(null);

  const [onlyDiff, setOnlyDiff] = useState(false);
  const [onlyAd, setOnlyAd] = useState(false);
  const [search, setSearch] = useState('');
  const [tab, setTab] = useState('');

  useEffect(() => () => abort.current?.abort(), []);

  const toggle = (id: string) =>
    setSelected((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]));

  // Re-request while the API says the audit is still pending
  const run = async (e: { preventDefault: () => void }) => {
    e.preventDefault();
    const target = site.trim();
    if (!/^https?:\/\/[^/\s]+/i.test(target) && !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(target)) {
      return setStatus('Enter a valid site URL');
    }
    if (!selected.length) return setStatus('Pick at least one mode');
    const pageList = pages
      .split('\n')
      .map((p) => p.trim())
      .filter(Boolean);
    if (pageList.length > 6) return setStatus('At most 6 pages');
    abort.current?.abort();
    const controller = new AbortController();
    abort.current = controller;
    setBusy(true);
    setResult(null);
    setProgress(null);
    const ordered = MODES.map((m) => m.id).filter((id) => selected.includes(id));
    const params = new URLSearchParams({ url: target, modes: ordered.join(',') });
    if (pageList.length) params.set('pages', pageList.join(','));
    if (usState) params.set('state', usState.toLowerCase());
    try {
      for (let i = 0; i < MAX_POLLS; i++) {
        setStatus(i ? `Auditing... (${i * (POLL_DELAY / 1000) + 10}s)` : 'Auditing...');
        const res = await fetch(`${apiBase}/consent-audit?${params}`, {
          signal: controller.signal,
        });
        const body = await res.json();
        if (!body.pending) {
          setResult(body);
          setTab(Object.keys(body.modes || {})[0] || '');
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

  const modeIds: string[] = Object.keys(result?.modes || {});
  const q = search.trim().toLowerCase();
  const keep = (text: string, presentIn: string[], ad: boolean) =>
    (!q || text.toLowerCase().includes(q)) &&
    (!onlyDiff || differs(presentIn, modeIds)) &&
    (!onlyAd || ad);

  // A ✓ in an opted-out mode is highlighted when the item is ad-tagged or absent from some mode
  const cells = (presentIn: string[], flag: boolean, counts?: Record<string, number>) =>
    modeIds.map((m) => {
      const hit = presentIn.includes(m);
      const warn = hit && flag && OPTED_OUT(m);
      return (
        <td key={m} className={hit ? `hit${warn ? ' flag' : ''}` : 'miss'}>
          {hit ? (counts ? counts[m] : '✓') : '–'}
        </td>
      );
    });

  const header = (first: string) => (
    <thead>
      <tr>
        <th>{first}</th>
        {modeIds.map((m) => (
          <th key={m}>{short(m)}</th>
        ))}
      </tr>
    </thead>
  );

  const renderCookies = () => {
    const rows = (result.matrix?.cookies || []).filter((c: any) =>
      keep(c.key, c.presentIn, c.adTag === 'ad'),
    );
    return (
      <Card heading={`Cookies (${rows.length})`}>
        <TableWrap>
          <table>
            {header('Cookie name @ domain')}
            <tbody>
              {rows.map((c: any) => (
                <tr key={c.key}>
                  <td>
                    {c.key}
                    {!c.firstParty && <Tag>3rd-party</Tag>}
                    {c.adTag && <Tag tone={colors.warning}>{c.adTag}</Tag>}
                    {c.category && <Tag tone={colors.info}>{c.category.toLowerCase()}</Tag>}
                    {inOptedOut(c.presentIn) && differs(c.presentIn, modeIds) && (
                      <Tag tone={colors.textColorSecondary}>in opted-out mode</Tag>
                    )}
                  </td>
                  {cells(c.presentIn, !!c.adTag || c.category === 'MARKETING')}
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      </Card>
    );
  };

  const renderHosts = () => {
    const rows = (result.matrix?.hosts || []).filter((h: any) =>
      keep(h.host, h.presentIn, h.adTag === 'ad'),
    );
    return (
      <Card heading={`Third-party hosts (${rows.length})`}>
        <TableWrap>
          <table>
            {header('Host (request count per mode)')}
            <tbody>
              {rows.map((h: any) => (
                <tr key={h.host}>
                  <td>
                    {h.host}
                    {h.adTag && <Tag tone={colors.warning}>{h.adTag}</Tag>}
                    {h.osanoCategory === 'UNCLASSIFIED' ? (
                      <Tag tone={colors.textColorTertiary}>unclassified</Tag>
                    ) : (
                      h.osanoCategory && (
                        <Tag tone={colors.info}>{h.osanoCategory.toLowerCase()}</Tag>
                      )
                    )}
                    {inOptedOut(h.presentIn) && h.adTag === 'ad' && (
                      <Tag tone={colors.error}>in opted-out mode</Tag>
                    )}
                  </td>
                  {cells(h.presentIn, h.adTag === 'ad', h.requestsByMode)}
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      </Card>
    );
  };

  const renderScripts = () => {
    const rows = (result.matrix?.scripts || []).filter((s: any) => keep(s.key, s.presentIn, false));
    return (
      <Card heading="External scripts">
        <details>
          <summary>
            {rows.length} script{rows.length === 1 ? '' : 's'} (host + path)
          </summary>
          <TableWrap>
            <table>
              {header('Script')}
              <tbody>
                {rows.map((s: any) => (
                  <tr key={s.key}>
                    <td>
                      {s.key}
                      {s.thirdParty && <Tag>3rd-party</Tag>}
                    </td>
                    {cells(s.presentIn, false)}
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        </details>
      </Card>
    );
  };

  const renderConfig = () => {
    const cfg = result.osanoConfig || {};
    const skip = ['available', 'classifiedHosts', 'classificationCounts', 'reason'];
    return (
      <Card heading="Osano configuration">
        {!cfg.available && <p>Not available: {cfg.reason || 'unknown reason'}</p>}
        {cfg.available &&
          Object.entries(cfg)
            .filter(([k]) => !skip.includes(k))
            .map(([k, v]) => <Row key={k} lbl={k} val={String(fmtFact(v))} />)}
        {cfg.classificationCounts && (
          <Row
            lbl="Classification rules"
            val={Object.entries(cfg.classificationCounts)
              .map(([k, v]) => `${k} ${v}`)
              .join(', ')}
          />
        )}
        <Note>
          Settings are read from the published osano.js. The bundled default jurisdiction is
          replaced at runtime by Osano; see each mode for the jurisdiction it reported.
        </Note>
      </Card>
    );
  };

  const renderMode = (id: string) => {
    const m = result.modes[id];
    if (!m) return null;
    return (
      <div>
        <Row lbl="Status" val={m.status} status={MODE_STATUS[m.status]} />
        {m.error && <Row lbl="Error" val={m.error} />}
        {m.interaction && (
          <>
            <Row
              lbl="Consent interaction"
              val={m.interaction.ok ? 'succeeded' : 'failed'}
              status={m.interaction.ok ? 'pass' : 'error'}
            />
            {(m.interaction.steps || []).length > 0 && (
              <List>
                {m.interaction.steps.map((s: string) => (
                  <li key={s}>{s}</li>
                ))}
              </List>
            )}
          </>
        )}
        <Row lbl="Jurisdiction" val={m.osano?.jurisdiction || 'n/a'} />
        <Row lbl="Consent" val={consentText(m.osano?.consent)} />
        {(m.pages || []).map((p: any, i: number) => (
          <details key={`${p.path}-${i}`} open={i === 0}>
            <summary>
              {p.path}
              {p.phase === 'after-consent' ? ' (right after saving consent, no reload)' : ''}
              {p.blocked ? ' [BLOCKED]' : ''} - {p.cookies.length} cookies, {p.requests.length}{' '}
              third-party hosts
            </summary>
            {p.blocked && (
              <Blocked>
                A bot check page was shown, so this page was not captured. Run from a network the
                site does not challenge.
              </Blocked>
            )}
            {p.error && <Row lbl="Load error" val={p.error} />}
            <Row lbl="Title" val={p.title || '(none)'} />
            <Row
              lbl="Osano"
              val={
                p.osano?.loaded
                  ? `${p.osano.jurisdiction} / opted out: ${String(p.osano.optedOut)}`
                  : 'not loaded'
              }
            />
            <h4>Cookies</h4>
            <List>
              {p.cookies.map((c: any) => (
                <li key={`${c.name}@${c.domain}${c.path}`}>
                  {c.name} @ {c.domain}
                  {c.path} - {c.expires === 'session' ? 'session' : c.expires.slice(0, 10)}
                  {c.httpOnly ? ', httpOnly' : ''}
                  {c.secure ? ', secure' : ''}
                  {c.sameSite ? `, ${c.sameSite}` : ''}, {c.size}B
                </li>
              ))}
            </List>
            <h4>Third-party hosts</h4>
            <List>
              {p.requests.map((h: any) => (
                <li key={h.host}>
                  {h.host} - {h.count} (
                  {Object.entries(h.types)
                    .map(([t, n]) => `${t} ${n}`)
                    .join(', ')}
                  )
                </li>
              ))}
            </List>
            <h4>
              Scripts ({p.scripts.length} external, {p.inlineScripts} inline)
            </h4>
            <List>
              {p.scripts.map((s: any) => (
                <li key={s.host + s.path}>
                  {s.host}
                  {s.path}
                </li>
              ))}
            </List>
            <h4>Storage keys</h4>
            <List>
              {[
                ...(p.storage?.localStorage || []).map((k: string) => `local: ${k}`),
                ...(p.storage?.sessionStorage || []).map((k: string) => `session: ${k}`),
              ].map((k) => (
                <li key={k}>{k}</li>
              ))}
            </List>
          </details>
        ))}
      </div>
    );
  };

  return (
    <>
      <Form onSubmit={run}>
        <input
          type="text"
          value={site}
          onChange={(e) => setSite(e.target.value)}
          placeholder="Site URL, e.g. https://www.newegg.com"
          aria-label="Site URL"
        />
        <select
          value={usState}
          onChange={(e) => setUsState(e.target.value)}
          aria-label="Simulated US state"
        >
          <option value="">No state simulation</option>
          {STATES.map((s) => (
            <option key={s} value={s}>
              Simulate {s}
            </option>
          ))}
        </select>
        <button type="submit" disabled={busy}>
          {busy ? 'Running' : 'Run'}
        </button>
        <textarea
          value={pages}
          onChange={(e) => setPages(e.target.value)}
          placeholder="Pages, one path per line (max 6). Blank = home, search, a product page and cart"
          aria-label="Pages"
        />
        <fieldset>
          {MODES.map((m) => (
            <label key={m.id}>
              <input
                type="checkbox"
                checked={selected.includes(m.id)}
                onChange={() => toggle(m.id)}
              />{' '}
              {m.label}
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
        <Card heading="Consent audit">
          <p>{result.error || result.skipped}</p>
        </Card>
      )}
      {result?.modes && (
        <Stack>
          <Card heading={`Consent audit: ${result.site}`}>
            <Row lbl="Pages" val={result.pages.join(', ')} />
            <Row
              lbl="State"
              val={result.state ? `${result.state.toUpperCase()} (simulated)` : 'none'}
            />
            {modeIds.map((m) => (
              <Row
                key={m}
                lbl={short(m)}
                val={`${result.modes[m].status}${result.modes[m].osano?.jurisdiction ? `, jurisdiction ${result.modes[m].osano.jurisdiction}` : ''}`}
                status={MODE_STATUS[result.modes[m].status]}
              />
            ))}
            {result.blockedPages > 0 && (
              <Blocked>
                {result.blockedPages} page load(s) hit a bot check and were not captured.
              </Blocked>
            )}
            <Note>Finished in {Math.round(result.timeTaken / 1000)}s</Note>
          </Card>
          {renderConfig()}
          <Card heading="Filters">
            <Toolbar>
              <input
                type="search"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search"
                aria-label="Search cookies, hosts and scripts"
              />
              <label>
                <input type="checkbox" checked={onlyDiff} onChange={() => setOnlyDiff((v) => !v)} />{' '}
                Only items that differ across modes
              </label>
              <label>
                <input type="checkbox" checked={onlyAd} onChange={() => setOnlyAd((v) => !v)} />{' '}
                Only ad-tagged
              </label>
            </Toolbar>
            <Note>
              Amber marks mean an ad-tagged or marketing item seen in a mode where the visitor opted
              out or denied a category. Tags are hints from a fixed domain list and Osano&apos;s own
              classification, not a verdict.
            </Note>
          </Card>
          {renderCookies()}
          {renderHosts()}
          {renderScripts()}
          <Card heading="Per-mode detail">
            <Tabs role="tablist">
              {modeIds.map((m) => (
                <button
                  key={m}
                  type="button"
                  role="tab"
                  aria-selected={tab === m}
                  onClick={() => setTab(m)}
                >
                  {short(m)}
                </button>
              ))}
            </Tabs>
            {tab && renderMode(tab)}
          </Card>
        </Stack>
      )}
    </>
  );
};

export default ConsentAudit;
