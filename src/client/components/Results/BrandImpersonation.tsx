import { Card, Note } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';
import type { Status } from 'client/components/misc/Icon';

const VERDICT_STATUS: Record<string, Status> = {
  'likely impersonation': 'error',
  suspicious: 'warning',
  'redirects-to-brand': 'pass',
  'benign/parked': 'info',
};

const BrandImpersonationCard = (props: {
  data: any;
  title: string;
  actionButtons: any;
}): JSX.Element => {
  const { brand, fingerprint = {}, checked, registered, suspects = [] } = props.data;
  const count = (v: string) => suspects.filter((s: any) => s.verdict === v).length;
  const likely = count('likely impersonation');
  const suspicious = count('suspicious');
  const hash = fingerprint.faviconMmh3;
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row lbl="Brand" val={brand} />
      {fingerprint.title && <Row lbl="Site title" val={fingerprint.title} />}
      {hash !== null && hash !== undefined && (
        <Row
          lbl="Favicon hash (mmh3)"
          val={String(hash)}
          link={`https://www.shodan.io/search?query=http.favicon.hash:${hash}`}
          title={fingerprint.faviconSha256 ? `SHA-256 ${fingerprint.faviconSha256}` : undefined}
        />
      )}
      <Row lbl="Registered lookalikes" val={registered} />
      <Row lbl="Lookalikes checked" val={checked} />
      <Row lbl="Likely impersonation" val={likely} status={likely ? 'error' : 'pass'} />
      <Row lbl="Suspicious" val={suspicious} status={suspicious ? 'warning' : 'pass'} />
      <Row lbl="Redirect to brand" val={count('redirects-to-brand')} />
      {suspects
        .filter((s: any) => s.verdict !== 'unreachable')
        .map((s: any) => (
          <Row
            key={s.domain}
            lbl={s.domain}
            val={`${s.verdict} · ${s.score}`}
            title={[s.title, s.finalUrl, s.signals.join(', ')].filter(Boolean).join(' · ')}
            status={VERDICT_STATUS[s.verdict] || 'info'}
          />
        ))}
      <Note>
        Scores are heuristic. Many lookalikes are parked or defensively owned by the brand.
      </Note>
    </Card>
  );
};

export default BrandImpersonationCard;
