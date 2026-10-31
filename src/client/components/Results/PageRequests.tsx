import { Card, Note } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';
import { formatNumber } from 'client/utils/format';

const MAX_DOMAINS = 15;

// Human-sized byte count
const bytes = (n = 0) =>
  n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.round(n / 1024)} KB`;

// Counts as "key: n" pairs, biggest first
const counts = (obj: Record<string, number> = {}) =>
  Object.entries(obj)
    .sort((a, b) => b[1] - a[1])
    .map(([k, n]) => `${k}: ${n}`);

const PageRequestsCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const { totals, domains = [], ips = [], protocols, types } = props.data || {};
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      {totals && (
        <>
          <Row lbl="Requests" val={formatNumber(totals.requests)} />
          <Row lbl="Transferred" val={bytes(totals.bytes)} />
          <Row
            lbl="HTTPS"
            val={`${totals.httpsPct}%`}
            status={totals.httpsPct < 100 ? 'warning' : 'pass'}
          />
          <Row lbl="Third-party" val={`${totals.thirdPartyPct}%`} />
          <Row lbl="IPv6" val={`${totals.ipv6Pct}%`} />
        </>
      )}
      <Row lbl="Domains" val={domains.length} />
      <Row lbl="Unique IPs" val={ips.length} />
      {domains.slice(0, MAX_DOMAINS).map((d: any) => (
        <Row
          key={d.domain}
          lbl={`${d.domain}${d.thirdParty ? ' (3rd party)' : ''}`}
          val={`${d.requests} req, ${bytes(d.bytes)}`}
        />
      ))}
      {protocols && <Row lbl="Protocols" listResults={counts(protocols)} />}
      {types && <Row lbl="Resource types" listResults={counts(types)} />}
      {domains.length > MAX_DOMAINS && (
        <Note>Showing top {MAX_DOMAINS} domains by request count</Note>
      )}
    </Card>
  );
};

export default PageRequestsCard;
