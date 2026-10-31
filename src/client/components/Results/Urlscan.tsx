import styled from '@emotion/styled';
import colors from 'client/styles/colors';
import { Card, Note } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';

const Table = styled.table`
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85rem;
  margin-top: 0.5rem;
  th,
  td {
    text-align: left;
    padding: 0.25rem;
    border-bottom: 1px solid ${colors.primaryTransparent};
    overflow-wrap: anywhere;
  }
  th {
    color: ${colors.textColorSecondary};
    font-weight: normal;
  }
  a {
    color: ${colors.primary};
  }
`;

const shortDate = (iso?: string) => (iso ? iso.slice(0, 10) : '?');

const UrlscanCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const { domain, total = 0, scans = [], verdicts } = props.data;
  const v = verdicts?.available ? verdicts : null;
  const anyMalicious = scans.some((s: any) => s.malicious);
  const newest = scans[0];
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row
        lbl="Public scans"
        val={total >= 10000 ? '10,000+' : total.toLocaleString()}
        link={`https://urlscan.io/search/#${encodeURIComponent(`domain:${domain}`)}`}
      />
      {newest && <Row lbl="Last scanned" val={shortDate(newest.time)} link={newest.reportUrl} />}
      {v ? (
        <>
          <Row
            lbl="Newest verdict"
            val={
              v.malicious
                ? 'Malicious'
                : v.score > 0
                  ? `Suspicious (score ${v.score})`
                  : 'No threats'
            }
            status={v.malicious ? 'error' : v.score > 0 ? 'warning' : 'pass'}
          />
          {v.categories.length > 0 && <Row lbl="Categories" val={v.categories.join(', ')} />}
          {v.brands.length > 0 && <Row lbl="Brands targeted" val={v.brands.join(', ')} />}
          <Row
            lbl="Page contacted"
            val={`${v.counts.domains} domains, ${v.counts.ips} IPs, ${v.counts.countries} countries`}
          />
        </>
      ) : (
        anyMalicious && (
          <Row lbl="Verdict" val="Flagged malicious in a recent scan" status="error" />
        )
      )}
      {scans.length > 0 && (
        <Table>
          <thead>
            <tr>
              <th>Date</th>
              <th>IP / Country</th>
              <th>Status</th>
              <th>Report</th>
            </tr>
          </thead>
          <tbody>
            {scans.slice(0, 10).map((s: any) => (
              <tr key={s.uuid}>
                <td>{shortDate(s.time)}</td>
                <td>
                  {s.ip || '-'}
                  {s.country ? ` (${s.country})` : ''}
                </td>
                <td>{s.status ?? '-'}</td>
                <td>
                  <a href={s.reportUrl} target="_blank" rel="noreferrer">
                    View
                  </a>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      <Note>
        Data comes from existing public scans on urlscan.io, submitted by anyone. No new scan was
        submitted.{verdicts && !verdicts.available && verdicts.reason ? ` ${verdicts.reason}.` : ''}
      </Note>
    </Card>
  );
};

export default UrlscanCard;
