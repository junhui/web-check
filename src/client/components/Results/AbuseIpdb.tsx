import { Card } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';

const AbuseIpdbCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const {
    ip,
    abuseConfidenceScore: score,
    totalReports,
    lastReportedAt,
    isp,
    usageType,
    isTor,
  } = props.data;
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row
        lbl="Abuse confidence"
        val={`${score ?? 0}%`}
        status={score >= 50 ? 'error' : score > 0 ? 'warning' : 'pass'}
        link={`https://www.abuseipdb.com/check/${ip}`}
      />
      <Row lbl="Reports (90 days)" val={totalReports} />
      {lastReportedAt && <Row lbl="Last reported" val={lastReportedAt} />}
      <Row lbl="ISP" val={isp} />
      <Row lbl="Usage type" val={usageType} />
      <Row lbl="Tor exit node" val={isTor} />
    </Card>
  );
};

export default AbuseIpdbCard;
