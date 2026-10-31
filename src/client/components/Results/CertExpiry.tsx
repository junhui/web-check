import { Card } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';
import type { Status } from 'client/components/misc/Icon';

const STATUS: Record<string, Status> = {
  ok: 'pass',
  warning: 'warning',
  critical: 'error',
  expired: 'error',
};

const CertExpiryCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const { subject, issuer, validFrom, validTo, daysRemaining, status, recentCertificates } =
    props.data;
  const byIssuer = Object.entries(recentCertificates?.byIssuer || {});
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row lbl="Days remaining" val={daysRemaining} status={STATUS[status]} />
      <Row lbl="Subject" val={subject} />
      <Row lbl="Issuer" val={issuer} />
      <Row lbl="Valid from" val={validFrom} />
      <Row lbl="Valid to" val={validTo} />
      {recentCertificates && (
        <>
          <Row
            lbl={`Issued in last ${recentCertificates.days} days`}
            val={recentCertificates.total}
          />
          {byIssuer.map(([name, count]) => (
            <Row key={name} lbl={name} val={count as number} />
          ))}
        </>
      )}
    </Card>
  );
};

export default CertExpiryCard;
