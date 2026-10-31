import { Card } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';

const ZoneTransferCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const { zone, vulnerable, nameservers = [] } = props.data;
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row lbl="Zone" val={zone} />
      <Row lbl="AXFR allowed" val={vulnerable} status={vulnerable ? 'error' : 'pass'} />
      {nameservers.map((ns: any) => (
        <Row
          key={ns.nameserver}
          lbl={ns.nameserver}
          val={ns.allowed ? `Open (${ns.recordCount} records)` : 'Refused'}
          status={ns.allowed ? 'error' : 'pass'}
          reason={ns.reason}
        />
      ))}
    </Card>
  );
};

export default ZoneTransferCard;
