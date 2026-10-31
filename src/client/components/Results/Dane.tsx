import { Card } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';

const DaneCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const { https, smtp = [], hasDane } = props.data;
  const entries = [https, ...smtp].filter(Boolean);
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row lbl="DANE in use" val={hasDane} status={hasDane ? 'pass' : 'info'} />
      {entries.map((e: any) => (
        <Row
          key={e.name}
          lbl={e.name}
          val={e.present ? `${e.records.length} TLSA` : 'None'}
          status={e.present ? (e.dnssecValidated ? 'pass' : 'warning') : undefined}
          reason={e.present && !e.dnssecValidated ? 'Not DNSSEC validated' : undefined}
        />
      ))}
    </Card>
  );
};

export default DaneCard;
