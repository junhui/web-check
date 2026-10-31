import { Card } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';

const SriCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const { total, missingCount, missing = [] } = props.data;
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row lbl="Third-party resources" val={total} />
      <Row
        lbl="Missing integrity"
        val={missingCount || 'None'}
        status={missingCount ? 'warning' : 'pass'}
      />
      {missing.map((r: any) => (
        <Row key={r.url} lbl={r.type} val={r.url} title={r.url} />
      ))}
    </Card>
  );
};

export default SriCard;
