import { Card, Note } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';

const TyposquatCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const { checked, count, registered = [] } = props.data;
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row lbl="Variations checked" val={checked} />
      <Row lbl="Registered lookalikes" val={count} status={count ? 'warning' : 'pass'} />
      {registered.map((r: any) => (
        <Row
          key={r.domain}
          lbl={r.domain}
          val={r.hasMx ? 'Resolves · MX' : 'Resolves'}
          title={r.ips.join(', ')}
          status={r.hasMx ? 'warning' : 'info'}
        />
      ))}
      <Note>Many lookalikes are defensive registrations owned by the brand itself.</Note>
    </Card>
  );
};

export default TyposquatCard;
