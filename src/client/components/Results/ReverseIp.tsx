import { Card } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';

const ReverseIpCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const { ip, count, truncated, domains = [] } = props.data;
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row lbl="IP" val={ip} />
      <Row lbl="Domains on this IP" val={truncated ? `${count}+` : count} />
      <Row lbl="" listResults={domains} />
    </Card>
  );
};

export default ReverseIpCard;
