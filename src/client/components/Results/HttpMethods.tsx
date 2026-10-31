import { Card } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';

const HttpMethodsCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const { allowed = [], traceEnabled, risky = [], optionsStatus } = props.data;
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row lbl="Advertised methods" val={allowed.length ? allowed.join(', ') : 'Not advertised'} />
      <Row lbl="OPTIONS status" val={optionsStatus ?? 'n/a'} />
      <Row lbl="TRACE enabled" val={traceEnabled} status={traceEnabled ? 'error' : 'pass'} />
      <Row
        lbl="Risky methods"
        val={risky.length ? risky.join(', ') : 'None'}
        status={risky.length ? 'warning' : 'pass'}
      />
    </Card>
  );
};

export default HttpMethodsCard;
