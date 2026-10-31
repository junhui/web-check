import { Card } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';
import type { Status } from 'client/components/misc/Icon';

const SEVERITY: Record<string, Status> = {
  high: 'error',
  medium: 'warning',
  low: 'info',
  none: 'pass',
};

const CorsCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const { reflectsOrigin, allowsNullOrigin, wildcard, allowCredentials, severity } = props.data;
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row lbl="Risk" val={severity} status={SEVERITY[severity]} />
      <Row
        lbl="Reflects any Origin"
        val={reflectsOrigin}
        status={reflectsOrigin ? 'warning' : 'pass'}
      />
      <Row
        lbl="Allows null Origin"
        val={allowsNullOrigin}
        status={allowsNullOrigin ? 'warning' : 'pass'}
      />
      <Row lbl="Wildcard (*)" val={wildcard} />
      <Row lbl="Allows credentials" val={allowCredentials} />
    </Card>
  );
};

export default CorsCard;
