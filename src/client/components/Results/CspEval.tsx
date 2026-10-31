import { Card, Note } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';
import type { Status } from 'client/components/misc/Icon';

const SEVERITY: Record<string, Status> = {
  high: 'error',
  medium: 'warning',
  low: 'info',
  info: 'info',
};

const CspEvalCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const { policies = [], findings = [] } = props.data;
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row lbl="Policies found" val={policies.length} status={policies.length ? 'pass' : 'error'} />
      <Row
        lbl="Issues"
        val={findings.length || 'None'}
        status={findings.length ? 'warning' : 'pass'}
      />
      {findings.map((f: any, i: number) => (
        <Row
          key={i}
          lbl={f.directive || 'policy'}
          val={f.issue}
          status={SEVERITY[f.severity] || 'info'}
        />
      ))}
      {policies.length > 0 && <Note>Rules based on Google's CSP Evaluator.</Note>}
    </Card>
  );
};

export default CspEvalCard;
