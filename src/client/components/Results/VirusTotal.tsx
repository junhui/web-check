import { Card } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';

const VirusTotalCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const { domain, lastAnalysisStats: s = {}, reputation, flaggedBy = [] } = props.data;
  const bad = (s.malicious || 0) + (s.suspicious || 0);
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row
        lbl="Flagged by"
        val={`${bad} engine${bad === 1 ? '' : 's'}`}
        status={s.malicious ? 'error' : s.suspicious ? 'warning' : 'pass'}
        link={`https://www.virustotal.com/gui/domain/${domain}`}
      />
      <Row lbl="Harmless" val={s.harmless ?? 0} />
      <Row lbl="Undetected" val={s.undetected ?? 0} />
      <Row lbl="Reputation" val={reputation ?? 'n/a'} />
      {flaggedBy.map((f: any) => (
        <Row key={f.engine} lbl={f.engine} val={f.result || f.category} status="warning" />
      ))}
    </Card>
  );
};

export default VirusTotalCard;
