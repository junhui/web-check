import { Card } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';
import type { Status } from 'client/components/misc/Icon';

const SEVERITY: Record<string, Status> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'info',
};

const JsLibsCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const { libs = [], vulnerableCount } = props.data;
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row lbl="Libraries detected" val={libs.length || 'None'} />
      <Row
        lbl="With known vulnerabilities"
        val={vulnerableCount || 'None'}
        status={vulnerableCount ? 'error' : 'pass'}
      />
      {libs.map((lib: any) => (
        <div key={`${lib.name}@${lib.version}`}>
          <Row
            lbl={`${lib.name} ${lib.version}`}
            val={lib.vulnerabilities.length ? `${lib.vulnerabilities.length} vulns` : 'OK'}
            status={lib.vulnerabilities.length ? 'error' : 'pass'}
          />
          {lib.vulnerabilities.map((v: any, i: number) => (
            <Row
              key={i}
              lbl={(v.identifiers?.CVE || [])[0] || v.identifiers?.githubID || 'Advisory'}
              val={v.summary || v.severity}
              title={v.summary}
              status={SEVERITY[v.severity] || 'info'}
            />
          ))}
        </div>
      ))}
    </Card>
  );
};

export default JsLibsCard;
