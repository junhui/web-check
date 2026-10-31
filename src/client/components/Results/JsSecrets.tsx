import { Card, Note } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';

const JsSecretsCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const { findings = [], scanned } = props.data;
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row
        lbl="Possible secrets"
        val={findings.length || 'None found'}
        status={findings.length ? 'error' : 'pass'}
      />
      {findings.map((f: any, i: number) => (
        <Row key={i} lbl={f.type} val={f.masked} title={f.file} status="error" />
      ))}
      <Note>Scanned {scanned} files. Values are masked, rotate any real keys found.</Note>
    </Card>
  );
};

export default JsSecretsCard;
