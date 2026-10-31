import { Card, Note } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';

const ExposedFilesCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const { exposed = [], checked } = props.data;
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row
        lbl="Exposed files"
        val={exposed.length || 'None found'}
        status={exposed.length ? 'error' : 'pass'}
      />
      {exposed.map((f: any) => (
        <Row key={f.path} lbl={f.path} val={f.evidence} status="error" />
      ))}
      <Note>Probed {checked} sensitive paths, matching on file contents to avoid soft-404s.</Note>
    </Card>
  );
};

export default ExposedFilesCard;
