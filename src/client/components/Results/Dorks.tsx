import { Card, Note } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';

const DorksCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const dorks = Array.isArray(props.data) ? props.data : [];
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      {dorks.map((d: any) => (
        <Row key={d.query} lbl={d.title} val="Search" link={d.url} title={d.query} />
      ))}
      <Note>Opens Google in a new tab, nothing is fetched by Web Check.</Note>
    </Card>
  );
};

export default DorksCard;
