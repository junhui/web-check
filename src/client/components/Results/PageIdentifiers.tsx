import { Card, Note } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';

const PageIdentifiersCard = (props: {
  data: any;
  title: string;
  actionButtons: any;
}): JSX.Element => {
  const { identifiers = [] } = props.data || {};
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      {!identifiers.length && <Row lbl="Tracking IDs" val="None found" />}
      {identifiers.map((item: any) => (
        <Row key={`${item.type}-${item.id}`} lbl={item.type} val={item.id} />
      ))}
      <Note>Sites sharing the same analytics or ad ID are usually run by the same owner.</Note>
    </Card>
  );
};

export default PageIdentifiersCard;
