import { Card } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';

const SubdomainTakeoverCard = (props: {
  data: any;
  title: string;
  actionButtons: any;
}): JSX.Element => {
  const { checked, vulnerable = [] } = props.data;
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row lbl="Subdomains checked" val={checked} />
      <Row
        lbl="Takeover candidates"
        val={vulnerable.length || 'None'}
        status={vulnerable.length ? 'error' : 'pass'}
      />
      {vulnerable.map((v: any) => (
        <Row
          key={v.subdomain}
          lbl={v.subdomain}
          val={v.service || v.cname}
          title={`${v.cname}: ${v.evidence}`}
          reason={v.evidence}
          status="error"
        />
      ))}
    </Card>
  );
};

export default SubdomainTakeoverCard;
