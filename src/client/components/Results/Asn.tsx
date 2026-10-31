import { Card } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';

const AsnCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const { ip, asn, holder, prefix, rpki } = props.data;
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row lbl="IP" val={ip} />
      <Row
        lbl="ASN"
        val={asn ? `AS${asn}` : 'Unknown'}
        link={asn && `https://bgp.he.net/AS${asn}`}
      />
      <Row lbl="Holder" val={holder} />
      <Row lbl="Prefix" val={prefix} />
      <Row
        lbl="RPKI"
        val={rpki?.status}
        status={rpki?.status === 'valid' ? 'pass' : rpki?.status === 'invalid' ? 'error' : 'info'}
      />
    </Card>
  );
};

export default AsnCard;
