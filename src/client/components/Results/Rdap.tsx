import { Card } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';

const RdapCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const {
    domain,
    registrar,
    registrant,
    status = [],
    events = {},
    nameservers = [],
    dnssecSigned,
  } = props.data;
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row lbl="Domain" val={domain} />
      <Row lbl="Registrar" val={registrar?.name} />
      {registrant?.organization && <Row lbl="Registrant" val={registrant.organization} />}
      {registrant?.country && <Row lbl="Country" val={registrant.country} />}
      <Row lbl="Registered" val={events.registration} />
      <Row lbl="Expires" val={events.expiration} />
      <Row lbl="Last changed" val={events.lastChanged} />
      <Row lbl="DNSSEC signed" val={dnssecSigned} />
      <Row lbl="Status" listResults={status} />
      <Row lbl="Nameservers" listResults={nameservers} />
    </Card>
  );
};

export default RdapCard;
