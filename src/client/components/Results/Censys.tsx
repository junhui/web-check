import { Card } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';

const CensysCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const { ip, services = [], autonomousSystem: as, country } = props.data;
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row lbl="IP" val={ip} link={`https://search.censys.io/hosts/${ip}`} />
      {as && <Row lbl="AS" val={`AS${as.asn} ${as.name || ''}`} />}
      {country && <Row lbl="Country" val={country} />}
      <Row lbl="Services" val={services.length} />
      {services.map((s: any) => (
        <Row
          key={`${s.port}/${s.transport}`}
          lbl={`${s.port}/${s.transport || 'tcp'}`}
          val={[s.serviceName, ...(s.software || [])].filter(Boolean).join(' · ')}
        />
      ))}
    </Card>
  );
};

export default CensysCard;
