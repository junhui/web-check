import { Card } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';

const PageRedirectsCard = (props: {
  data: any;
  title: string;
  actionButtons: any;
}): JSX.Element => {
  const { url, finalUrl, title, status, redirects = {} } = props.data || {};
  const { http = [], navigations = [], count = 0 } = redirects;
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row lbl="Requested" val={url} />
      <Row lbl="Final URL" val={finalUrl} link={finalUrl} />
      <Row lbl="Page title" val={title} />
      {status && <Row lbl="Status" val={status} />}
      <Row lbl="Redirects" val={count} status={count > 2 ? 'warning' : 'pass'} />
      {http.map((hop: any, i: number) => (
        <Row key={`h${i}`} lbl={`HTTP ${hop.status ?? ''}`} val={hop.url} />
      ))}
      {navigations.length > 1 &&
        navigations.map((nav: string, i: number) => (
          <Row key={`n${i}`} lbl={`Navigation ${i + 1}`} val={nav} />
        ))}
    </Card>
  );
};

export default PageRedirectsCard;
