import { Card } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';

const CookieSecurityCard = (props: {
  data: any;
  title: string;
  actionButtons: any;
}): JSX.Element => {
  const { cookies = [], issueCount } = props.data;
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row lbl="Cookies" val={cookies.length} />
      <Row lbl="Issues" val={issueCount || 'None'} status={issueCount ? 'warning' : 'pass'} />
      {cookies.map((c: any) => (
        <Row
          key={c.name}
          lbl={c.name}
          val={
            [c.secure && 'Secure', c.httpOnly && 'HttpOnly', c.sameSite && `SameSite=${c.sameSite}`]
              .filter(Boolean)
              .join(' · ') || 'No flags'
          }
          status={c.issues.length ? 'warning' : 'pass'}
          reason={c.issues.join('; ')}
        />
      ))}
    </Card>
  );
};

export default CookieSecurityCard;
