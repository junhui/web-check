import { Card, Note } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';

const PageDownloadsCard = (props: {
  data: any;
  title: string;
  actionButtons: any;
}): JSX.Element => {
  const { downloads = [] } = props.data || {};
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row
        lbl="Downloads triggered"
        val={downloads.length}
        status={downloads.length ? 'error' : 'pass'}
        reason={downloads.length ? 'The page served files as downloads on load' : undefined}
      />
      {downloads.map((d: any) => (
        <Row
          key={d.url}
          lbl={d.mimeType || 'unknown type'}
          listResults={[d.url, d.sha256 && `SHA-256: ${d.sha256}`].filter(Boolean)}
        />
      ))}
      <Note>Downloads were blocked, nothing was saved. Look up hashes on VirusTotal.</Note>
    </Card>
  );
};

export default PageDownloadsCard;
