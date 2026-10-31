import { Card } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';

const PageScriptsCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const { pageErrors = [], websockets = [], storage = {}, globals = [] } = props.data || {};
  const consoleMsgs = props.data?.console || [];
  const errors = consoleMsgs.filter((m: any) => m.type === 'error');
  const warnings = consoleMsgs.filter((m: any) => m.type !== 'error');
  const local = storage.localStorage || [];
  const session = storage.sessionStorage || [];
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row
        lbl="Uncaught exceptions"
        val={pageErrors.length}
        status={pageErrors.length ? 'warning' : 'pass'}
      />
      {pageErrors.length > 0 && <Row lbl="Exceptions" listResults={pageErrors} />}
      <Row lbl="Console errors" val={errors.length} />
      {errors.length > 0 && <Row lbl="Errors" listResults={errors.map((m: any) => m.text)} />}
      <Row lbl="Console warnings" val={warnings.length} />
      {warnings.length > 0 && <Row lbl="Warnings" listResults={warnings.map((m: any) => m.text)} />}
      <Row lbl="WebSockets" val={websockets.length} />
      {websockets.length > 0 && <Row lbl="Sockets" listResults={websockets} />}
      <Row lbl="localStorage keys" val={local.length} />
      {local.length > 0 && <Row lbl="localStorage" listResults={local} />}
      <Row lbl="sessionStorage keys" val={session.length} />
      {session.length > 0 && <Row lbl="sessionStorage" listResults={session} />}
      <Row lbl="Custom globals" val={globals.length} />
      {globals.length > 0 && <Row lbl="Globals" listResults={globals} />}
    </Card>
  );
};

export default PageScriptsCard;
