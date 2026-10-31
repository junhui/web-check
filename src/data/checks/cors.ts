import type { Check } from '.';

export default {
  title: 'CORS Policy',
  categories: ['security'],
  summary: 'Whether other sites can read responses on behalf of visitors',
  description:
    'Sends requests with a foreign Origin and with a null Origin, then inspects the Access-Control-Allow-Origin and Allow-Credentials headers that come back.',
  use: 'Reflecting any origin while allowing credentials lets a malicious site read authenticated data from logged-in visitors. Wildcards are lower risk but still worth knowing about.',
  resources: [
    'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
    'https://portswigger.net/web-security/cors',
  ],
} satisfies Check;
