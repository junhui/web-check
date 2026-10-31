import type { Check } from '.';

export default {
  title: 'Subresource Integrity',
  categories: ['security'],
  summary: 'Third-party scripts and styles loaded without integrity hashes',
  description:
    'Lists scripts and stylesheets loaded from other origins, and whether each carries an integrity attribute.',
  use: 'Without SRI, a compromised CDN or third party can silently change the code running on your page. Integrity hashes make the browser refuse modified files.',
  resources: ['https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity'],
} satisfies Check;
