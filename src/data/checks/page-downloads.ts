import type { Check } from '.';

export default {
  title: 'Automatic Downloads',
  categories: ['security'],
  summary: 'Files the page tries to download as soon as it loads',
  description:
    'Watches for responses served as attachments or with executable and archive content types while the page loads. Downloads are blocked and only hashed.',
  use: 'Drive-by downloads are a classic malware delivery trick. A legitimate page rarely pushes a file at visitors without being asked.',
  resources: [
    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Disposition',
    'https://www.virustotal.com/',
  ],
} satisfies Check;
