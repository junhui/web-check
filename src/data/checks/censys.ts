import type { Check } from '.';

export default {
  title: 'Censys',
  categories: ['server'],
  summary: 'Internet-facing services seen by Censys',
  description:
    'Fetches the Censys host record for the server IP, listing exposed services and detected software. Needs CENSYS_API_ID and CENSYS_API_SECRET.',
  use: 'Shows what an internet-wide scanner already knows about the host, complementing Shodan.',
  resources: ['https://search.censys.io/'],
} satisfies Check;
