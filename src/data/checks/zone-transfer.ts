import type { Check } from '.';

export default {
  title: 'Zone Transfer',
  categories: ['security', 'domain'],
  summary: 'Whether nameservers hand out the whole DNS zone',
  description: 'Attempts a DNS AXFR zone transfer against each authoritative nameserver.',
  use: 'An open zone transfer reveals every hostname in the zone, including internal and forgotten ones. This is an active check, only enabled when the instance allows it.',
  resources: [
    'https://www.cloudflare.com/learning/dns/glossary/what-is-a-zone-transfer/',
    'https://datatracker.ietf.org/doc/html/rfc5936',
  ],
} satisfies Check;
