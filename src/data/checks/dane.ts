import type { Check } from '.';

export default {
  title: 'DANE / TLSA',
  categories: ['security', 'email'],
  summary: 'TLSA records pinning certificates in DNS',
  description:
    'Looks up TLSA records for the HTTPS service and each mail server, and whether DNSSEC validated them.',
  use: 'DANE lets DNSSEC vouch for which certificates are valid, which stops downgrade and interception attacks on mail delivery between servers.',
  resources: ['https://datatracker.ietf.org/doc/html/rfc6698', 'https://internet.nl/'],
} satisfies Check;
