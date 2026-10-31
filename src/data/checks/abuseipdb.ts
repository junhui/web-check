import type { Check } from '.';

export default {
  title: 'AbuseIPDB',
  categories: ['security', 'server'],
  summary: 'Abuse reports against the server IP',
  description:
    'Checks the server IP on AbuseIPDB for abuse reports in the last 90 days. Needs an ABUSEIPDB_API_KEY on the instance.',
  use: 'A high abuse score means the IP has been reported for attacks or spam, which can point to compromise or a noisy shared host.',
  resources: ['https://www.abuseipdb.com/'],
} satisfies Check;
