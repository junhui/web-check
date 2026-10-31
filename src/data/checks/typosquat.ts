import type { Check } from '.';

export default {
  title: 'Lookalike Domains',
  categories: ['security', 'domain'],
  summary: 'Registered typo and lookalike domains',
  description:
    'Generates typo, homoglyph, bit-flip and TLD-swap variations of the domain and checks which of them resolve, and which accept mail.',
  use: 'Lookalike domains are used for phishing and credential harvesting. Ones with MX records can also receive misaddressed email.',
  resources: ['https://github.com/elceef/dnstwist'],
} satisfies Check;
