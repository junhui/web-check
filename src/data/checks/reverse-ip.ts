import type { Check } from '.';

export default {
  title: 'Reverse IP',
  categories: ['server'],
  summary: 'Other domains hosted on the same IP',
  description: 'Finds other domain names that resolve to the same IP address.',
  use: 'Shared hosting means neighbouring sites can affect reputation and blocklisting, and the list can reveal related properties.',
  resources: ['https://hackertarget.com/reverse-ip-lookup/'],
} satisfies Check;
