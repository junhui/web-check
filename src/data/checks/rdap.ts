import type { Check } from '.';

export default {
  title: 'RDAP Registration',
  categories: ['domain'],
  summary: 'Structured domain registration data via RDAP',
  description:
    "Queries the registry's RDAP service for registrar, status codes, key dates, nameservers and DNSSEC delegation. Personal contact details are removed.",
  use: 'RDAP is the structured replacement for WHOIS, and gives consistent expiry dates and registry locks across TLDs.',
  resources: ['https://www.icann.org/rdap', 'https://about.rdap.org/'],
} satisfies Check;
