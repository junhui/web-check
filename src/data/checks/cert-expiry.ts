import type { Check } from '.';

export default {
  title: 'Certificate Expiry',
  categories: ['security'],
  summary: 'Days left on the certificate, and recent issuance',
  description:
    'Reads the live certificate validity dates, and counts certificates issued for the domain in the last 90 days from Certificate Transparency logs, grouped by issuer.',
  use: 'Expired certificates take sites offline. An unexpected issuer in the CT logs can mean a mis-issued or malicious certificate.',
  resources: ['https://certificate.transparency.dev/', 'https://crt.sh/'],
} satisfies Check;
