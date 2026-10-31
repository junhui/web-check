import type { Check } from '.';

export default {
  title: 'urlscan.io History',
  categories: ['security'],
  summary: 'Past public scans of this domain on urlscan.io',
  description:
    'Searches urlscan.io for existing public scans of the domain, showing when it was scanned, which IPs and countries it resolved to, and the latest verdict. No new scan is submitted. An optional URLSCAN_API_KEY raises rate limits and enables verdicts.',
  use: 'Shows how a site has looked and where it was hosted over time, and whether urlscan.io has ever classified it as malicious or phishing.',
  resources: ['https://urlscan.io/', 'https://docs.urlscan.io/'],
} satisfies Check;
