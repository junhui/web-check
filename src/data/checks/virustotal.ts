import type { Check } from '.';

export default {
  title: 'VirusTotal',
  categories: ['security'],
  summary: 'Verdicts from 70+ security vendors',
  description:
    'Fetches the VirusTotal domain report, including how many engines flag it as malicious or suspicious. Needs a VT_API_KEY on the instance.',
  use: 'A domain flagged by several vendors may be compromised, or may get blocked by browsers and corporate proxies.',
  resources: ['https://www.virustotal.com/'],
} satisfies Check;
