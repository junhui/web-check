import type { Check } from '.';

export default {
  title: 'Brand Impersonation',
  categories: ['security', 'domain'],
  summary: 'Whether registered lookalike domains are copying the site to fool visitors',
  description:
    "Fingerprints the site's title, site name and favicon (SHA-256 and Shodan-style MurmurHash3), then visits up to 40 registered typosquat domains and scores each on a matching favicon, the brand name in its title or text, a password form, and whether it simply redirects back to the real site.",
  use: "Phishing kits often clone a brand's favicon and login page onto a lookalike domain. Spotting these early lets you request takedowns, warn customers and block the domains, while redirecting lookalikes are usually defensive registrations you already own.",
  resources: [
    'https://github.com/elceef/dnstwist',
    'https://help.shodan.io/the-basics/search-query-fundamentals',
    'https://attack.mitre.org/techniques/T1583/001/',
  ],
} satisfies Check;
