import type { Check } from '.';

export default {
  title: 'Subdomain Takeover',
  categories: ['security', 'domain'],
  summary: 'Subdomains pointing at unclaimed cloud resources',
  description:
    'Resolves CNAMEs for known subdomains and flags ones pointing at missing targets, or at cloud services showing an unclaimed-resource page.',
  use: 'A dangling CNAME lets anyone register the abandoned resource and serve content on your subdomain, which is useful for phishing and cookie theft.',
  resources: [
    'https://github.com/EdOverflow/can-i-take-over-xyz',
    'https://developer.mozilla.org/en-US/docs/Web/Security/Subdomain_takeovers',
  ],
} satisfies Check;
