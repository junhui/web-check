import type { Check } from '.';

export default {
  title: 'Page Requests',
  categories: ['performance', 'privacy'],
  summary: 'Every request the page makes as it loads, grouped by domain',
  description:
    'Loads the page in headless Chromium and records each network request, with its domain, IP, protocol, size and type, then totals how much is HTTPS, IPv6 and third-party.',
  use: 'Shows who a page really talks to, how heavy it is, and how much of it comes from third parties you may not control.',
  resources: [
    'https://developer.chrome.com/docs/devtools/network',
    'https://web.dev/articles/third-party-summary',
  ],
} satisfies Check;
