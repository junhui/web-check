import type { Check } from '.';

export default {
  title: 'Browser Redirects',
  categories: ['security', 'seo'],
  summary: 'Where a real browser ends up after HTTP, JavaScript and meta redirects',
  description:
    'Follows the page in a browser, recording HTTP redirect hops and each main-frame navigation, including ones triggered by scripts or meta refresh, along with the final URL and title.',
  use: 'Script-based redirects are invisible to plain HTTP checks and are common in phishing, cloaking and hijacked sites. Long chains also slow pages down and dilute SEO.',
  resources: [
    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections',
    'https://developers.google.com/search/docs/crawling-indexing/301-redirects',
  ],
} satisfies Check;
