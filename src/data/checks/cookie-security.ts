import type { Check } from '.';

export default {
  title: 'Cookie Security',
  categories: ['security', 'privacy'],
  summary: 'Secure, HttpOnly and SameSite flags on each cookie',
  description:
    'Reads every Set-Cookie header the page sends and checks its security attributes and name prefixes. Cookie values are never returned.',
  use: 'Missing HttpOnly lets injected scripts steal session cookies, missing Secure lets them leak over plain HTTP, and missing SameSite weakens CSRF protection.',
  resources: [
    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security',
    'https://owasp.org/www-community/HttpOnly',
  ],
} satisfies Check;
