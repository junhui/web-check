import type { Check } from '.';

export default {
  title: 'Leaked Secrets',
  categories: ['security'],
  summary: 'API keys and tokens exposed in front-end code',
  description:
    'Scans the page and its same-origin scripts for patterns matching cloud keys, payment keys, access tokens, JWTs and private keys. Matches are masked.',
  use: 'Anything shipped to the browser is public. Live keys found in JavaScript can be abused for billing fraud or data access, and should be rotated.',
  resources: ['https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure'],
} satisfies Check;
