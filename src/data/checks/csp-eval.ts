import type { Check } from '.';

export default {
  title: 'CSP Evaluation',
  categories: ['security'],
  summary: 'How strong the Content Security Policy actually is',
  description:
    "Parses the Content-Security-Policy header and meta tags, then evaluates each directive using rules modelled on Google's CSP Evaluator.",
  use: "Having a CSP isn't the same as having a useful one. unsafe-inline, wildcards or a missing object-src can make a policy easy to bypass for cross-site scripting.",
  resources: [
    'https://csp-evaluator.withgoogle.com/',
    'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
  ],
} satisfies Check;
