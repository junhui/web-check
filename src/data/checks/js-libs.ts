import type { Check } from '.';

export default {
  title: 'Vulnerable JS Libraries',
  categories: ['security'],
  summary: 'Front-end libraries with known vulnerabilities',
  description:
    'Detects JavaScript libraries and their versions from script URLs and file contents, then matches them against the retire.js vulnerability database.',
  use: 'Outdated front-end libraries like old jQuery or Angular versions carry public CVEs, often for cross-site scripting, and are easy for attackers to fingerprint.',
  resources: [
    'https://retirejs.github.io/retire.js/',
    'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
  ],
} satisfies Check;
