import type { Check } from '.';

export default {
  title: 'HTTP Methods',
  categories: ['security', 'server'],
  summary: 'Which HTTP verbs the server accepts',
  description:
    'Sends an OPTIONS request to read the advertised methods, and a TRACE request to see whether the server echoes requests back.',
  use: 'TRACE enables cross-site tracing, and PUT or DELETE on a public endpoint can let anyone change content. Most sites only need GET, HEAD and POST. This is an active check, only enabled when the instance allows it.',
  resources: [
    'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods',
  ],
} satisfies Check;
