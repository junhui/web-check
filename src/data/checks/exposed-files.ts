import type { Check } from '.';

export default {
  title: 'Exposed Files',
  categories: ['security'],
  summary: 'Sensitive files left publicly downloadable',
  description:
    'Probes a short list of paths that should never be public, such as .git metadata, .env files, database dumps and phpinfo pages, and confirms hits by their content rather than status code alone.',
  use: 'A readable .git folder or .env file hands over source code and credentials. These leaks are common after manual deployments and are one of the first things attackers try. This is an active check, only enabled when the instance allows it.',
  resources: [
    'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information',
  ],
} satisfies Check;
