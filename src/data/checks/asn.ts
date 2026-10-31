import type { Check } from '.';

export default {
  title: 'ASN & RPKI',
  categories: ['server'],
  summary: 'Which network announces the IP, and whether its route is signed',
  description:
    'Looks up the autonomous system and prefix announcing the IP via RIPEstat, and checks the RPKI validation status of that route.',
  use: 'RPKI-valid routes are protected against BGP hijacks. The ASN also tells you which provider really hosts the site.',
  resources: ['https://stat.ripe.net/', 'https://rpki.readthedocs.io/'],
} satisfies Check;
