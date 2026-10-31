import type { Check } from '.';

export default {
  title: 'Search Dorks',
  categories: ['security'],
  summary: 'Ready-made search queries for exposed content',
  description:
    'Builds Google search queries for the domain that surface exposed documents, login pages, directory listings, config files and mentions on paste sites.',
  use: 'Search engines often index things that were never meant to be public. These queries let you review that exposure quickly.',
  resources: ['https://www.exploit-db.com/google-hacking-database'],
} satisfies Check;
