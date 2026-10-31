import type { Check } from '.';

export default {
  title: 'Tracking IDs',
  categories: ['privacy'],
  summary: 'Analytics and ad account IDs embedded in the page',
  description:
    'Scans the rendered HTML and loaded scripts for Google Analytics, Tag Manager, AdSense, Facebook Pixel, Hotjar, Microsoft Clarity and Yandex Metrica IDs.',
  use: 'These IDs belong to an account, so finding the same one on other sites is a strong sign they share an owner. Useful for OSINT and investigating networks of sites.',
  resources: [
    'https://support.google.com/analytics/answer/12270356',
    'https://www.bellingcat.com/resources/how-tos/2015/07/23/unveiling-hidden-connections-with-google-analytics-ids/',
  ],
} satisfies Check;
