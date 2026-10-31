import type { Check } from '.';

export default {
  title: 'Page Scripts',
  categories: ['security', 'performance'],
  summary: 'Console errors, WebSockets, storage keys and globals the page creates',
  description:
    'While the page loads, collects console errors and warnings, uncaught exceptions, WebSocket connections, the names of localStorage and sessionStorage keys, and window properties not present on a blank page.',
  use: 'Errors point at broken or tampered scripts, unexpected WebSockets can signal miners or remote control, and custom globals and storage keys reveal which libraries and trackers are running.',
  resources: [
    'https://developer.mozilla.org/en-US/docs/Web/API/Window/localStorage',
    'https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API',
  ],
} satisfies Check;
