// Known advertising / data-sharing and analytics hosts, used only to tag items in the consent audit.
// An entry with a path ("facebook.com/tr") only matches requests under that path.
export const AD_DOMAINS = [
  'doubleclick.net',
  'googlesyndication.com',
  'googleadservices.com',
  'googletagservices.com',
  'google.com/ads',
  'google.com/pagead',
  'adservice.google.com',
  'facebook.com/tr',
  'connect.facebook.net',
  'bat.bing.com',
  'ads.linkedin.com',
  'px.ads.linkedin.com',
  'analytics.tiktok.com',
  'tiktok.com/i18n/pixel',
  'criteo.com',
  'criteo.net',
  'attentivemobile.com',
  'attn.tv',
  'narrativ.com',
  'ct.pinterest.com',
  'pinimg.com/ct',
  'sc-static.net',
  'tr.snapchat.com',
  'redditstatic.com/ads',
  'alb.reddit.com',
  'taboola.com',
  'outbrain.com',
  'amazon-adsystem.com',
  'adnxs.com',
  'rubiconproject.com',
  'pubmatic.com',
  'openx.net',
  'casalemedia.com',
  'adsrvr.org',
  'demdex.net',
  'everesttech.net',
  'rlcdn.com',
  'quantserve.com',
  'scorecardresearch.com',
  'bluekai.com',
  'mathtag.com',
  'agkn.com',
  'adroll.com',
  'yahoo.com/cms',
  'ads.yahoo.com',
  'analytics.yahoo.com',
  'impactradius-event.com',
  'cj.com',
  'emjcd.com',
  'awin1.com',
  'pepperjam.com',
  'rakuten.com',
  'linksynergy.com',
  'tapad.com',
  '33across.com',
  '3lift.com',
];

export const ANALYTICS_DOMAINS = [
  'google-analytics.com',
  'analytics.google.com',
  'googletagmanager.com',
  'clarity.ms',
  'hotjar.com',
  'omtrdc.net',
  '2o7.net',
  'segment.io',
  'segment.com',
  'mixpanel.com',
  'amplitude.com',
  'fullstory.com',
  'quantummetric.com',
  'newrelic.com',
  'nr-data.net',
  'optimizely.com',
];

const split = (entry) => {
  const i = entry.indexOf('/');
  return i < 0 ? [entry, null] : [entry.slice(0, i), entry.slice(i)];
};

const hostMatches = (host, domain) => host === domain || host.endsWith(`.${domain}`);

const matchList = (list, host, paths) =>
  list.some((entry) => {
    const [domain, prefix] = split(entry);
    if (!hostMatches(host, domain)) return false;
    return !prefix || (paths || []).some((p) => p.startsWith(prefix));
  });

// 'ad', 'analytics' or null. Path-prefixed entries need a matching path
export const domainTag = (host, paths) => {
  const h = String(host || '')
    .toLowerCase()
    .replace(/^\./, '');
  if (!h) return null;
  if (matchList(AD_DOMAINS, h, paths)) return 'ad';
  if (matchList(ANALYTICS_DOMAINS, h, paths)) return 'analytics';
  return null;
};
