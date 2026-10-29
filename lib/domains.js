/* Pall data: starter lists. These are deliberately small and readable. Pair with a full
   list-based blocker for broad coverage; Pall's value is the local heuristics around them. */
(function (root) {
  'use strict';
  const P = (root.Pall = root.Pall || {});

  // Ad networks, trackers and pop-under / push-spam networks. Used for both the blocking
  // ruleset (tools/gen_rules.js) and for counting ad references on a page.
  const AD_DOMAINS = [
    'doubleclick.net', 'googlesyndication.com', 'googleadservices.com', 'adservice.google.com',
    'amazon-adsystem.com', 'adnxs.com', 'adsrvr.org', 'advertising.com', 'criteo.com', 'criteo.net',
    'taboola.com', 'outbrain.com', 'revcontent.com', 'mgid.com', 'rubiconproject.com', 'pubmatic.com',
    'openx.net', 'casalemedia.com', 'indexww.com', 'smartadserver.com', 'adform.net', 'yieldmo.com',
    'sharethrough.com', '33across.com', 'media.net', 'bidswitch.net', 'contextweb.com', 'lijit.com',
    'sovrn.com', 'teads.tv', 'adtelligent.com', 'moatads.com', 'adsafeprotected.com', 'doubleverify.com',
    'serving-sys.com', 'flashtalking.com', 'bluekai.com', 'demdex.net', 'krxd.net', 'agkn.com',
    'rlcdn.com', 'tapad.com', 'everesttech.net', 'adition.com', 'zemanta.com',
    'scorecardresearch.com', 'quantserve.com', 'quantcount.com', 'google-analytics.com',
    'ads-twitter.com', 'ads.linkedin.com', 'px.ads.linkedin.com', 'analytics.tiktok.com',
    'ads.tiktok.com', 'bat.bing.com',
    'popads.net', 'popcash.net', 'propellerads.com', 'exoclick.com', 'exosrv.com', 'adcash.com',
    'clickadu.com', 'hilltopads.net', 'onclickads.net', 'adsterra.com', 'juicyads.com',
    'trafficjunky.net', 'plugrush.com', 'monetag.com', 'galaksion.com', 'admaven.com'
  ];

  const TRACKER_PARAMS = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'fbclid',
    'gclid', 'msclkid', 'mc_eid', 'igshid', 'yclid', '_hsenc', '_hsmi'];

  // Legitimate domains per brand. A page that uses the brand name on any other domain is suspect.
  const BRANDS = {
    paypal: ['paypal.com', 'paypal.me', 'paypalobjects.com'],
    microsoft: ['microsoft.com', 'live.com', 'office.com', 'office365.com', 'microsoftonline.com', 'outlook.com', 'azure.com', 'windows.com', 'bing.com'],
    google: ['google.com', 'gmail.com', 'youtube.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com', 'goo.gl', 'google.co.uk'],
    apple: ['apple.com', 'icloud.com', 'mzstatic.com'],
    amazon: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazonaws.com', 'amazon.ca', 'amazon.in'],
    netflix: ['netflix.com', 'nflxext.com', 'nflximg.net'],
    facebook: ['facebook.com', 'fb.com', 'fbcdn.net', 'messenger.com', 'meta.com'],
    instagram: ['instagram.com', 'cdninstagram.com'],
    linkedin: ['linkedin.com', 'licdn.com'],
    dropbox: ['dropbox.com', 'dropboxusercontent.com'],
    docusign: ['docusign.com', 'docusign.net'],
    dhl: ['dhl.com', 'dhl.de'],
    fedex: ['fedex.com'],
    ups: ['ups.com'],
    hmrc: ['gov.uk'],
    barclays: ['barclays.co.uk', 'barclays.com'],
    hsbc: ['hsbc.com', 'hsbc.co.uk'],
    lloyds: ['lloydsbank.com', 'lloydsbank.co.uk'],
    natwest: ['natwest.com'],
    chase: ['chase.com'],
    wellsfargo: ['wellsfargo.com'],
    bankofamerica: ['bankofamerica.com'],
    coinbase: ['coinbase.com'],
    binance: ['binance.com'],
    metamask: ['metamask.io']
  };

  const MULTI_TLD = ['co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.au', 'co.nz', 'co.jp', 'com.br', 'co.in', 'com.mx', 'co.za'];
  const SUSPICIOUS_TLDS = ['zip', 'mov', 'top', 'xyz', 'click', 'loan', 'work', 'gq', 'tk', 'ml', 'cf', 'ga', 'icu',
    'rest', 'country', 'stream', 'download', 'review', 'date', 'racing', 'win', 'bid', 'trade', 'accountant',
    'cricket', 'science', 'party', 'faith', 'men'];
  const SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'cutt.ly', 'rb.gy', 't.ly', 'shorturl.at', 'buff.ly'];

  P.domains = { AD_DOMAINS, TRACKER_PARAMS, BRANDS, MULTI_TLD, SUSPICIOUS_TLDS, SHORTENERS };
  if (typeof module !== 'undefined' && module.exports) module.exports = P;
})(typeof self !== 'undefined' ? self : globalThis);
