/* Pall security engine. Pure functions, no DOM, no network: everything runs locally and is unit-tested.

   Findings have an audience:
     user  risks to the person browsing (phishing, scams, spam, adware, insecure logins); scored
     dev   site hygiene for owners and developers (headers, outdated libraries, exposed keys); not scored
   Detection is heuristic. It will miss things and occasionally flag legitimate pages, which is why
   every finding says why it fired and nothing here acts on a page without the user. */
(function (root) {
  'use strict';
  const P = (root.Pall = root.Pall || {});
  const D = P.domains;
  const WEIGHT = { critical: 45, high: 30, medium: 15, low: 6, info: 0 };

  // ---------- host helpers ----------
  function registrable(host) {
    const h = String(host).toLowerCase().replace(/\.$/, '');
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(':')) return h;     // an IP address is its own domain
    const parts = h.split('.');
    if (parts.length <= 2) return parts.join('.');
    const last2 = parts.slice(-2).join('.');
    return D.MULTI_TLD.includes(last2) ? parts.slice(-3).join('.') : last2;
  }
  const hostOf = (u) => { try { return new URL(u).hostname.toLowerCase(); } catch (e) { return ''; } };
  const isIp = (h) => /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(':');
  const isLocal = (h) => h === 'localhost' || h.endsWith('.localhost') || /^(127\.|10\.|192\.168\.)/.test(h) || h === '::1' || h === '[::1]';
  const onDomain = (host, d) => host === d || host.endsWith('.' + d);
  const isAdHost = (h) => D.AD_DOMAINS.some((d) => onDomain(h, d));
  function lev(a, b) {
    const m = a.length, n = b.length;
    if (Math.abs(m - n) > 1) return 2;
    const dp = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
    for (let j = 1; j <= n; j++) dp[0][j] = j;
    for (let i = 1; i <= m; i++) for (let j = 1; j <= n; j++)
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    return dp[m][n];
  }
  const deleet = (s) => s.replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/5/g, 's').replace(/@/g, 'a');

  // Does this host impersonate a known brand? Returns {brand, kind} or null.
  function brandImpersonation(host) {
    host = host.toLowerCase();
    const reg = registrable(host);
    for (const [brand, real] of Object.entries(D.BRANDS)) if (real.some((d) => onDomain(host, d))) return null;
    const regLabel = reg.split('.')[0];
    const subLabels = host.slice(0, Math.max(0, host.length - reg.length)).split('.').filter(Boolean);
    const regTokens = regLabel.split('-');
    for (const brand of Object.keys(D.BRANDS)) {
      if (subLabels.some((l) => l.split('-').includes(brand) || deleet(l) === brand)) return { brand, kind: 'subdomain' };
      if (regTokens.some((t) => t === brand || (t !== deleet(t) && deleet(t) === brand))) return { brand, kind: 'keyword' };
      if (brand.length >= 6 && regTokens.some((t) => t.length >= 5 && t !== brand && lev(deleet(t), brand) === 1)) return { brand, kind: 'lookalike' };
    }
    return null;
  }

  // ---------- text patterns ----------
  const PHONE_RE = /(\+?\d[\d\s().-]{8,}\d)/;
  const SCAM = [
    { id: 'tech-support', w: 30, sev: 'high', title: 'Fake virus or tech-support alert',
      detail: 'Wording typical of tech-support scams. Real browsers and Windows never tell you to call a number.',
      re: /(your (computer|pc|device|system|browser) (is|has been|may be) (infected|compromised|blocked|locked|hacked)|virus(es)? (was |were )?detected|malware (was )?detected|windows defender (alert|warning)|microsoft (support|security) (alert|warning)|call (microsoft|apple|windows|tech)? ?support|do not (close|restart|shut ?down) (this|your))/i },
    { id: 'seed-phrase', w: 45, sev: 'critical', title: 'Asks for your wallet recovery phrase',
      detail: 'No legitimate site or support agent ever needs your seed or recovery phrase. Anyone who has it can empty your wallet.',
      re: /((enter|provide|submit|paste|type|import) (your )?(wallet )?(seed|recovery|secret recovery|mnemonic) (phrase|words)|(seed|recovery|secret recovery) phrase.{0,40}(validate|verify|sync|rectify|unlock))/i },
    { id: 'gift-card', w: 30, sev: 'high', title: 'Asks for payment by gift card',
      detail: 'Gift card payment is a hallmark of scams: it is untraceable and cannot be reversed.',
      re: /((pay(ment)?|send|buy|purchase).{0,40}(gift ?cards?|itunes cards?|google play cards?|steam cards?)|(gift ?cards?).{0,30}(codes?|pin).{0,30}(send|read|share))/i },
    { id: 'remote-access', w: 25, sev: 'high', title: 'Pushes you to install remote-access software',
      detail: 'Scammers get you to install remote-control tools to take over your computer and bank logins.',
      re: /((anydesk|teamviewer|ultraviewer|quick ?assist).{0,80}(install|download|enter|code)|(install|download).{0,40}(anydesk|teamviewer|ultraviewer))/i },
    { id: 'prize', w: 20, sev: 'medium', title: 'Prize or reward claim',
      detail: 'Unsolicited "you have won" messages are used to harvest personal data or payments.',
      re: /(you('| ha)ve (been selected|won)|congratulations[!,]? you|claim your (prize|reward|gift)|you are (the )?(lucky )?winner|free (iphone|ipad|gift card|robux|v-?bucks)|unclaimed (funds|reward))/i },
    { id: 'verify-account', w: 18, sev: 'medium', title: 'Pressure to verify or unlock an account',
      detail: 'Phishing often claims your account is suspended and asks you to confirm details.',
      re: /(verify your (account|identity|information|details)|confirm your (account|identity|password|payment)|(account|card|access) (has been |was |will be )?(suspended|locked|limited|restricted|disabled|closed)|unusual (sign-?in|activity) (detected|on your)|(update|confirm) your (billing|payment) (information|details|method))/i },
    { id: 'delivery-fee', w: 22, sev: 'medium', title: 'Delivery-fee scam wording',
      detail: 'Fake courier messages ask for a small "redelivery" fee to capture card details.',
      re: /(your (parcel|package|delivery) (could not|couldn't|cannot|can't) be delivered|redelivery fee|customs fee|pay (a )?(small )?(shipping|delivery|redelivery) fee)/i },
    { id: 'crypto-pay', w: 20, sev: 'medium', title: 'Asks for crypto payment',
      detail: 'Requests to send crypto, or to "double" it, are almost always fraud.',
      re: /((send|transfer|pay).{0,30}(bitcoin|btc|usdt|ethereum|crypto)|double your (bitcoin|crypto|btc|eth))/i },
    { id: 'advance-fee', w: 20, sev: 'medium', title: 'Advance-fee or inheritance wording',
      detail: 'Classic advance-fee fraud: a large sum is promised if you pay or share details first.',
      re: /((inheritance|next of kin|beneficiary).{0,80}(million|usd|\$|£|€)|(transfer|release) of funds)/i },
    { id: 'tax-refund', w: 18, sev: 'medium', title: 'Tax refund bait',
      detail: 'Fake tax-authority messages promise refunds to collect bank details.',
      re: /(tax refund|hmrc|irs).{0,60}(eligible|claim|refund of)/i },
    { id: 'urgency', w: 8, sev: 'low', title: 'High-pressure urgency',
      detail: 'Artificial deadlines are used to stop you thinking.',
      re: /(within (12|24|48) hours|act now|immediately or|final (notice|warning)|last chance|expires? (today|in \d+ (minutes|hours))|urgent(ly)? (action|response))/i }
  ];
  const SPAM_WORDS = ['viagra', 'cialis', 'casino', 'payday loan', 'replica watches', 'cheap ray-ban', 'seo services',
    'buy followers', 'online pharmacy', 'weight loss miracle', 'work from home', 'forex signals', 'essay writing service',
    'no credit check', 'adult dating', 'bitcoin doubler', 'cheap nfl jerseys'];

  function textFindings(text) {
    const out = [];
    const t = String(text || '');
    for (const s of SCAM) {
      if (s.re.test(t)) {
        let { w, sev, title, detail } = s;
        if (s.id === 'tech-support' && PHONE_RE.test(t)) { w += 5; detail += ' It also includes a phone number to call.'; }
        out.push({ id: s.id, audience: 'user', severity: sev, weight: w, title, detail });
      }
    }
    const low = t.toLowerCase();
    const hits = SPAM_WORDS.filter((w) => low.includes(w));
    if (hits.length >= 2 || (hits.length === 1 && t.length < 400)) {
      out.push({ id: 'spam-content', audience: 'user', severity: 'medium', weight: 15, title: 'Looks like spam',
        detail: `Contains spam-typical terms: ${hits.slice(0, 4).join(', ')}.` });
    }
    return out;
  }

  const levelFor = (score) => (score >= 60 ? 'danger' : score >= 25 ? 'caution' : 'safe');
  const finalize = (findings, extra = {}) => {
    const user = findings.filter((f) => f.audience === 'user');
    const score = Math.min(100, user.reduce((a, f) => a + (f.weight ?? WEIGHT[f.severity] ?? 0), 0));
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    findings.sort((a, b) => order[a.severity] - order[b.severity]);
    return { score, level: levelFor(score), findings, ...extra };
  };

  // ---------- link checks (shared by page and text analysis) ----------
  function urlFindings(url, ctx = '') {
    const h = hostOf(url);
    if (!h) return [];
    const out = [];
    if (h.includes('xn--')) out.push({ id: 'punycode', audience: 'user', severity: 'high', weight: 30, title: 'Address uses disguised characters', detail: `${h} contains punycode, which can make a fake address look like a real one.` });
    if (isIp(h) && !isLocal(h)) out.push({ id: 'ip-host', audience: 'user', severity: 'medium', weight: 18, title: 'Site is a bare IP address', detail: `${h} is not a normal website name. Legitimate services rarely ask you to sign in at a raw IP.` });
    const bi = brandImpersonation(h);
    if (bi) {
      const strong = bi.kind === 'subdomain' || bi.kind === 'lookalike';
      out.push({ id: 'brand-' + bi.kind, audience: 'user', severity: strong ? 'high' : 'medium', weight: strong ? 30 : 15,
        title: `Possible ${bi.brand} impersonation`,
        detail: `${h} uses the name "${bi.brand}" but is not one of ${bi.brand}'s own domains.${ctx}` });
    }
    const tld = h.split('.').pop();
    if (D.SUSPICIOUS_TLDS.includes(tld)) out.push({ id: 'odd-tld', audience: 'user', severity: 'low', weight: 6, title: `.${tld} addresses are often abused`, detail: `Many scam and spam sites use cheap .${tld} domains.` });
    if (D.SHORTENERS.some((s) => onDomain(h, s))) out.push({ id: 'shortener', audience: 'user', severity: 'low', weight: 6, title: 'Shortened link hides its destination', detail: `${h} is a link shortener; the real address is not visible.` });
    return out;
  }

  // ---------- full page analysis ----------
  function analyzePage(sig) {
    const f = [];
    const host = (sig.hostname || hostOf(sig.url) || '').toLowerCase();
    const https = /^https:/.test(sig.url || '');
    const local = isLocal(host);
    const forms = sig.forms || [];
    const hasPassword = forms.some((x) => x.hasPassword);
    const hasCard = forms.some((x) => x.hasCard);

    f.push(...urlFindings(sig.url));
    if (!https && !local && /^http:/.test(sig.url || '')) {
      if (hasPassword || hasCard) f.push({ id: 'insecure-login', audience: 'user', severity: 'critical', weight: 40, title: 'Sign-in or payment form on an unencrypted page', detail: 'Anything you type here travels in plain text and can be read by others on the network.' });
      else f.push({ id: 'no-https', audience: 'user', severity: 'low', weight: 6, title: 'Connection is not encrypted', detail: 'This page uses plain HTTP, so others on your network can see and alter it.' });
    }
    for (const fm of forms) {
      if (!(fm.hasPassword || fm.hasCard) || !fm.action) continue;
      const ah = hostOf(fm.action);
      if (/^http:/.test(fm.action) && https) f.push({ id: 'form-downgrade', audience: 'user', severity: 'high', weight: 30, title: 'Form sends your details over HTTP', detail: `The form posts to ${ah} without encryption.` });
      else if (ah && registrable(ah) !== registrable(host)) f.push({ id: 'form-cross-site', audience: 'user', severity: 'high', weight: 30, title: 'Sign-in form sends data to a different site', detail: `This page is on ${registrable(host)} but the form posts to ${registrable(ah)}.` });
    }
    // brand named in the page title/text with a login form, on a different domain
    if (hasPassword) {
      const head = ((sig.title || '') + ' ' + String(sig.text || '').slice(0, 1500)).toLowerCase();
      for (const [brand, real] of Object.entries(D.BRANDS)) {
        if (head.includes(brand) && !real.some((d) => onDomain(host, d)) && !f.some((x) => x.id.startsWith('brand-'))) {
          f.push({ id: 'brand-login-mismatch', audience: 'user', severity: 'high', weight: 30, title: `Asks for a password while presenting as ${brand}`, detail: `The page mentions ${brand} and asks you to sign in, but the site is ${registrable(host)}.` });
          break;
        }
      }
    }
    f.push(...textFindings(sig.text));

    // hidden cross-origin frames, redirects, overlays
    const hid = (sig.iframes || []).filter((x) => x.hidden && x.src && registrable(hostOf(x.src)) !== registrable(host) && !isAdHost(hostOf(x.src)));
    if (hid.length) f.push({ id: 'hidden-iframe', audience: 'user', severity: 'medium', weight: 15, title: 'Hidden frame loads another site', detail: `${hid.length} invisible frame(s), e.g. ${hostOf(hid[0].src)}. Used for tracking and drive-by attacks.` });
    if (sig.metaRefresh) {
      const m = String(sig.metaRefresh).match(/url\s*=\s*['"]?([^'"]+)/i);
      const rh = m ? hostOf(new URL(m[1], sig.url).href) : '';
      if (rh && registrable(rh) !== registrable(host)) f.push({ id: 'meta-redirect', audience: 'user', severity: 'medium', weight: 15, title: 'Page redirects you to another site', detail: `Automatic redirect to ${rh}.` });
    }
    if ((sig.overlays || 0) > 0) f.push({ id: 'click-overlay', audience: 'user', severity: 'medium', weight: 18, title: 'Invisible layer covers the page', detail: 'A transparent element sits over the whole page and can capture your clicks (clickjacking or forced ad clicks).' });

    // link text that shows one address while linking to another
    let mism = null;
    for (const l of sig.links || []) {
      const m = String(l.text || '').match(/\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b/i);
      if (!m) continue;
      const th = m[1].toLowerCase(), hh = hostOf(l.href);
      if (hh && registrable(th) !== registrable(hh) && !isAdHost(hh) && /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(th) && /^(www\.)?[a-z0-9-]+\.[a-z]{2,}/.test(th)) { mism = { th, hh }; break; }
    }
    if (mism) f.push({ id: 'link-mismatch', audience: 'user', severity: 'medium', weight: 18, title: 'A link shows one address but goes to another', detail: `Link text says ${mism.th} but leads to ${mism.hh}.` });

    // runtime events from the page-world guard
    const ev = sig.events || {};
    if (ev.notification) f.push({ id: 'push-prompt', audience: 'user', severity: 'medium', weight: 12, title: 'Site tried to ask for notifications unprompted', detail: `Pall denied ${ev.notification} automatic notification request(s). Push-notification spam is a common adware route.` });
    if (ev.popup) f.push({ id: 'popups', audience: 'user', severity: ev.popup >= 3 ? 'high' : 'medium', weight: ev.popup >= 3 ? 25 : 12, title: 'Site tried to open pop-ups without a click', detail: `Pall blocked ${ev.popup} pop-up attempt(s).` });

    // adware / trackers referenced by the page
    const adHosts = [...new Set((sig.resourceHosts || []).filter(isAdHost))];
    if (adHosts.length >= 8) f.push({ id: 'ad-heavy', audience: 'user', severity: 'medium', weight: 12, title: 'Very ad- and tracker-heavy page', detail: `References ${adHosts.length} ad or tracking networks.` });
    const popNets = adHosts.filter((h) => ['popads.net', 'popcash.net', 'propellerads.com', 'exoclick.com', 'exosrv.com', 'adcash.com', 'clickadu.com', 'hilltopads.net', 'onclickads.net', 'adsterra.com', 'monetag.com', 'galaksion.com', 'admaven.com'].some((d) => onDomain(h, d)));
    if (popNets.length) f.push({ id: 'popunder-network', audience: 'user', severity: 'high', weight: 30, title: 'Uses a pop-under / push-ad network', detail: `Loads ${popNets.join(', ')}, networks known for aggressive pop-unders and fake alerts.` });

    // developer hygiene
    if (https && (sig.mixed || 0) > 0) f.push({ id: 'mixed-content', audience: 'dev', severity: 'medium', title: 'Mixed content', detail: `${sig.mixed} resource(s) load over HTTP on an HTTPS page.`, fix: { label: 'Serve every resource over HTTPS', snippets: { csp: "Content-Security-Policy: upgrade-insecure-requests" } } });
    f.push(...analyzeLibs(sig.libs || []));
    f.push(...analyzeSecrets([...(sig.inlineScripts || []), String(sig.html || '')]));

    return finalize(f, { stats: { adHosts: adHosts.length, host } });
  }

  // ---------- text-only check (pasted message, email, selection) ----------
  function analyzeText(text) {
    const f = textFindings(text);
    const urls = [...new Set(String(text).match(/https?:\/\/[^\s<>"')]+/gi) || [])].slice(0, 20);
    const urlF = [];
    urls.forEach((u) => urlF.push(...urlFindings(u, ' (found in the message)')));
    f.push(...urlF);
    // Scam wording AND a link to a suspicious address is far stronger than either alone.
    const wording = f.some((x) => x.weight >= 18 && !urlF.includes(x));
    const badLink = urlF.some((x) => /^(brand-|odd-tld|punycode|ip-host|shortener)/.test(x.id));
    if (wording && badLink) f.push({ id: 'scam-combo', audience: 'user', severity: 'high', weight: 15, title: 'Scam wording plus a suspicious link', detail: 'The message pressures you to act and points to an address that does not look legitimate.' });
    const r = finalize(f, { urls });
    r.verdict = r.level === 'danger' ? 'Likely scam or phishing' : r.level === 'caution' ? 'Suspicious' : 'No warning signs found';
    return r;
  }

  // ---------- libraries ----------
  function cmp(a, b) {
    const pa = String(a).split(/[.-]/).map((x) => parseInt(x, 10) || 0), pb = String(b).split(/[.-]/).map((x) => parseInt(x, 10) || 0);
    for (let i = 0; i < 3; i++) { if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0); }
    return 0;
  }
  const VULN_LIBS = [
    { name: 'jQuery', ranges: [['0.0.0', '3.5.0']], cves: ['CVE-2020-11022', 'CVE-2020-11023'], issue: 'Cross-site scripting in HTML handling', upgrade: '3.7.1 or later' },
    { name: 'lodash', ranges: [['0.0.0', '4.17.21']], cves: ['CVE-2020-8203', 'CVE-2021-23337'], issue: 'Prototype pollution and command injection via templates', upgrade: '4.17.21 or later' },
    { name: 'Bootstrap', ranges: [['0.0.0', '3.4.1'], ['4.0.0', '4.3.1']], cves: ['CVE-2019-8331'], issue: 'Cross-site scripting in tooltip/popover', upgrade: '3.4.1, 4.3.1 or 5.x' },
    { name: 'Moment.js', ranges: [['0.0.0', '2.29.4']], cves: ['CVE-2022-24785', 'CVE-2022-31129'], issue: 'Path traversal and regular-expression denial of service', upgrade: '2.29.4 or later' }
  ];
  const EOL_LIBS = [
    { name: 'AngularJS', test: (v) => cmp(v, '2.0.0') < 0, issue: 'AngularJS reached end of life in December 2021 and receives no security fixes', upgrade: 'Migrate to a supported framework' },
    { name: 'Vue', test: (v) => cmp(v, '3.0.0') < 0, issue: 'Vue 2 reached end of life on 31 December 2023', upgrade: 'Upgrade to Vue 3' }
  ];
  function analyzeLibs(libs) {
    const out = [];
    for (const l of libs) {
      if (!l || !l.name || !l.version) continue;
      const v = VULN_LIBS.find((x) => x.name === l.name);
      if (v && v.ranges.some(([lo, hi]) => cmp(l.version, lo) >= 0 && cmp(l.version, hi) < 0)) {
        out.push({ id: 'vuln-lib-' + l.name.toLowerCase(), audience: 'dev', severity: 'high', title: `${l.name} ${l.version} has known vulnerabilities`,
          detail: `${v.issue} (${v.cves.join(', ')}). Upgrade to ${v.upgrade}.`, fix: { label: `Update ${l.name}`, snippets: { npm: `npm install ${l.name === 'Moment.js' ? 'moment' : l.name.toLowerCase()}@latest` } } });
        continue;
      }
      const e = EOL_LIBS.find((x) => x.name === l.name);
      if (e && e.test(l.version)) out.push({ id: 'eol-lib-' + l.name.toLowerCase(), audience: 'dev', severity: 'medium', title: `${l.name} ${l.version} is end-of-life`, detail: `${e.issue}. ${e.upgrade}.` });
    }
    return out;
  }

  // ---------- exposed secrets in page source (never stores the secret) ----------
  function analyzeSecrets(texts) {
    const seen = new Map();
    for (const t of texts) for (const s of P.scanSecrets(t || '')) seen.set(s.kind + s.tag, s);
    return [...seen.values()].slice(0, 5).map((s) => ({
      id: 'exposed-secret', audience: 'dev', severity: 'critical', title: `Possible exposed ${s.kind.replace(/_/g, ' ')} in page source`,
      detail: `A value matching a ${s.kind.replace(/_/g, ' ')} (${s.length} characters, fingerprint ${s.tag}) is visible to every visitor. Pall never stores or sends the value itself.`,
      fix: { label: 'Rotate the key and move it server-side', snippets: { steps: '1. Revoke the exposed key at the provider.\n2. Issue a new key and keep it in a server-side environment variable.\n3. Call the provider from your backend, not from browser code.' } }
    }));
  }

  // ---------- response headers ----------
  function analyzeHeaders(url, headers) {
    const h = {}, cookies = [];
    for (const x of headers || []) {
      const n = String(x.name).toLowerCase();
      if (n === 'set-cookie') cookies.push(String(x.value)); else h[n] = String(x.value);
    }
    const https = /^https:/.test(url);
    const f = [];
    const add = (id, severity, title, detail, snippets) => f.push({ id, audience: 'dev', severity, title, detail, ...(snippets ? { fix: { label: 'Copy fix', snippets } } : {}) });
    if (https && !h['strict-transport-security']) add('hdr-hsts', 'low', 'No Strict-Transport-Security header', 'Browsers may be tricked into HTTP on a first visit or after a downgrade attack.', {
      nginx: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;', apache: 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"', node: "app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));" });
    const csp = h['content-security-policy'];
    if (!csp) add('hdr-csp', 'medium', 'No Content-Security-Policy header', 'A CSP is the strongest browser-side defence against cross-site scripting.', {
      nginx: `add_header Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'" always;`, apache: `Header always set Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"`, node: "app.use(helmet.contentSecurityPolicy());" });
    else if (/script-src[^;]*'unsafe-(inline|eval)'/.test(csp)) add('hdr-csp-unsafe', 'low', "CSP allows 'unsafe-inline' or 'unsafe-eval' scripts", 'This largely cancels the protection against injected scripts. Use nonces or hashes instead.');
    if (!h['x-frame-options'] && !(csp && /frame-ancestors/.test(csp))) add('hdr-frame', 'low', 'Page can be framed by other sites', 'Without X-Frame-Options or frame-ancestors, the page is open to clickjacking.', {
      nginx: 'add_header X-Frame-Options "SAMEORIGIN" always;', apache: 'Header always set X-Frame-Options "SAMEORIGIN"', node: 'app.use(helmet.frameguard({ action: "sameorigin" }));' });
    if ((h['x-content-type-options'] || '').toLowerCase() !== 'nosniff') add('hdr-nosniff', 'low', 'No X-Content-Type-Options: nosniff', 'Browsers may guess content types and execute uploaded files as scripts.', {
      nginx: 'add_header X-Content-Type-Options "nosniff" always;', apache: 'Header always set X-Content-Type-Options "nosniff"', node: 'app.use(helmet.noSniff());' });
    if (!h['referrer-policy']) add('hdr-referrer', 'info', 'No Referrer-Policy header', 'Full URLs, which may contain tokens, can leak to other sites in the Referer header.', {
      nginx: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;', apache: 'Header always set Referrer-Policy "strict-origin-when-cross-origin"', node: 'app.use(helmet.referrerPolicy({ policy: "strict-origin-when-cross-origin" }));' });
    if (/\d+\.\d+/.test(h.server || '')) add('hdr-server', 'info', 'Server header reveals a version', `"${h.server}" helps attackers pick known exploits.`, { nginx: 'server_tokens off;', apache: 'ServerTokens Prod\nServerSignature Off' });
    if (h['x-powered-by']) add('hdr-powered', 'info', 'X-Powered-By header reveals the stack', `"${h['x-powered-by']}" is unnecessary information for attackers.`, { node: 'app.disable("x-powered-by");', nginx: 'proxy_hide_header X-Powered-By;' });
    if (h['access-control-allow-origin'] === '*' && /true/i.test(h['access-control-allow-credentials'] || '')) add('hdr-cors', 'high', 'CORS allows any origin with credentials', 'Any website could read authenticated responses from this site.');
    if (cookies.length) {
      const weak = cookies.map((c) => ({ name: c.split('=')[0].trim(), secure: /;\s*secure/i.test(c), httponly: /;\s*httponly/i.test(c), samesite: /;\s*samesite=/i.test(c) }))
        .filter((c) => (https && !c.secure) || !c.httponly || !c.samesite);
      if (weak.length) add('hdr-cookies', 'low', `${weak.length} cookie(s) missing security flags`, `Cookies ${weak.slice(0, 4).map((c) => c.name).join(', ')} lack Secure, HttpOnly or SameSite.`, { node: 'res.cookie(name, value, { secure: true, httpOnly: true, sameSite: "lax" });', nginx: 'proxy_cookie_flags ~ secure httponly samesite=lax;' });
    }
    return f;
  }

  // One ready-to-paste nginx block for every header issue found.
  function buildHeaderFixes(findings) {
    const lines = findings.filter((f) => f.fix && f.fix.snippets && f.fix.snippets.nginx && f.id.startsWith('hdr-')).map((f) => f.fix.snippets.nginx);
    return lines.length ? `# Pall: suggested security headers (nginx)\n${lines.join('\n')}\n` : '';
  }

  Object.assign(P, { analyzePage, analyzeText, analyzeHeaders, analyzeLibs, analyzeSecrets, buildHeaderFixes, brandImpersonation, registrable, isAdHost, urlFindings, levelFor, cmpVersion: cmp });
  if (typeof module !== 'undefined' && module.exports) module.exports = P;
})(typeof self !== 'undefined' ? self : globalThis);
