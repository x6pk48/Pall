/* Pall redactor (JavaScript port of src/pall/redact.py). No network. The vault is injected so the
   caller decides where it is persisted. Secrets become one-way tokens; PII becomes reversible
   placeholders that only the local vault can restore. */
(function (root) {
  'use strict';
  const P = (root.Pall = root.Pall || {});

  const PH_FULL = /^\[[A-Z]+(?:_[A-Za-z0-9]+){1,4}\]$/;
  const PH_ANY = /\[[A-Z]+(?:_[A-Za-z0-9]+){1,4}\]/g;
  const digits = (s) => s.replace(/\D/g, '');
  const luhn = (s) => {
    const d = digits(s);
    if (d.length < 13 || d.length > 19 || /^(\d)\1+$/.test(d)) return false;
    let t = 0;
    [...d].reverse().forEach((c, i) => { let n = +c; if (i % 2) { n *= 2; if (n > 9) n -= 9; } t += n; });
    return t % 10 === 0;
  };
  const ibanOk = (s) => {
    const c = s.replace(/\s/g, '').toUpperCase();
    if (c.length < 15 || c.length > 34) return false;
    let n = '';
    for (const ch of c.slice(4) + c.slice(0, 4)) n += parseInt(ch, 36);
    try { return BigInt(n) % 97n === 1n; } catch (e) { return false; }
  };
  const ssnOk = (s) => { const [a, g, n] = s.split('-'); return a !== '000' && a !== '666' && !a.startsWith('9') && g !== '00' && n !== '0000'; };
  const phoneOk = (s) => { const d = digits(s); return d.length >= 9 && d.length <= 15 && (s.trim().startsWith('+') || d.length >= 10); };
  const notPh = (v) => !PH_FULL.test(v);
  const credLike = (v) => notPh(v) && (v.length >= 10 || /[\d\W]/.test(v));
  const KV = '(?:api[_ -]?key|secret(?:[_ -]?key)?|access[_ -]?token|auth[_ -]?token|token|passw(?:or)?d|pwd|passcode|pin)';
  const SECRET = 'SECRET';
  const PRIO = { SECRET: 4, PATTERN: 3, ENTITY: 2 };
  const R = (sub, type, src, flags = '', g = 0, ok = null) => ({ sub, type, re: new RegExp(src, flags + 'dg'), g, ok });

  const RULES = [
    R('private_key', SECRET, '-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]+?-----END [A-Z ]*PRIVATE KEY-----'),
    R('aws_access_key', SECRET, '\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b'),
    R('api_key', SECRET, '\\b(?:sk|nvapi|rk|pk)-[A-Za-z0-9_\\-]{16,}'),
    R('github_token', SECRET, '\\bgh[pousr]_[A-Za-z0-9]{30,}\\b'),
    R('slack_token', SECRET, '\\bxox[abprs]-[A-Za-z0-9-]{10,}'),
    R('jwt', SECRET, '\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}'),
    R('bearer_token', SECRET, '\\b[Bb]earer\\s+([A-Za-z0-9._~+/=-]{20,})', '', 1),
    R('credential', SECRET, `\\b${KV}\\b["']?\\s*[:=]\\s*["']?([^\\s"',;]{3,}[^\\s"',;.])`, 'i', 1, notPh),
    R('credential', SECRET, `\\b${KV}\\s+is\\s+["']?([^\\s"',;]{4,}[^\\s"',;.])`, 'i', 1, credLike),
    R('credit_card', SECRET, '(?<![\\d-])(?:\\d[ -]?){12,18}\\d(?![\\d-])', '', 0, luhn),
    R('iban', SECRET, '\\b[A-Z]{2}\\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\\b', '', 0, ibanOk),
    R('sort_code', SECRET, '\\bsort[ -]?code\\W{0,3}(\\d{2}[- ]?\\d{2}[- ]?\\d{2})\\b', 'i', 1),
    R('account_number', SECRET, '\\b(?:account|acct|a/c)(?:\\s*(?:no\\.?|number|num|#))?\\s*[:#]?\\s*(\\d{6,12})\\b', 'i', 1),
    R('routing_number', SECRET, '\\brouting(?:\\s*(?:no\\.?|number|#))?\\s*[:#]?\\s*(\\d{9})\\b', 'i', 1),
    R('us_ssn', SECRET, '\\b\\d{3}-\\d{2}-\\d{4}\\b', '', 0, ssnOk),
    R('uk_ni_number', SECRET, '\\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\\s?\\d{2}\\s?\\d{2}\\s?\\d{2}\\s?[A-D]\\b'),
    R('email', 'EMAIL', '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,}\\b'),
    R('phone', 'PHONE', '(?<!\\w)\\+?\\d[\\d\\s().-]{7,}\\d(?!\\w)', '', 0, phoneOk),
    R('ipv4', 'IP', '\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b')
  ];
  const TYPES = { person: 'PERSON', org: 'ORG', place: 'PLACE', other: 'ENTITY' };
  const fnv = (s) => { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return (h >>> 0).toString(16).padStart(8, '0'); };
  const randHex = (n) => [...root.crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, '0')).join('');

  function createRedactor(opts = {}) {
    const vault = opts.vault || { salt: randHex(4), entries: [] };
    if (!vault.salt) vault.salt = randHex(4);
    if (!vault.entries) vault.entries = [];
    let entMap = {}, entRe = null, tally = {};
    const onChange = opts.onChange || (() => {});

    function setEntities(text) {
      entMap = {};
      String(text || '').split('\n').forEach((l) => {
        const m = l.match(/^\s*[-*]?\s*(person|org|place|other)\s*:\s*(.+?)\s*$/i);
        if (!m) return;
        const names = m[2].split('|').map((s) => s.trim()).filter(Boolean);
        names.forEach((n) => { entMap[n.toLowerCase()] = { type: TYPES[m[1].toLowerCase()], canon: names[0] }; });
      });
      const alts = Object.keys(entMap).sort((a, b) => b.length - a.length).map((a) => a.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
      entRe = alts.length ? new RegExp('(?<!\\w)(?:' + alts.join('|') + ')(?!\\w)', 'gi') : null;
    }
    const normOf = (t, x) => (t === 'PHONE' ? (x.trim().startsWith('+') ? '+' : '') + digits(x) : x.trim().toLowerCase());
    function phFor(type, orig) {
      const norm = normOf(type, orig);
      let e = vault.entries.find((v) => v.type === type && v.norm === norm);
      if (e) return e.ph;
      const n = vault.entries.filter((v) => v.type === type).length + 1;
      e = { ph: `[${type}_${n}]`, type, norm, original: orig.trim() };
      vault.entries.push(e);
      onChange(vault);
      return e.ph;
    }
    function findSpans(text) {
      const sp = [];
      for (const r of RULES) {
        r.re.lastIndex = 0;
        for (const m of text.matchAll(r.re)) {
          const ix = m.indices[r.g];
          if (!ix) continue;
          const seg = text.slice(ix[0], ix[1]);
          if (r.ok && !r.ok(seg)) continue;
          sp.push({ s: ix[0], e: ix[1], type: r.type, sub: r.sub, text: seg, prio: r.type === SECRET ? PRIO.SECRET : PRIO.PATTERN });
        }
      }
      if (entRe) {
        entRe.lastIndex = 0;
        for (const m of text.matchAll(entRe)) {
          const en = entMap[m[0].toLowerCase()];
          sp.push({ s: m.index, e: m.index + m[0].length, type: en.type, sub: en.canon, text: m[0], prio: PRIO.ENTITY });
        }
      }
      const chosen = [];
      sp.sort((a, b) => b.prio - a.prio || (b.e - b.s) - (a.e - a.s) || a.s - b.s)
        .forEach((x) => { if (chosen.every((c) => x.e <= c.s || x.s >= c.e)) chosen.push(x); });
      return chosen.sort((a, b) => a.s - b.s);
    }
    const tag = (t) => fnv(vault.salt + t).slice(0, 6);
    const label = (x) => (x.type === SECRET ? `SECRET/${x.sub}` : x.type);
    function redact(text) {
      if (!text) return { text: text || '', n: 0 };
      let out = '', last = 0, n = 0;
      for (const x of findSpans(text)) {
        const ph = x.type === SECRET ? `[SECRET_${x.sub}_${tag(x.text)}]` : phFor(x.type, x.prio === PRIO.ENTITY ? x.sub : x.text);
        out += text.slice(last, x.s) + ph; last = x.e; n++;
        tally[label(x)] = (tally[label(x)] || 0) + 1;
      }
      return { text: out + text.slice(last), n };
    }
    const scrub = (text) => {
      let out = '', last = 0;
      for (const x of findSpans(text)) { if (x.type !== SECRET) continue; out += text.slice(last, x.s) + `[SECRET_${x.sub}_${tag(x.text)}]`; last = x.e; }
      return out + text.slice(last);
    };
    const verify = (text) => findSpans(text).map(label);
    const rehydrate = (t) => String(t).replace(PH_ANY, (m) => { const e = vault.entries.find((v) => v.ph === m); return e ? e.original : m; });
    const rehydrateObj = (o) => (typeof o === 'string' ? rehydrate(o) : Array.isArray(o) ? o.map(rehydrateObj)
      : o && typeof o === 'object' ? Object.fromEntries(Object.entries(o).map(([k, v]) => [k, rehydrateObj(v)])) : o);
    const drain = () => { const t = tally; tally = {}; return t; };
    setEntities(opts.entitiesText);
    return { redact, scrub, verify, rehydrate, rehydrateObj, drain, setEntities, findSpans, vault };
  }

  // High-confidence key patterns only, for scanning page source. Never returns the secret itself.
  const HIGH_CONF = new Set(['aws_access_key', 'api_key', 'github_token', 'slack_token', 'private_key']);
  function scanSecrets(text) {
    const found = [];
    for (const r of RULES) {
      if (r.type !== SECRET || !HIGH_CONF.has(r.sub)) continue;
      r.re.lastIndex = 0;
      for (const m of String(text).matchAll(r.re)) found.push({ kind: r.sub, tag: fnv(m[0]).slice(0, 6), length: m[0].length });
    }
    return found;
  }

  P.createRedactor = createRedactor;
  P.scanSecrets = scanSecrets;
  if (typeof module !== 'undefined' && module.exports) module.exports = P;
})(typeof self !== 'undefined' ? self : globalThis);
