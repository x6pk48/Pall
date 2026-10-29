(async function () {
  'use strict';
  const P = self.Pall;
  const $ = (s, r = document) => r.querySelector(s);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const PH = /\[[A-Z]+(?:_[A-Za-z0-9]+){1,4}\]/g;
  const hl = (t) => esc(t).replace(PH, (m) => `<mark>${m}</mark>`);

  const DEFAULTS = {
    gatewayUrl: 'http://127.0.0.1:8787/v1', gatewayToken: '',
    models: { reason: 'nvidia/nemotron-3-super-120b-a12b', fast: 'nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B' },
    theme: { background: '#F4F3E9', accent: '#087F73' },
    mascot: { species: 'cat', color: '#E8A879' }, mascotPopups: true,
    blockAds: true, stripParams: true, httpsUpgrade: false, warnBanner: true, autoCloseDangerTabs: false, devMode: false,
    entitiesText: '', trusted: [], blockedDomains: []
  };
  const store = { get: async (k) => (await chrome.storage.local.get(k))[k], set: (k, v) => chrome.storage.local.set({ [k]: v }) };
  const getSettings = async () => { const s = (await store.get('settings')) || {}; return { ...DEFAULTS, ...s, models: { ...DEFAULTS.models, ...(s.models || {}) } }; };
  const setSettings = async (fn) => { const s = await getSettings(); fn(s); await store.set('settings', s); return s; };

  const dbh = P.createDB(store);
  await dbh.load();
  const db = dbh.data;
  let settings = await getSettings();
  settings.theme = { ...DEFAULTS.theme, ...(settings.theme || {}) };
  settings.mascot = { ...DEFAULTS.mascot, ...(settings.mascot || {}) };
  const redactor = P.createRedactor({ vault: db.vault, entitiesText: settings.entitiesText, onChange: () => dbh.save() });

  function applyTheme(theme) {
    const root = document.documentElement;
    const luminance = (hex) => {
      const rgb = hex.match(/[0-9a-f]{2}/gi).map((part) => parseInt(part, 16) / 255).map((channel) => channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4);
      return rgb[0] * 0.2126 + rgb[1] * 0.7152 + rgb[2] * 0.0722;
    };
    const ink = luminance(theme.background) > 0.42 ? '#17231F' : '#F6F5EE';
    const accentInk = luminance(theme.accent) > 0.42 ? '#17231F' : '#FFFFFF';
    root.style.setProperty('--bg', theme.background);
    root.style.setProperty('--surface', `color-mix(in srgb, ${theme.background} 93%, white)`);
    root.style.setProperty('--surface-2', `color-mix(in srgb, ${theme.background} 89%, ${ink})`);
    root.style.setProperty('--line', `color-mix(in srgb, ${theme.background} 78%, ${ink})`);
    root.style.setProperty('--ink', ink);
    root.style.setProperty('--muted', `color-mix(in srgb, ${ink} 62%, ${theme.background})`);
    root.style.setProperty('--accent', theme.accent);
    root.style.setProperty('--accent-ink', accentInk);
    root.style.setProperty('--accent-soft', `color-mix(in srgb, ${theme.accent} 17%, ${theme.background})`);
  }
  applyTheme(settings.theme);

  const activeTab = async () => (await chrome.tabs.query({ active: true, lastFocusedWindow: true }))[0];
  const getState = async () => { const t = await activeTab(); return t ? { tab: t, st: await chrome.runtime.sendMessage({ type: 'pall:state', tabId: t.id }) } : { tab: null, st: null }; };

  // ---------- approval gate (policy control for anything that changes protection) ----------
  let pending = null;
  const confirmAsk = (msg) => new Promise((res) => { pending = { msg, res }; if (tab !== 'assistant') setTab('assistant'); else render(); });

  const host = {
    pageText: async () => {
      const t = await activeTab();
      if (!t || !/^https?:/.test(t.url || '')) return { error: 'No readable web page is open in the active tab.' };
      try {
        const [r] = await chrome.scripting.executeScript({ target: { tabId: t.id }, func: () => ({ url: location.href, title: document.title, text: (document.body ? document.body.innerText : '').slice(0, 20000) }) });
        return r.result;
      } catch (e) { return { error: 'Could not read this page: ' + e.message }; }
    },
    pageSecurity: async () => {
      const { st } = await getState();
      if (!st) return { error: 'No scan is available for the active tab.' };
      return { url: st.url, level: st.combined.level, score: st.combined.score, findings: st.combined.findings.map((f) => ({ audience: f.audience, severity: f.severity, title: f.title, detail: f.detail })) };
    },
    updateSettings: async (fn) => { settings = await setSettings(fn); await chrome.runtime.sendMessage({ type: 'pall:apply' }); }
  };
  const agent = P.createAgent({ db, save: dbh.save, redactor, getSettings, host, confirm: confirmAsk });

  // ---------- state ----------
  let tab = 'protect', chat = [], busy = false, textResult = null, audit = null, dismissedCheck = 0, eraseArmed = false;
  let dismissedMascotKey = '';
  let mascotTabId = null;
  const view = $('#view');

  const LEVEL_TXT = { safe: 'No warning signs', caution: 'Be careful', danger: 'Dangerous page' };
  const safePetColor = (value) => /^#[0-9a-f]{6}$/i.test(value || '') ? value : DEFAULTS.mascot.color;
  function mascotSvg(species, level, color) {
    const alert = level === 'danger' ? '#BD473B' : level === 'caution' ? '#BD8124' : '#277D6D';
    const tail = species === 'cat'
      ? `<path class="pet-tail" d="M65 69q18 4 17-11t-8-11" fill="none" stroke="${color}" stroke-width="8" stroke-linecap="round"/>`
      : `<path class="pet-tail" d="M68 69q13-8 9-17" fill="none" stroke="${color}" stroke-width="7" stroke-linecap="round"/>`;
    const ears = species === 'dog'
      ? `<path d="M28 34Q8 31 16 58q4 13 14 4M68 34Q88 31 80 58q-4 13-14 4" fill="${color}" stroke="${alert}" stroke-width="4" stroke-linecap="round"/>`
      : `<path d="m28 39-7-23q17 2 26 15m21 8 7-23q-17 2-26 15" fill="${color}" stroke="${alert}" stroke-width="4" stroke-linejoin="round"/>`;
    const face = level === 'danger'
      ? '<ellipse cx="39" cy="48" rx="4" ry="5"/><ellipse cx="57" cy="48" rx="4" ry="5"/><circle cx="40" cy="49" r="1.3" fill="white"/><circle cx="58" cy="49" r="1.3" fill="white"/><path d="M42 64q6-8 12 0" fill="none" stroke="#17231f" stroke-width="3" stroke-linecap="round"/>'
      : level === 'caution'
        ? '<path d="m34 45 9 2m10 0 9-2" fill="none" stroke="#17231f" stroke-width="3" stroke-linecap="round"/><ellipse cx="39" cy="51" rx="3.5" ry="4"/><ellipse cx="57" cy="51" rx="3.5" ry="4"/><path d="M43 63h10" fill="none" stroke="#17231f" stroke-width="3" stroke-linecap="round"/>'
        : '<ellipse cx="39" cy="48" rx="3.5" ry="4.5"/><ellipse cx="57" cy="48" rx="3.5" ry="4.5"/><path d="M42 60q6 7 12 0" fill="none" stroke="#17231f" stroke-width="3" stroke-linecap="round"/>';
    return `<svg viewBox="0 0 96 96" xmlns="http://www.w3.org/2000/svg"><ellipse cx="48" cy="88" rx="25" ry="4" fill="#17231f" opacity=".12"/>${tail}<g class="pet-head">${ears}<circle cx="48" cy="51" r="31" fill="${color}" stroke="${alert}" stroke-width="4"/><path d="M21 53q3-25 27-27 24 2 27 27-4 21-27 26-23-5-27-26Z" fill="#FFF4E4"/><g fill="#17231f">${face}</g><path d="M46 55q2-3 4 0-2 4-4 0Z" fill="#BD756A"/><circle cx="31" cy="57" r="3" fill="#E99082" opacity=".7"/><circle cx="65" cy="57" r="3" fill="#E99082" opacity=".7"/></g></svg>`;
  }
  async function closeRiskTab(tabId) {
    const id = Number(tabId);
    if (!Number.isInteger(id) || id < 0 || !window.confirm('Close this browser tab?')) return;
    const target = await chrome.tabs.get(id).catch(() => null);
    if (!target || !/^https?:/.test(target.url || '')) return;
    await chrome.tabs.remove(id);
  }
  async function askPallAboutRisk() {
    setTab('assistant');
    send('Explain the current page-safety findings and recommend safe next steps. Use Pall’s local page_security findings.');
  }
  async function updateMascot() {
    if (!settings.mascotPopups) { $('#mascotPopup').hidden = true; return; }
    const { tab: active, st } = await getState();
    const level = st?.combined?.level || 'safe';
    const key = `${active?.id || 'none'}:${st?.url || ''}:${level}`;
    const danger = level === 'danger';
    $('#mascotPopup').dataset.level = level;
    $('#mascotPopup').dataset.key = key;
    $('#mascotPopup').dataset.species = settings.mascot.species;
    $('#mascotPopup').dataset.thinking = String(busy);
    $('#mascotArt').innerHTML = mascotSvg(settings.mascot.species, level, safePetColor(settings.mascot.color));
    $('#mascotTitle').textContent = danger ? 'Pip spotted a risky page' : level === 'caution' ? 'Pip has a small warning' : 'Pip is here';
    $('#mascotMessage').textContent = danger ? 'Pause before sharing details. Review the findings or leave this tab.' : level === 'caution' ? 'Take a moment to check the page details.' : 'Ready to check a page or plan your day?';
    const action = $('#mascotActionButton');
    action.dataset.act = danger ? 'mascot-close-tab' : 'mascot-assistant';
    action.textContent = danger ? 'Close tab' : 'Ask Pall';
    if (busy) {
      $('#mascotTitle').textContent = 'Pip is thinking';
      $('#mascotMessage').textContent = 'Working on your request…';
    }
    mascotTabId = active?.id ?? null;
    $('#mascotPopup').hidden = dismissedMascotKey === key;
  }
  async function refreshPill() {
    const { st } = await getState();
    const pill = $('#verdictPill');
    if (!st) { pill.className = 'pill'; pill.textContent = 'Not scanned'; updateMascot(); return; }
    const lv = st.combined.level;
    pill.className = 'pill ' + lv; pill.textContent = st.page ? LEVEL_TXT[lv] : 'Scanning…';
    updateMascot();
  }

  const findingHtml = (f) => `<div class="f"><div class="h"><span class="sev ${f.severity}">${f.severity}</span><b>${esc(f.title)}</b></div><p>${esc(f.detail)}</p>${
    f.fix && f.fix.snippets ? `<div class="chips" style="margin-top:6px">${Object.entries(f.fix.snippets).map(([k, v]) => `<button class="btn s" data-act="copy" data-text="${esc(v)}">Copy ${esc(k)} fix</button>`).join('')}</div>` : ''}</div>`;

  function textCheckCard(res, snippet) {
    return `<div class="card ${res.level}"><div class="row"><p class="big">${esc(res.verdict)}</p><span class="muted small">score ${res.score}</span></div>${snippet ? `<p class="muted small">“${esc(snippet.slice(0, 160))}${snippet.length > 160 ? '…' : ''}”</p>` : ''}${res.findings.map(findingHtml).join('') || '<p class="muted small">No scam, phishing or spam wording found. That does not prove it is safe.</p>'}</div>`;
  }

  // ---------- views ----------
  async function renderProtect() {
    const { tab: t, st } = await getState();
    let h = '';
    const { lastTextCheck } = await chrome.storage.session.get('lastTextCheck');
    if (lastTextCheck && Date.now() - lastTextCheck.ts < 600000 && dismissedCheck !== lastTextCheck.ts)
      h += `<section><h2>Text you selected</h2>${textCheckCard(lastTextCheck.result, lastTextCheck.text)}<button class="btn s" data-act="dismiss-check" data-ts="${lastTextCheck.ts}" style="margin-top:6px">Dismiss</button></section>`;

    if (!st) {
      h += `<div class="card"><p class="big">Nothing to scan here</p><p class="muted small">Pall scans normal web pages. Browser pages, the Web Store and new tabs can't be inspected, and pages opened before Pall was installed need a reload.</p></div>`;
    } else {
      const c = st.combined, page = st.page;
      const user = c.findings.filter((f) => f.audience === 'user'), dev = c.findings.filter((f) => f.audience === 'dev');
      let host_ = ''; try { host_ = new URL(st.url).hostname; } catch (e) { /* */ }
      h += `<div class="card ${c.level}"><div class="row"><p class="big">${page ? LEVEL_TXT[c.level] : 'Scanning…'}</p><span class="muted small">risk ${c.score}/100</span></div><p class="muted small" style="margin:2px 0 0;overflow-wrap:anywhere">${esc(host_)}</p></div>`;
      if (c.level !== 'safe') {
        const recommendation = c.level === 'danger' ? 'Avoid entering passwords or downloading files from this page.' : 'Check links and requests carefully before sharing information.';
        h += `<section class="safety-recommendation ${c.level}" aria-live="polite"><div class="recommendation-head"><span class="recommendation-dot" aria-hidden="true"></span><b>${c.level === 'danger' ? 'Pip recommends leaving' : 'Pip recommends a closer look'}</b></div><p>${recommendation}</p><div class="chips"><button class="btn p" data-act="recommendation-close" data-tab-id="${t?.id ?? ''}" ${c.level !== 'danger' ? 'disabled' : ''}>Close this tab</button><button class="btn" data-act="recommendation-details">Review findings</button><button class="btn" data-act="recommendation-ask">Ask Pall</button></div></section>`;
      }
      const counts = (page && page.counts) || {};
      const bc = t ? await chrome.runtime.sendMessage({ type: 'pall:blocked-count', tabId: t.id }) : { count: null };
      h += `<div class="stats"><div class="stat"><b>${bc && bc.count != null ? bc.count : '–'}</b><span class="muted small">ads & trackers blocked</span></div><div class="stat"><b>${counts.popup || 0}</b><span class="muted small">pop-ups stopped</span></div><div class="stat"><b>${counts.notification || 0}</b><span class="muted small">prompts denied</span></div></div>`;
      h += `<section id="risk-findings"><h2>Risks to you</h2>${user.length ? user.map(findingHtml).join('') : '<p class="muted small">No scam, phishing, spam or adware signs found on this page. Pall checks locally and can miss things.</p>'}</section>`;
      if (settings.devMode) {
        const fixes = P.buildHeaderFixes(dev);
        h += `<section><h2>For site owners and developers</h2>${dev.length ? dev.map(findingHtml).join('') : '<p class="muted small">No hygiene issues found.</p>'}${fixes ? `<button class="btn p" data-act="copy" data-text="${esc(fixes)}" style="margin-top:8px">Copy all header fixes (nginx)</button>` : ''}<p class="muted small">Passive checks of what your browser already received. Pall never probes or attacks sites.</p></section>`;
      } else if (dev.length) {
        h += `<p class="muted small">${dev.length} site-hygiene finding(s) hidden. Turn on Developer mode in Settings to see headers, outdated libraries and exposed keys.</p>`;
      }
    }
    h += `<section><h2>Check a message</h2><textarea id="txt" placeholder="Paste a suspicious email, text or link here" aria-label="Message to check"></textarea><div class="row" style="margin-top:6px"><span class="muted small">Checked on your device only.</span><button class="btn p" data-act="check-text">Check</button></div>${textResult ? `<div style="margin-top:8px">${textCheckCard(textResult)}</div>` : ''}</section>`;
    h += `<section><h2>Browser extensions</h2><p class="muted small" style="margin:0 0 6px">Adware often arrives as an extension. Pall lists what can read every site you visit.</p><button class="btn" data-act="audit">Audit my extensions</button>${audit ? auditHtml() : ''}</section>`;
    view.innerHTML = h;
  }
  const auditHtml = () => `<div style="margin-top:8px">${audit.map((e) => `<div class="ext"><div style="min-width:0"><b>${esc(e.name)}</b> <span class="sev ${e.risk}">${e.risk}</span><div class="muted small">${esc(e.reasons.join('. ') || 'No broad access.')}${e.enabled ? '' : ' (disabled)'}</div></div>${e.enabled && e.mayDisable && e.risk !== 'low' ? `<button class="btn s d" data-act="disable-ext" data-id="${esc(e.id)}" data-name="${esc(e.name)}">Disable</button>` : ''}</div>`).join('') || '<p class="muted small">No other extensions installed.</p>'}</div>`;

  function renderAssistant() {
    const log = chat.map((m) => m.k === 'u' ? `<div class="m u">${esc(m.t)}</div>` : m.k === 'a' ? `<div class="m a">${esc(m.t)}</div>` : m.k === 'e' ? `<div class="m e">${esc(m.t)}</div>` : `<div class="step"><code>${esc(m.name)}</code> ${esc(m.sum)}</div>`).join('') ||
      `<div class="empty">Ask Pall to manage tasks, summarize the page you're on, draft something, or explain whether a site is safe.</div>`;
    const ask = pending ? `<div class="ask"><b>Approval needed</b><p style="margin:4px 0 8px;white-space:pre-wrap">${esc(pending.msg)}</p><div class="chips"><button class="btn p" data-act="allow">Allow</button><button class="btn" data-act="deny">Deny</button></div></div>` : '';
    view.innerHTML = `<div class="log" id="log">${log}</div>${ask}
      <div class="chips"><button class="btn s" data-act="quick" data-q="Plan my day from my open tasks.">Plan my day</button><button class="btn s" data-act="quick" data-q="Summarize the page I'm on.">Summarize this page</button><button class="btn s" data-act="quick" data-q="Is the page I'm on safe? Explain what Pall found.">Is this page safe?</button><button class="btn s" data-act="newchat">New chat</button></div>
      <form class="composer" id="form"><input type="text" id="in" placeholder="Message Pall" aria-label="Message" autocomplete="off" ${busy ? 'disabled' : ''}><button class="btn p" ${busy ? 'disabled' : ''}>${busy ? '…' : 'Send'}</button></form>`;
    const l = $('#log'); if (l) l.scrollTop = l.scrollHeight;
  }

  function renderTasks() {
    const open = db.tasks.filter((t) => !t.done), done = db.tasks.filter((t) => t.done);
    const row = (t) => { const over = !t.done && t.due && new Date(t.due) < new Date(); return `<div class="task ${t.done ? 'done' : ''}"><input type="checkbox" data-act="toggle" data-id="${t.id}" ${t.done ? 'checked' : ''} aria-label="Done"><div class="grow"><span>${esc(t.title)}</span>${t.due ? `<div class="small ${over ? '' : 'muted'}" style="${over ? 'color:var(--bad)' : ''}">${over ? 'Overdue · ' : 'Due '}${esc(new Date(t.due).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }))}</div>` : ''}</div><button class="btn s d" data-act="del-task" data-id="${t.id}" aria-label="Delete">×</button></div>`; };
    view.innerHTML = `<form id="taskform" class="card"><label class="f2">New task<input type="text" id="ttitle" placeholder="What needs doing?" required></label><label class="f2" style="margin-top:6px">Due (optional, you'll get a reminder)<input type="datetime-local" id="tdue"></label><button class="btn p" style="margin-top:8px">Add task</button></form>
      <section><h2>Open (${open.length})</h2>${open.map(row).join('') || '<p class="muted small">Nothing open. Add one above, or ask the assistant.</p>'}</section>${done.length ? `<section><h2>Done (${done.length})</h2>${done.slice(-5).map(row).join('')}</section>` : ''}`;
  }

  function renderMemory() {
    const mem = db.memory.map((m) => `<div class="f"><div class="row"><span class="sev">${m.kind}</span><button class="btn s d" data-act="forget" data-id="${m.id}">Forget</button></div><p style="color:var(--ink)">${esc(m.text)}</p></div>`).join('') || '<p class="muted small">Nothing yet. Tell the assistant something to remember.</p>';
    const skills = db.skills.map((s) => `<div class="f"><div class="row"><b>${esc(s.name)}</b><span class="muted small">v${s.version} · used ${s.uses}×</span></div><p>${esc(s.description)}</p><details><summary>Steps</summary><pre>${esc(s.body)}</pre></details></div>`).join('');
    const log = db.audit.slice(-15).reverse().map((e) => `<div class="f"><div class="row"><b>${e.tier === 'fast' ? 'Nano' : 'Super'} · ${e.blocked ? '<span style="color:var(--bad)">BLOCKED ' + esc(e.violations.join(', ')) + '</span>' : 'sent'}</b><span class="muted small">${new Date(e.ts).toLocaleTimeString()}</span></div><p>Redacted: ${esc(Object.entries(e.redactions || {}).map(([k, v]) => `${k} ×${v}`).join(', ') || 'none')} · ${e.bytes} B · sha256 ${esc(e.sha)}…</p>${e.payload ? `<details><summary>Exact payload sent</summary><pre>${hl(e.payload.messages.filter((m) => m.role !== 'system').map((m) => `[${m.role}] ${m.content || JSON.stringify(m.tool_calls || '')}`).join('\n'))}</pre></details>` : '<p>No payload kept (it contained plaintext).</p>'}</div>`).join('') || '<p class="muted small">No model calls yet.</p>';
    view.innerHTML = `<section><h2>Memory</h2>${mem}</section><section><h2>Skills</h2>${skills}</section><section><h2>Privacy log</h2><p class="muted small" style="margin:0 0 6px">Every model call, with what was redacted first. Originals are never logged.</p>${log}</section>`;
  }

  function renderSettings() {
    const s = settings;
    const tog = (k, label, hint) => `<label class="t"><input type="checkbox" data-set="${k}" ${s[k] ? 'checked' : ''}><span>${label}<span class="muted small" style="display:block">${hint}</span></span></label>`;
    view.innerHTML = `<section><h2>Look & feel</h2><div class="card theme-card"><div class="theme-controls"><label>Background<input id="theme-bg" type="color" value="${esc(s.theme.background)}"></label><label>Accent<input id="theme-accent" type="color" value="${esc(s.theme.accent)}"></label></div><div class="row"><button class="btn p" data-act="save-theme">Save colours</button><span id="theme-saved" class="muted small" aria-live="polite"></span></div></div></section><section><h2>Protection</h2><div class="card">${tog('blockAds', 'Block ads, trackers and pop-under networks', 'A small starter list; pair with a full blocker for broad coverage.')}${tog('stripParams', 'Strip tracking parameters from links', 'Removes utm_*, fbclid, gclid and similar.')}${tog('httpsUpgrade', 'Upgrade http:// pages to https://', 'Off by default: pages that only support HTTP will fail to load.')}${tog('warnBanner', 'Show a warning banner on dangerous pages', '')}${tog('devMode', 'Developer mode', 'Show header, library and exposed-key checks.')}</div>${(s.blockedDomains || []).length ? `<p class="muted small">Your blocked domains:</p>${s.blockedDomains.map((d) => `<div class="row small"><code>${esc(d)}</code><button class="btn s" data-act="unblock" data-d="${esc(d)}">Remove</button></div>`).join('')}` : ''}${(s.trusted || []).length ? `<p class="muted small">Trusted sites (no banner):</p>${s.trusted.map((d) => `<div class="row small"><code>${esc(d)}</code><button class="btn s" data-act="untrust" data-d="${esc(d)}">Remove</button></div>`).join('')}` : ''}</section>
      <section><h2>Assistant gateway</h2><div class="card"><p class="muted small" style="margin:0 0 8px">Pall never holds a model key. It talks to your own gateway (<code>pall gateway</code>), which holds the Nebius Token Factory key and checks every request again.</p><label class="f2">Gateway URL<input type="text" id="gw" value="${esc(s.gatewayUrl)}"></label><label class="f2" style="margin-top:6px">Gateway access token (optional)<input type="password" id="gt" value="${esc(s.gatewayToken)}" autocomplete="off"></label><label class="f2" style="margin-top:6px">Reasoning model<input type="text" id="mr" value="${esc(s.models.reason)}"></label><label class="f2" style="margin-top:6px">Fast model<input type="text" id="mf" value="${esc(s.models.fast)}"></label><button class="btn p" data-act="save-gw" style="margin-top:8px">Save</button> <span id="saved" class="muted small"></span></div></section>
      <section><h2>Private entities</h2><div class="card"><p class="muted small" style="margin:0 0 6px">Names, places and organisations replaced by placeholders before anything reaches a model. One per line: <code>person: Name | alias</code> (person, org, place, other).</p><textarea id="ents" spellcheck="false">${esc(s.entitiesText)}</textarea><button class="btn p" data-act="save-ents" style="margin-top:8px">Apply</button></div></section>
      <section><h2>Your data</h2><div class="card"><p class="muted small" style="margin:0 0 8px">Everything lives in this browser profile. Nothing is synced or uploaded.</p><div class="chips"><button class="btn" data-act="export">Export</button><button class="btn d" data-act="erase">${eraseArmed ? 'Click again to erase everything' : 'Erase all data'}</button></div></div></section>`;
  }

  async function render() {
    if (tab === 'protect') await renderProtect();
    else if (tab === 'assistant') renderAssistant();
    else if (tab === 'tasks') renderTasks();
    else if (tab === 'memory') renderMemory();
    else renderSettings();
    if (tab === 'settings') appendCompanionSettings();
    refreshPill();
  }

  function appendCompanionSettings() {
    const color = safePetColor(settings.mascot.color);
    view.insertAdjacentHTML('afterbegin', `<section><h2>Your companion</h2><div class="card companion-card"><div class="companion-preview" id="companionPreview">${mascotSvg(settings.mascot.species, 'safe', color)}</div><label class="f2">Pet<select id="pet-species"><option value="cat" ${settings.mascot.species === 'cat' ? 'selected' : ''}>Pip the cat</option><option value="dog" ${settings.mascot.species === 'dog' ? 'selected' : ''}>Pip the dog</option></select></label><div class="theme-controls"><label>Fur colour<input id="pet-color" type="color" value="${color}"></label></div><label class="t"><input type="checkbox" data-set="mascotPopups" ${settings.mascotPopups ? 'checked' : ''}><span>Animated companion pop-ups<span class="muted small" style="display:block">Pip changes expression and alert colour with the page risk.</span></span></label><button class="btn p" data-act="save-mascot">Save companion</button></div></section>`);
    const protection = view.querySelector('section h2')?.parentElement;
    const protectionCard = [...view.querySelectorAll('section')].find((section) => section.querySelector('h2')?.textContent === 'Protection')?.querySelector('.card');
    if (protectionCard) protectionCard.insertAdjacentHTML('beforeend', `<label class="t"><input type="checkbox" data-set="autoCloseDangerTabs" ${settings.autoCloseDangerTabs ? 'checked' : ''}><span>Automatically close dangerous tabs<span class="muted small" style="display:block">Opt in: closes pages scoring 60+ only when another tab remains open. Never closes a whole window.</span></span></label>`);
    if (protection) protection.dataset.companionControls = 'added';
    const species = $('#pet-species'), fur = $('#pet-color'), preview = $('#companionPreview');
    const updatePreview = () => { if (preview) preview.innerHTML = mascotSvg(species.value, 'safe', safePetColor(fur.value)); };
    species.addEventListener('change', updatePreview);
    fur.addEventListener('input', updatePreview);
  }
  function setTab(t) { tab = t; document.querySelectorAll('#tabs button').forEach((b) => b.setAttribute('aria-selected', b.dataset.tab === t)); render(); }

  async function send(text) {
    if (busy || !text.trim()) return;
    busy = true; chat.push({ k: 'u', t: text }); render();
    try { const r = await agent.turn(text, (ev) => { chat.push(ev); if (tab === 'assistant') renderAssistant(); }); chat.push({ k: 'a', t: r.text }); }
    catch (e) { chat.push({ k: 'e', t: e.message }); }
    busy = false; render();
  }

  // ---------- events ----------
  $('#tabs').addEventListener('click', (e) => { const b = e.target.closest('button'); if (b) setTab(b.dataset.tab); });
  view.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (e.target.id === 'form') { const i = $('#in'); const v = i.value; i.value = ''; send(v); }
    if (e.target.id === 'taskform') {
      const title = $('#ttitle').value.trim(); if (!title) return;
      const due = $('#tdue').value ? new Date($('#tdue').value).toISOString() : '';
      db.tasks.push({ id: db.nextTask++, title: redactor.scrub(title), due, done: false, notified: false, created: new Date().toISOString() });
      await dbh.save(); renderTasks();
    }
  });
  view.addEventListener('change', async (e) => {
    const k = e.target.dataset.set;
    if (k) { settings = await setSettings((s) => { s[k] = e.target.checked; }); await chrome.runtime.sendMessage({ type: 'pall:apply' }); render(); }
    if (e.target.dataset.act === 'toggle') { const t = db.tasks.find((x) => x.id === +e.target.dataset.id); if (t) { t.done = e.target.checked; await dbh.save(); renderTasks(); } }
  });
  view.addEventListener('click', async (e) => {
    const b = e.target.closest('[data-act]'); if (!b || b.type === 'checkbox') return;
    const a = b.dataset.act;
    if (a === 'copy') { try { await navigator.clipboard.writeText(b.dataset.text); b.textContent = 'Copied'; } catch (x) { b.textContent = 'Copy failed'; } setTimeout(() => render(), 1200); }
    else if (a === 'dismiss-check') { dismissedCheck = +b.dataset.ts; render(); }
    else if (a === 'check-text') { textResult = await chrome.runtime.sendMessage({ type: 'pall:check-text', text: $('#txt').value }); render(); }
    else if (a === 'audit') { b.textContent = 'Auditing…'; audit = await chrome.runtime.sendMessage({ type: 'pall:audit-extensions' }); render(); }
    else if (a === 'disable-ext') {      // two clicks: the first arms the button, the second disables
      b.textContent = `Disable ${b.dataset.name}?`; b.dataset.act = 'disable-ext-yes';
      setTimeout(() => { if (b.isConnected) { b.textContent = 'Disable'; b.dataset.act = 'disable-ext'; } }, 4000);
    }
    else if (a === 'disable-ext-yes') { await chrome.runtime.sendMessage({ type: 'pall:disable-extension', id: b.dataset.id }); audit = await chrome.runtime.sendMessage({ type: 'pall:audit-extensions' }); render(); }
    else if (a === 'allow' || a === 'deny') { const p = pending; pending = null; if (p) p.res(a === 'allow'); renderAssistant(); }
    else if (a === 'quick') send(b.dataset.q);
    else if (a === 'newchat') {
      b.textContent = 'Saving memory…';
      try { const saved = await agent.endSession(); if (saved.length) chat.push({ k: 's', name: 'memory', sum: `remembered ${saved.length} thing(s)` }); } catch (x) { /* gateway offline: skip */ }
      agent.reset(); chat = []; await dbh.save(); render();
    }
    else if (a === 'del-task') { db.tasks = db.tasks.filter((t) => t.id !== +b.dataset.id); await dbh.save(); renderTasks(); }
    else if (a === 'forget') { db.memory = db.memory.filter((m) => m.id !== +b.dataset.id); await dbh.save(); renderMemory(); }
    else if (a === 'unblock') { settings = await setSettings((s) => { s.blockedDomains = s.blockedDomains.filter((d) => d !== b.dataset.d); }); render(); }
    else if (a === 'untrust') { settings = await setSettings((s) => { s.trusted = s.trusted.filter((d) => d !== b.dataset.d); }); render(); }
    else if (a === 'recommendation-close') await closeRiskTab(b.dataset.tabId);
    else if (a === 'recommendation-details') { setTab('protect'); setTimeout(() => $('#risk-findings')?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 50); }
    else if (a === 'recommendation-ask') await askPallAboutRisk();
    else if (a === 'save-mascot') {
      settings = await setSettings((s) => { s.mascot = { species: $('#pet-species').value === 'dog' ? 'dog' : 'cat', color: safePetColor($('#pet-color').value) }; });
      await render();
    }
    else if (a === 'save-theme') {
      settings = await setSettings((s) => { s.theme = { background: $('#theme-bg').value, accent: $('#theme-accent').value }; });
      applyTheme(settings.theme);
      $('#theme-saved').textContent = 'Colours saved';
    }
    else if (a === 'save-gw') {
      settings = await setSettings((s) => { s.gatewayUrl = $('#gw').value.trim(); s.gatewayToken = $('#gt').value; s.models = { reason: $('#mr').value.trim(), fast: $('#mf').value.trim() }; });
      $('#saved').textContent = 'Saved';
    }
    else if (a === 'save-ents') { settings = await setSettings((s) => { s.entitiesText = $('#ents').value; }); redactor.setEntities(settings.entitiesText); b.textContent = 'Applied'; }
    else if (a === 'export') {
      const url = URL.createObjectURL(new Blob([JSON.stringify({ settings: { ...settings, gatewayToken: '' }, db }, null, 2)], { type: 'application/json' }));
      const l = document.createElement('a'); l.href = url; l.download = 'pall-data.json'; l.click(); setTimeout(() => URL.revokeObjectURL(url), 2000);
    }
    else if (a === 'erase') {
      if (!eraseArmed) { eraseArmed = true; renderSettings(); setTimeout(() => { eraseArmed = false; }, 4000); return; }
      await chrome.storage.local.clear(); location.reload();
    }
  });

  $('#mascotPopup').addEventListener('click', (e) => {
    const action = e.target.closest('[data-act]')?.dataset.act;
    if (action === 'mascot-dismiss') { dismissedMascotKey = $('#mascotPopup').dataset.key; $('#mascotPopup').hidden = true; }
    if (action === 'mascot-assistant') { $('#mascotPopup').hidden = true; setTab('assistant'); }
    if (action === 'mascot-close-tab') closeRiskTab(mascotTabId);
  });

  chrome.tabs.onActivated.addListener(() => { if (tab === 'protect') render(); else refreshPill(); });
  chrome.tabs.onUpdated.addListener((id, info) => { if (info.status === 'complete') { if (tab === 'protect') render(); else refreshPill(); } });
  chrome.storage.session.onChanged.addListener(() => { if (tab === 'protect' && !document.activeElement.matches('textarea,input')) render(); else refreshPill(); });
  chrome.storage.onChanged.addListener((ch, area) => {
    if (area !== 'local' || !ch.db || !ch.db.newValue) return;
    const incoming = ch.db.newValue.tasks || [];      // reminders mark tasks as notified from the service worker
    if (JSON.stringify(incoming) !== JSON.stringify(db.tasks)) { db.tasks = incoming; if (tab === 'tasks') renderTasks(); }
  });

  render();
  setTimeout(updateMascot, 500);
})();
