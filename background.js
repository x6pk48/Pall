/* Pall service worker: the always-on part. Everything here is local.
   - watches main-frame response headers (read-only) for site-hygiene findings
   - receives page scan results from the content script and keeps per-tab state
   - applies the user's protection settings (blocking rulesets, HTTPS upgrade, own blocklist)
   - audits installed extensions for adware-style risk, and checks selected text for scams
   - fires task reminders */
importScripts('lib/domains.js', 'lib/redact.js', 'lib/heuristics.js');
const P = self.Pall;

const DEFAULTS = {
  gatewayUrl: 'http://127.0.0.1:8787/v1', gatewayToken: '',
  models: { reason: 'nvidia/nemotron-3-super-120b-a12b', fast: 'nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B' },
  blockAds: true, stripParams: true, httpsUpgrade: false, warnBanner: true, autoCloseDangerTabs: false, devMode: false,
  entitiesText: '', trusted: [], blockedDomains: []
};
async function getSettings() { const { settings } = await chrome.storage.local.get('settings'); return { ...DEFAULTS, ...(settings || {}), models: { ...DEFAULTS.models, ...((settings || {}).models || {}) } }; }

// ---------- protections ----------
async function applyProtections() {
  const s = await getSettings();
  const want = { ads: s.blockAds, params: s.stripParams, https: s.httpsUpgrade };
  await chrome.declarativeNetRequest.updateEnabledRulesets({
    enableRulesetIds: Object.keys(want).filter((k) => want[k]),
    disableRulesetIds: Object.keys(want).filter((k) => !want[k])
  });
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const domains = [...new Set(s.blockedDomains || [])].filter((d) => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d));
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: existing.map((r) => r.id),
    addRules: domains.map((d, i) => ({ id: i + 1, priority: 2, action: { type: 'block' }, condition: { requestDomains: [d], resourceTypes: ['sub_frame', 'script', 'image', 'xmlhttprequest', 'ping', 'media', 'font', 'stylesheet', 'websocket', 'other'] } }))
  });
}

// ---------- per-tab state ----------
const key = (id) => 'tab:' + id;
async function getState(tabId) { return (await chrome.storage.session.get(key(tabId)))[key(tabId)] || null; }
async function putState(tabId, st) { await chrome.storage.session.set({ [key(tabId)]: st }); }

function combine(st) {
  const findings = [...((st.page && st.page.result.findings) || []), ...(st.headerFindings || [])];
  const user = findings.filter((f) => f.audience === 'user');
  const score = Math.min(100, user.reduce((a, f) => a + (f.weight ?? 0), 0));
  return { score, level: P.levelFor(score), findings };
}
async function setIcon(tabId, level) {
  const s = level === 'danger' ? 'danger' : level === 'caution' ? 'caution' : 'safe';
  const path = Object.fromEntries([16, 32].map((n) => [n, `icons/${s}-${n}.png`]));
  try { await chrome.action.setIcon({ tabId, path }); await chrome.action.setTitle({ tabId, title: `Pall: ${level === 'safe' ? 'no warning signs' : level}` }); } catch (e) { /* tab gone */ }
}

chrome.webRequest.onHeadersReceived.addListener((d) => {
  if (d.type !== 'main_frame' || d.tabId < 0) return;
  const headerFindings = P.analyzeHeaders(d.url, d.responseHeaders || []);
  putState(d.tabId, { url: d.url, ts: Date.now(), headerFindings, page: null });
  setIcon(d.tabId, 'safe');
}, { urls: ['<all_urls>'], types: ['main_frame'] }, ['responseHeaders', 'extraHeaders']);

chrome.tabs.onRemoved.addListener((id) => chrome.storage.session.remove(key(id)));

// ---------- messages ----------
chrome.runtime.onMessage.addListener((msg, sender, respond) => {
  (async () => {
    if (msg.type === 'pall:page' && sender.tab) {
      const prev = (await getState(sender.tab.id)) || { url: msg.url, headerFindings: [] };
      if (prev.url !== msg.url) { prev.url = msg.url; prev.headerFindings = []; }
      const st = { ...prev, ts: Date.now(), page: { result: msg.result, counts: msg.counts } };
      await putState(sender.tab.id, st);
      const assessment = combine(st);
      await setIcon(sender.tab.id, assessment.level);
      if (assessment.level === 'danger' && (await getSettings()).autoCloseDangerTabs && /^https?:/.test(sender.tab.url || '')) {
        const remaining = await chrome.tabs.query({ windowId: sender.tab.windowId });
        if (remaining.length > 1) {
          await chrome.tabs.remove(sender.tab.id).catch(() => {});
          return { ok: true, closed: true };
        }
      }
      return { ok: true };
    }
    if (msg.type === 'pall:state') {
      const st = await getState(msg.tabId);
      return st ? { ...st, combined: combine(st) } : null;
    }
    if (msg.type === 'pall:check-text') return P.analyzeText(String(msg.text || '').slice(0, 20000));
    if (msg.type === 'pall:audit-extensions') return auditExtensions();
    if (msg.type === 'pall:disable-extension') { await chrome.management.setEnabled(msg.id, false); return { ok: true }; }
    if (msg.type === 'pall:apply') { await applyProtections(); return { ok: true }; }
    if (msg.type === 'pall:blocked-count') {
      try { const r = await chrome.declarativeNetRequest.getMatchedRules({ tabId: msg.tabId }); return { count: r.rulesMatchedInfo.length }; } catch (e) { return { count: null }; }
    }
    return null;
  })().then(respond);
  return true;
});

// ---------- extension audit (adware most often arrives as an extension) ----------
const RISKY = ['cookies', 'webRequest', 'webRequestBlocking', 'history', 'tabs', 'clipboardRead', 'nativeMessaging', 'debugger', 'proxy', 'declarativeNetRequestFeedback', 'management', 'downloads', 'bookmarks'];
async function auditExtensions() {
  const all = await chrome.management.getAll();
  return all.filter((e) => e.type === 'extension' && e.id !== chrome.runtime.id).map((e) => {
    const hosts = e.hostPermissions || [];
    const broad = hosts.some((h) => h === '<all_urls>' || /^\*:\/\/\*\/\*$/.test(h) || /^https?:\/\/\*\/\*$/.test(h));
    const risky = (e.permissions || []).filter((p) => RISKY.includes(p));
    const reasons = [];
    if (broad && risky.length) reasons.push(`Can read every site and also uses ${risky.slice(0, 4).join(', ')}`);
    else if (broad) reasons.push('Can read and change every site you visit');
    if (e.installType === 'sideload' || e.installType === 'other') reasons.push('Installed outside the web store, a common adware route');
    if (e.installType === 'development') reasons.push('Loaded as an unpacked developer extension');
    const risk = (broad && risky.length) || e.installType === 'sideload' || e.installType === 'other' ? 'high' : broad ? 'medium' : 'low';
    return { id: e.id, name: e.name, enabled: e.enabled, version: e.version, installType: e.installType, risk, reasons, mayDisable: e.mayDisable };
  }).sort((a, b) => ({ high: 0, medium: 1, low: 2 }[a.risk] - { high: 0, medium: 1, low: 2 }[b.risk]));
}

// ---------- selected text check ----------
chrome.runtime.onInstalled.addListener(async () => {
  chrome.contextMenus.create({ id: 'pall-check', title: 'Check this with Pall', contexts: ['selection'] });
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});
  chrome.alarms.create('pall-tasks', { periodInMinutes: 1 });
  await applyProtections();
});
chrome.runtime.onStartup.addListener(() => { chrome.alarms.create('pall-tasks', { periodInMinutes: 1 }); applyProtections(); });
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== 'pall-check' || !tab) return;
  const result = P.analyzeText(info.selectionText || '');
  await chrome.storage.session.set({ lastTextCheck: { text: (info.selectionText || '').slice(0, 600), result, ts: Date.now() } });
  try { await chrome.sidePanel.open({ tabId: tab.id }); } catch (e) { /* needs a user gesture; the panel shows it next time */ }
});
chrome.storage.onChanged.addListener((ch, area) => { if (area === 'local' && ch.settings) applyProtections(); });

// ---------- task reminders ----------
chrome.alarms.onAlarm.addListener(async (a) => {
  if (a.name !== 'pall-tasks') return;
  const { db } = await chrome.storage.local.get('db');
  if (!db || !db.tasks) return;
  const now = Date.now();
  let changed = false;
  for (const t of db.tasks) {
    if (!t.done && t.due && !t.notified && new Date(t.due).getTime() <= now) {
      t.notified = true; changed = true;
      chrome.notifications.create('task-' + t.id, { type: 'basic', iconUrl: 'icons/safe-128.png', title: 'Task due', message: t.title });
    }
  }
  if (changed) await chrome.storage.local.set({ db });
});
