/* Page scanner (isolated world). Gathers signals from the DOM, runs the local engine, and sends the
   RESULT (findings, never the page text) to the service worker. Page content does not leave the tab. */
(function () {
  'use strict';
  if (window.top !== window || !/^https?:$/.test(location.protocol) || window.__pallScan) return;
  window.__pallScan = true;
  const P = self.Pall;
  const ev = { notification: 0, popup: 0 };
  let libs = [], scans = 0, timer = null, bannerShown = false;

  window.addEventListener('pall:blocked', (e) => { try { const d = JSON.parse(e.detail); ev[d.kind] = (ev[d.kind] || 0) + 1; } catch (x) { /* ignore */ } schedule(800); });
  window.addEventListener('pall:libs', (e) => { try { libs = JSON.parse(e.detail); } catch (x) { /* ignore */ } schedule(200); });

  const abs = (u) => { try { return new URL(u, location.href).href; } catch (e) { return ''; } };
  const hostOf = (u) => { try { return new URL(u, location.href).hostname; } catch (e) { return ''; } };

  function gather() {
    const sig = { url: location.href, hostname: location.hostname, title: document.title || '', events: { ...ev }, libs };
    sig.text = (document.body && document.body.innerText || '').slice(0, 30000);
    sig.forms = [...document.forms].slice(0, 20).map((f) => {
      const inputs = [...f.querySelectorAll('input')];
      return {
        hasPassword: inputs.some((i) => i.type === 'password'),
        hasCard: inputs.some((i) => /^cc-/.test(i.autocomplete || '') || /card.?num|cc.?num|cvv|cvc/i.test((i.name || '') + (i.id || ''))),
        action: f.getAttribute('action') ? abs(f.getAttribute('action')) : ''
      };
    });
    sig.links = [...document.querySelectorAll('a[href]')].slice(0, 300).map((a) => ({ href: a.href, text: (a.textContent || '').trim().slice(0, 120) })).filter((l) => l.text);
    sig.iframes = [...document.querySelectorAll('iframe')].slice(0, 40).map((f) => {
      const r = f.getBoundingClientRect(), cs = getComputedStyle(f);
      return { src: f.src || '', hidden: (r.width <= 2 && r.height <= 2) || cs.display === 'none' || cs.visibility === 'hidden' || cs.opacity === '0' || r.right < 0 || r.bottom < 0 };
    });
    const hosts = new Set();
    document.querySelectorAll('script[src],iframe[src],img[src],link[href]').forEach((n) => { const h = hostOf(n.src || n.href); if (h) hosts.add(h); });
    try { performance.getEntriesByType('resource').forEach((e) => { const h = hostOf(e.name); if (h) hosts.add(h); }); } catch (e) { /* ignore */ }
    sig.resourceHosts = [...hosts];
    sig.inlineScripts = [...document.scripts].filter((s) => !s.src).slice(0, 30).map((s) => (s.textContent || '').slice(0, 20000));
    const mr = document.querySelector('meta[http-equiv="refresh" i]');
    sig.metaRefresh = mr ? mr.getAttribute('content') : '';
    if (location.protocol === 'https:') sig.mixed = [...document.querySelectorAll('script[src],iframe[src],link[rel=stylesheet][href],img[src]')].filter((n) => /^http:/.test(n.src || n.href)).length;
    sig.overlays = countOverlays();
    return sig;
  }

  function countOverlays() {
    let n = 0;
    const vw = innerWidth, vh = innerHeight;
    const els = document.body ? [...document.body.querySelectorAll('div,a,span')].slice(0, 1500) : [];
    for (const el of els) {
      const cs = getComputedStyle(el);
      if ((cs.position !== 'fixed' && cs.position !== 'absolute') || +cs.zIndex < 100) continue;
      const r = el.getBoundingClientRect();
      if (r.width < vw * 0.9 || r.height < vh * 0.9) continue;
      const clear = +cs.opacity < 0.05 || (/rgba\(.*, 0\)|transparent/.test(cs.backgroundColor) && !el.textContent.trim() && !el.querySelector('img,video,canvas,iframe'));
      if (clear && cs.pointerEvents !== 'none') n++;
    }
    return n;
  }

  async function run() {
    scans++;
    const sig = gather();
    const result = P.analyzePage(sig);
    const counts = { notification: ev.notification, popup: ev.popup };
    try { chrome.runtime.sendMessage({ type: 'pall:page', url: location.href, result, counts }); } catch (e) { return; }
    if (result.level === 'danger') maybeBanner(result);
  }
  function schedule(ms) { if (scans >= 6) return; clearTimeout(timer); timer = setTimeout(run, ms); }

  async function maybeBanner(result) {
    if (bannerShown) return;
    let s = {};
    try { s = (await chrome.storage.local.get('settings')).settings || {}; } catch (e) { /* ignore */ }
    if (s.warnBanner === false || (s.trusted || []).includes(location.hostname)) return;
    bannerShown = true;
    const top = result.findings.find((f) => f.audience === 'user');
    const host = document.createElement('div');
    host.setAttribute('data-pall-banner', '');
    const root = host.attachShadow({ mode: 'closed' });
    root.innerHTML = `<style>
      .b{all:initial;position:fixed;inset:0 0 auto 0;z-index:2147483647;background:#8E1B0B;color:#fff;font:14px/1.45 system-ui,sans-serif;padding:12px 16px;display:flex;gap:12px;align-items:center;flex-wrap:wrap;box-shadow:0 2px 12px #0006}
      b{font-weight:600}.t{flex:1;min-width:220px}button{font:inherit;border:1px solid #fff8;background:transparent;color:#fff;border-radius:6px;padding:5px 11px;cursor:pointer}
      button.p{background:#fff;color:#8E1B0B;border-color:#fff;font-weight:600}</style>
      <div class="b" role="alert"><div class="t"><b>Pall warning:</b> this page looks dangerous. <span id="why"></span></div>
      <button class="p" id="leave">Leave this page</button><button id="dismiss">Dismiss</button><button id="trust">Trust this site</button></div>`;
    root.getElementById('why').textContent = top ? top.title + '.' : '';
    root.getElementById('leave').onclick = () => { if (history.length > 1) history.back(); else location.href = 'about:blank'; };
    root.getElementById('dismiss').onclick = () => host.remove();
    root.getElementById('trust').onclick = async () => {
      try { const cur = (await chrome.storage.local.get('settings')).settings || {}; cur.trusted = [...new Set([...(cur.trusted || []), location.hostname])]; await chrome.storage.local.set({ settings: cur }); } catch (e) { /* ignore */ }
      host.remove();
    };
    (document.documentElement || document).appendChild(host);
  }

  const start = () => schedule(1500);
  if (document.readyState === 'complete') start(); else window.addEventListener('load', start);
})();
