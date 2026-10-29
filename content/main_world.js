/* Runs inside the page's own JavaScript world, before page scripts. Two jobs:
   1. Deny notification prompts and pop-ups the page opens WITHOUT a user click (the standard adware
      and push-spam tricks). Prompts that follow a real click are left alone.
   2. Report library versions so the isolated scanner can check them for known vulnerabilities. */
(function () {
  'use strict';
  if (window.__pallMain) return;
  window.__pallMain = true;
  const post = (name, detail) => { try { window.dispatchEvent(new CustomEvent('pall:' + name, { detail: JSON.stringify(detail) })); } catch (e) { /* ignore */ } };
  const active = () => !(navigator.userActivation && !navigator.userActivation.isActive) ? true : false;

  try {
    if (window.Notification && Notification.requestPermission) {
      const orig = Notification.requestPermission.bind(Notification);
      Notification.requestPermission = function (cb) {
        if (!active()) {
          post('blocked', { kind: 'notification' });
          if (typeof cb === 'function') { try { cb('denied'); } catch (e) { /* ignore */ } }
          return Promise.resolve('denied');
        }
        return orig(cb);
      };
    }
    const open = window.open;
    window.open = function (url) {
      if (!active()) { post('blocked', { kind: 'popup', url: String(url || '') }); return null; }
      return open.apply(window, arguments);
    };
  } catch (e) { /* a page that locks these down is not our problem */ }

  const libs = () => {
    const out = [];
    const g = (name, fn) => { try { const v = fn(); if (v) out.push({ name, version: String(v) }); } catch (e) { /* ignore */ } };
    g('jQuery', () => window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery);
    g('lodash', () => window._ && window._.VERSION);
    g('AngularJS', () => window.angular && window.angular.version && window.angular.version.full);
    g('Moment.js', () => window.moment && window.moment.version);
    g('Bootstrap', () => (window.bootstrap && window.bootstrap.Tooltip && window.bootstrap.Tooltip.VERSION) ||
      (window.jQuery && window.jQuery.fn.tooltip && window.jQuery.fn.tooltip.Constructor && window.jQuery.fn.tooltip.Constructor.VERSION));
    g('Vue', () => window.Vue && window.Vue.version);
    return out;
  };
  const report = () => post('libs', libs());
  window.addEventListener('load', () => { setTimeout(report, 500); });
})();
