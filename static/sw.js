// Service worker — ported from gianna's static/sw.js. Cache-busting is
// purely a function of file content: __SW_VERSION__ is templated in by
// http::pages at request time to the daemon's build version, so a new
// release changes this file's bytes, the browser detects the diff and
// installs the new worker, and `activate` below drops every cache key
// that isn't the current one.
const VERSION = '__SW_VERSION__';
const CACHE = `opsclaw-shell-${VERSION}`;
const SHELL = '/app';

const PRECACHE = [
  SHELL,
  '/app/state.js',
  '/app/api.js',
  '/app/auth.js',
  '/app/chat.js',
  '/app/incidents.js',
  '/app/approvals.js',
  '/app/status.js',
  '/app/settings.js',
  '/app/main.js',
  '/static/manifest.json',
  '/static/img/icon.svg',
];

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    for (const url of PRECACHE) {
      try { await cache.add(url); } catch (_) { /* one missing asset must not abort install */ }
    }
  })());
  // Deliberately no skipWaiting() here — a new worker waits until the
  // reload banner (main.js) or a full tab close activates it, so an
  // in-flight session is never yanked out from under the operator.
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter((k) => k.startsWith('opsclaw-shell-') && k !== CACHE).map((k) => caches.delete(k)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/cli/') || url.pathname.startsWith('/webhooks/')) {
    return; // never cache API/webhook responses
  }
  if (req.mode === 'navigate') {
    event.respondWith((async () => {
      try {
        const res = await fetch(req);
        const cache = await caches.open(CACHE);
        cache.put(SHELL, res.clone());
        return res;
      } catch (_) {
        const cached = await caches.match(SHELL);
        return cached || Response.error();
      }
    })());
    return;
  }
  event.respondWith((async () => {
    const cached = await caches.match(req);
    if (cached) return cached;
    try {
      const res = await fetch(req);
      const cache = await caches.open(CACHE);
      cache.put(req, res.clone());
      return res;
    } catch (_) {
      return Response.error();
    }
  })());
});

self.addEventListener('message', (event) => {
  if (event.data === 'skipWaiting') self.skipWaiting();
});

// ---- Web push (TODO: opsclaw#push-task) ----
//
// A SEPARATE later task ports gianna's VAPID subscribe flow and push.rs
// (DESIGN §3: "web push is how incident alerts and approval requests reach
// operators' iOS/Android lock screens"). This handler is deliberately a
// stub — installed and push-capability-ready (the manifest + this
// listener are what iOS requires to treat the installed PWA as
// push-eligible at all), but showing nothing until that task wires
// /api/push/subscribe and the VAPID keypair. See gianna's static/sw.js for
// the reference shape (title/body/icon from the push payload,
// showNotification, notificationclick focuses/opens the app).
self.addEventListener('push', (event) => {
  // TODO(opsclaw#push-task): parse event.data, self.registration.showNotification(...).
});
