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
  '/app/format.js',
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

// ---- Web push ----
//
// DESIGN §3/§4: "web push is how incident alerts and approval requests
// reach operators' iOS/Android lock screens". The payload is the small JSON
// object `channels::push::PushChannel::send` builds server-side:
// { title, body, url } — url is where notificationclick below deep-links
// (e.g. "/app#approvals"). Ported in shape from gianna's static/sw.js.
self.addEventListener('push', (event) => {
  let data = { title: 'OpsClaw', body: 'You have a new notification.', url: '/app' };
  if (event.data) {
    try { data = { ...data, ...event.data.json() }; } catch (_) { data.body = event.data.text(); }
  }
  event.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: '/static/img/icon-192.svg',
      badge: '/static/img/icon-192.svg',
      data: { url: data.url || '/app' },
    })
  );
});

// Tapping a notification focuses an already-open client on the target URL if
// one exists, else opens a new one — never stacks a duplicate tab per push.
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = event.notification.data && event.notification.data.url ? event.notification.data.url : '/app';
  event.waitUntil((async () => {
    const clientsList = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of clientsList) {
      if (c.url.includes(new URL(url, self.location.origin).pathname) && 'focus' in c) {
        return c.focus();
      }
    }
    // No matching client yet: focus any open OpsClaw tab and navigate it,
    // or fall back to opening a fresh one.
    for (const c of clientsList) {
      if ('navigate' in c && 'focus' in c) {
        await c.focus();
        return c.navigate(url);
      }
    }
    return self.clients.openWindow(url);
  })());
});
