'use strict';
const CACHE = 'lockgate-static-v1';
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil((async () => {
  const keys = await caches.keys();
  await Promise.all(keys.filter(key => key.startsWith('lockgate-static-') && key !== CACHE).map(key => caches.delete(key)));
  await self.clients.claim();
})()));
self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== 'GET' || url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/static/')) {
    event.respondWith((async () => {
      const cached = await caches.match(request);
      if (cached) return cached;
      const response = await fetch(request);
      if (response.ok) {
        const cache = await caches.open(CACHE);
        await cache.put(request, response.clone());
      }
      return response;
    })());
    return;
  }
  if (request.mode === 'navigate') {
    event.respondWith(fetch(request).catch(() => new Response(`<!doctype html><html><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#102f2d"><title>LockGate · Offline</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#102f2d;color:#eafff8;font:16px/1.6 system-ui}.card{max-width:360px;padding:32px;text-align:center}b{display:block;font-size:24px;margin-bottom:10px}p{color:#a8c7c1}</style><div class="card"><b>LockGate is offline</b><p>Reconnect to the server to manage or retrieve secrets. Sensitive admin pages are never stored for offline use.</p></div></html>`, {status: 503, headers: {'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store'}})));
  }
});
