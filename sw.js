/* Migration stub for pre-1.1 deployments (which registered sw.js).
 * Takes over the old registration, passes every request through to the
 * network, and unregisters itself so sp-sw.js can claim the scope cleanly. */
'use strict';
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', ev => {
  ev.waitUntil((async () => { self.registration.unregister(); await self.clients.claim(); })());
});
