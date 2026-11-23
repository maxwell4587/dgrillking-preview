/* Scarlett Preview — service worker (public runtime, deployed as-is).
 *
 * Gate architecture:
 *  - EVERY protected file exists only as ciphertext in p/<n>.enc. This worker
 *    decrypts on demand, using the CryptoKey the login shell posted after a
 *    successful password verification (acknowledged handshake).
 *  - The worker's unlock state IS the browsing session: it lives only in
 *    worker memory. A fresh browser profile, an incognito window, or a
 *    service-worker termination all start locked, so the visitor always
 *    re-encounters the Scarlett login screen. Non-GET or cross-origin
 *    requests are ignored.
 *  - Without an unlocked worker: page navigations redirect to the login
 *    shell, direct asset requests get empty 404s. There is no path by which
 *    a non-authenticated visitor obtains plaintext content.
 *  - The plaintext password is never stored, sent or logged anywhere; the
 *    derived key is a non-extractable CryptoKey held only in worker memory.
 */
'use strict';

const PUBLIC_FILES = new Set([
  'sp-app.js', 'sp-style.css', 'sp-sw.js', 'sp-view.json',
  'sw.js', 'manifest.json', 'scarlett-logo.jpg', '404.html', '.nojekyll',
]);
const STATE = { key: null, tree: null, aadPrefix: null, entries: null };
/** Per-session decrypted-file cache: an aborted lazy-load retry is served
    instantly and never re-hits the network. Cleared whenever state resets. */
const PLAINTEXT_CACHE = new Map();
const CACHE_LIMIT = 64;

const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json', '.webmanifest': 'application/manifest+json',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp',
  '.gif': 'image/gif', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
  '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf', '.txt': 'text/plain',
  '.xml': 'application/xml', '.pdf': 'application/pdf', '.mp4': 'video/mp4',
};

const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', ev => ev.waitUntil(self.clients.claim()));

self.addEventListener('message', ev => {
  const m = ev.data || {};
  const reply = msg => {
    const port = ev.ports && ev.ports[0];
    if (port) port.postMessage(msg);
    else if (ev.source) ev.source.postMessage(msg);
  };
  if (m.type === 'spv-unlock') {
    STATE.key = m.key || null;
    PLAINTEXT_CACHE.clear(); // old session's decrypted bytes must not survive a key change
    reply({ type: 'spv-ack-unlock' });
  } else if (m.type === 'spv-payload') {
    STATE.tree = m.tree || null;
    STATE.aadPrefix = m.aadPrefix || null;
    STATE.entries = m.entries || null;
    reply({ type: 'spv-ack-payload' });
  } else if (m.type === 'spv-lock') {
    STATE.key = null; STATE.tree = null; STATE.aadPrefix = null; STATE.entries = null;
    PLAINTEXT_CACHE.clear();
    reply({ type: 'spv-acked-lock' });
  } else if (m.type === 'spv-ping') {
    // small introspection helper used by local tests; harmless in production
    reply({
      type: 'spv-pong',
      hasKey: !!STATE.key, hasTree: !!STATE.tree,
    });
  }
});

function relPathOf(url) {
  const scope = self.registration.scope;
  if (!url.href.startsWith(scope)) return null;
  const rel = decodeURIComponent(url.href.slice(scope.length)).split('#')[0];
  return rel.replace(/[?#].*$/, '');
}

function isPayloadRequest(rel) { return /^p\/\d+\.enc$/.test(rel); }

/** Session = the worker's own unlock state (worker-memory lifetime).
    No cookie or storage: a terminated or restarted worker locks the gate. */
function isAuthed() {
  return !!(STATE.key && STATE.tree);
}

async function serveEntry(request, rel) {
  const entry = STATE.tree[rel];
  if (typeof entry !== 'number') {
    // Known-content routing only; anything else falls back to network (404).
    if (rel === '' || rel === 'index.html') throw new Error('tree lacks index.html');
    return fetch(request);
  }
  try {
    const cached = PLAINTEXT_CACHE.get(rel);
    if (cached) {
      return cached.response();
    }
    const meta = STATE.entries[entry];
    if (!meta) return new Response(null, { status: 404 });
    const res = await fetch(`p/${entry}.enc`, { cache: 'no-store' });
    if (!res.ok) return new Response(null, { status: 404 });
    const ct = new Uint8Array(await res.arrayBuffer());
    const aad = new TextEncoder().encode(`${STATE.aadPrefix}|${entry}`);
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: unb64(meta.iv), additionalData: aad, tagLength: 128 },
      STATE.key, ct,
    );
    const ext = rel.slice(rel.lastIndexOf('.')).toLowerCase();
    const headers = {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    };
    // Hold the plaintext as its own copy; every Response gets a fresh copy so
    // no consumer can detach shared memory (an ArrayBuffer body is owned
    // by the first Response that consumes it).
    const bytes = new Uint8Array(plain);
    const make = () => new Response(bytes.slice(), { status: 200, headers });
    if (PLAINTEXT_CACHE.size >= CACHE_LIMIT) {
      const oldest = PLAINTEXT_CACHE.keys().next().value;
      PLAINTEXT_CACHE.delete(oldest);
    }
    PLAINTEXT_CACHE.set(rel, { response: make });
    return make();
  } catch (err) {
    // Never reject into respondWith: log server-side and return a stable 502
    // (browsers re-request; the cached plaintext path will serve on retry).
    console.warn('[spv] decrypt/serve failed:', String(err && err.message || err));
    return new Response(null, { status: 502, headers: { 'Cache-Control': 'no-store' } });
  }
}

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin || event.request.method !== 'GET') return;

  const rel = relPathOf(url);
  if (rel === null) return; // outside preview scope

  if (isPayloadRequest(rel)) return; // ciphertext is public by design

  if (rel === 'lock') {
    // explicit session termination: clears worker state and returns to login
    STATE.key = null; STATE.tree = null; STATE.aadPrefix = null; STATE.entries = null;
    PLAINTEXT_CACHE.clear();
    event.respondWith(Response.redirect(new URL('index.html', self.registration.scope).href, 302));
    return;
  }

  if (rel === 'index.html' || rel === '') {
    // The login shell is the public face; once the worker holds a verified
    // unlock, the root serves the client's own encrypted home page instead.
    if (isAuthed()) {
      event.respondWith(serveEntry(event.request, 'index.html'));
    }
    return; // unauthenticated: network passthrough (the shell)
  }

  if (PUBLIC_FILES.has(rel)) return; // public support files

  // Security review M2: uniform behavior for unauthenticated requests so the
  // gate cannot be used to enumerate which site paths exist.
  if (!isAuthed()) {
    if (event.request.mode === 'navigate') {
      event.respondWith(Response.redirect(new URL('index.html', self.registration.scope).href, 302));
    } else {
      event.respondWith(new Response(null, { status: 404, headers: { 'Cache-Control': 'no-store' } }));
    }
    return;
  }

  // Authenticated: decrypt and serve (tree misses fall back to host 404s).
  event.respondWith(serveEntry(event.request, rel));
});
