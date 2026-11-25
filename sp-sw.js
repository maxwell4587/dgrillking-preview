/* Scarlett Preview — service worker (public runtime, deployed as-is).
 *
 * Gate architecture:
 *  - EVERY protected file exists only as ciphertext in p/<n>.enc. This worker
 *    decrypts on demand, using a CryptoKey that an authenticated document
 *    hands over in an acknowledged handshake. The plaintext password is
 *    never stored, sent or logged anywhere.
 *  - Sessions are TAB-SCOPED. Each tab holds its own session record — the
 *    derived key in sessionStorage — which survives reloads and same-tab
 *    navigation, is never shared with another tab, and dies with the tab.
 *    The worker keeps a per-tab binding (client id -> key) only in worker
 *    memory, so a terminated or restarted worker starts unbound and the
 *    next navigation from any tab runs the resume step.
 *  - Every protected navigation, while unbound, is answered with ONE resume
 *    document (sp-resume.html). It re-arms this worker from the tab's key
 *    and installs the requested page in place at the original URL, or — for
 *    a tab with no session record — falls through to the login shell. All
 *    protected paths see identical unauthenticated behavior, so the gate
 *    cannot be used to enumerate which site paths exist.
 *  - A fresh browser profile, an incognito window, a service-worker
 *    termination, /lock or a cleared session record all start (or return
 *    to) locked: wrong or missing credentials can never produce plaintext.
 *  - No plaintext site content is ever stored by this worker; routing
 *    tables live in worker memory only. The per-tab key record in
 *    sessionStorage is dropped by the tab's close, by /lock (through the
 *    login shell) and whenever its key fails verification. No cookies and
 *    no storage other than sessionStorage hold any capability.
 */

'use strict';

const PUBLIC_FILES = new Set([
  'sp-app.js', 'sp-style.css', 'sp-sw.js', 'sp-view.json',
  'sp-resume.html', 'sp-resume.js',
  'sw.js', 'manifest.json', 'scarlett-logo.jpg', '404.html', '.nojekyll',
]);
const STATE = { tree: null, aadPrefix: null, entries: null, buildSig: null };
/** Per-tab unlock bindings (client id -> CryptoKey), set only through the
    acknowledged handshake after the offered key verifies against the
    encrypted routing table. Cleared by spv-lock and lost with this worker. */
const SESSION_KEYS = new Map();
/** Per-session decrypted-file cache: an aborted lazy-load retry is served
    instantly and never re-hits the network. Only ever populated by bytes
    decrypted with a verify-bound key; cleared on lock, on crypto failure
    and on build change. */
const PLAINTEXT_CACHE = new Map();
const CACHE_LIMIT = 64;
/** Public routing-table ciphertext (entry 0) kept for key verification. */
let VERIFY = null;

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

/** Proves the offered CryptoKey decrypts the CURRENT build's routing table
    (AES-GCM auth = the password check, done worker-side). Uses the loaded
    routing state when present, otherwise the public manifest. */
async function keyIsForCurrentBuild(key) {
  let iv = null;
  let aadPrefix = null;
  if (STATE.entries && STATE.aadPrefix) {
    iv = STATE.entries[0].iv;
    aadPrefix = STATE.aadPrefix;
  } else {
    try {
      const res = await fetch(new URL('manifest.json', self.registration.scope), { cache: 'no-store' });
      if (!res.ok) return false;
      const mf = await res.json();
      iv = mf.entries[0].iv;
      aadPrefix = mf.aadPrefix;
    } catch {
      return false;
    }
  }
  try {
    const sig = `${aadPrefix}|${iv}`;
    if (!(VERIFY && VERIFY.sig === sig)) {
      const res = await fetch(new URL('p/0.enc', self.registration.scope), { cache: 'no-store' });
      if (!res.ok) return false;
      VERIFY = { sig, ct: new Uint8Array(await res.arrayBuffer()) };
    }
    const aad = new TextEncoder().encode(`${aadPrefix}|0`);
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: unb64(iv), additionalData: aad, tagLength: 128 }, key, VERIFY.ct,
    );
    return true;
  } catch {
    return false;
  }
}

/** Drops bindings whose client (tab) no longer exists. A binding lives only
    as long as its document is reachable. */
function pruneBindings() {
  self.clients.matchAll({ type: 'window', includeUncontrolled: true })
    .then(cls => {
      const alive = new Set(cls.map(c => c.id));
      for (const id of SESSION_KEYS.keys()) {
        if (!alive.has(id)) SESSION_KEYS.delete(id);
      }
    })
    .catch(() => { /* pruning is best-effort */ });
}

/** Build-identity string of a posted routing state (unique per build: the
    entry-0 IV is random per build). A change invalidates worker caches. */
function buildSigOf(aadPrefix, entries) {
  return `${aadPrefix}|${entries && entries[0] ? entries[0].iv : 'none'}`;
}

self.addEventListener('message', ev => {
  const m = ev.data || {};
  const reply = msg => {
    const port = ev.ports && ev.ports[0];
    if (port) port.postMessage(msg);
    else if (ev.source) ev.source.postMessage(msg);
  };
  if (m.type === 'spv-unlock') {
    if (!(m.key && ev.source && ev.source.id)) { reply({ type: 'spv-nack-unlock' }); return; }
    // Security: bind ONLY a key that verifiably decrypts the current build
    // (an arbitrary or stale key is rejected, and with it any ability to
    // influence the decrypted-content cache).
    keyIsForCurrentBuild(m.key).then(valid => {
      if (!valid) { reply({ type: 'spv-nack-unlock' }); return; }
      if (SESSION_KEYS.size === 0) PLAINTEXT_CACHE.clear(); // worker generation had no sessions
      SESSION_KEYS.set(ev.source.id, m.key);
      reply({ type: 'spv-ack-unlock' });
      pruneBindings();
    });
  } else if (m.type === 'spv-payload') {
    // Accept routing state only from a document whose key was just verified
    // and bound in the immediately preceding handshake step.
    if (!(m.tree && m.aadPrefix && m.entries && ev.source && ev.source.id
          && SESSION_KEYS.has(ev.source.id))) { reply({ type: 'spv-nack-payload' }); return; }
    const sig = buildSigOf(m.aadPrefix, m.entries);
    if (STATE.buildSig !== null && STATE.buildSig !== sig) {
      // a different build took over the scope: old decrypted bytes (and the
      // public routing-table ciphertext used for verification) are revoked
      PLAINTEXT_CACHE.clear();
      VERIFY = null;
    }
    STATE.buildSig = sig;
    STATE.tree = m.tree;
    STATE.aadPrefix = m.aadPrefix;
    STATE.entries = m.entries;
    reply({ type: 'spv-ack-payload' });
    pruneBindings();
  } else if (m.type === 'spv-lock') {
    lockEverything();
    reply({ type: 'spv-acked-lock' });
  } else if (m.type === 'spv-ping') {
    // small introspection helper used by local tests; harmless in production
    reply({
      type: 'spv-pong',
      hasKey: !!(ev.source && ev.source.id && SESSION_KEYS.has(ev.source.id)),
      hasTree: !!(STATE.tree && SESSION_KEYS.size > 0),
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

/** The key bound to the requesting client, if a routing table is loaded. */
function keyFor(cid) {
  return (cid && SESSION_KEYS.get(cid) && STATE.tree) ? SESSION_KEYS.get(cid) : null;
}

async function serveEntry(request, rel, cid) {
  const entry = STATE.tree[rel];
  if (typeof entry !== 'number') {
    // Known-content routing only; anything else falls back to network (404).
    if (rel === '' || rel === 'index.html') throw new Error('tree lacks the home page');
    return fetch(request);
  }
  try {
    // The requesting tab's OWN verified binding comes first: nothing is
    // served from any cache without a bound key in the loop.
    const key = keyFor(cid);
    if (!key) return new Response(null, { status: 404, headers: { 'Cache-Control': 'no-store' } });
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
      key, ct,
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
    // Decryption failure means the bound key no longer matches the payload
    // (a redeploy under a fresh build or a stale tab): drop this tab's
    // binding and its cached plaintext. Non-navigations get a stable 502
    // (browsers re-request and re-resume); navigations fall through to the
    // resume step via the fetch handler's null result.
    console.warn('[spv] decrypt/serve failed:', String(err && err.message || err));
    SESSION_KEYS.delete(cid);
    PLAINTEXT_CACHE.clear();
    return null;
  }
}

/** The single resume answer for every protected navigation while unbound:
    a small pass-through document that continues this tab's session or hands
    the visitor to the login shell. Never reveals whether a path exists. */
function resumeDocument() {
  return fetch(new URL('sp-resume.html', self.registration.scope), { cache: 'no-store' })
    .then(async res => {
      if (!res.ok) throw new Error('resume document unavailable');
      return new Response(await res.arrayBuffer(), {
        status: 200,
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff',
          'Referrer-Policy': 'no-referrer',
        },
      });
    })
    .catch(() => Response.redirect(new URL('index.html?spv-login=1', self.registration.scope).href, 302));
}

function lockEverything() {
  STATE.tree = null; STATE.aadPrefix = null; STATE.entries = null; STATE.buildSig = null;
  SESSION_KEYS.clear();
  PLAINTEXT_CACHE.clear();
}

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin || event.request.method !== 'GET') return;

  const rel = relPathOf(url);
  if (rel === null) return; // outside preview scope

  if (isPayloadRequest(rel)) return; // ciphertext is public by design

  if (rel === 'lock') {
    // explicit session termination: clears every binding and returns to login
    lockEverything();
    event.respondWith(Response.redirect(new URL('index.html?spv-login=1', self.registration.scope).href, 302));
    return;
  }

  if (rel === 'index.html' || rel === '') {
    // The login shell is the public face at the home URL. A ?spv-login=1
    // request is the shell by definition. A bare home navigation is wrapped:
    // a tab with a session record gets its decrypted home page, a fresh tab
    // sees the login. Subresource GETs of this path stay public either way.
    if (url.searchParams.has('spv-login')) return;
    if (event.request.mode !== 'navigate') return;
    event.respondWith(resumeDocument());
    return;
  }

  if (PUBLIC_FILES.has(rel)) return; // public support files

  // Security review M2: uniform behavior for unauthenticated requests so the
  // gate cannot be used to enumerate which site paths exist. Navigations
  // always get the same resume document; direct asset requests get empty 404s.
  if (event.request.mode === 'navigate') {
    event.respondWith(resumeDocument());
    return;
  }

  const cid = event.clientId;
  const key = keyFor(cid);
  if (key) {
    // Authenticated subresource: decrypt with this tab's own key (tree misses
    // fall back to host 404s).
    event.respondWith(serveEntry(event.request, rel, cid).then(
      res => res || new Response(null, { status: 502, headers: { 'Cache-Control': 'no-store' } }),
    ));
  } else {
    event.respondWith(new Response(null, { status: 404, headers: { 'Cache-Control': 'no-store' } }));
  }
});
