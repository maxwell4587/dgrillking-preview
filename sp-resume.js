/* Scarlett Preview — resume step (deployed as sp-resume.js; served by the
   service worker for protected navigations).
   Runs BEFORE authentication, from the resume document. This tab either holds
   a session record (the derived key, kept in sessionStorage: it survives
   reloads and same-tab navigation, is never shared with another tab and dies
   with the tab) or it does not. With a key: the key is re-verified against
   the encrypted routing table (GCM auth), re-armed in an acknowledged
   handshake, and the requested page is decrypted and installed in place, at
   the original URL. Without a key — a new tab, a closed session, or cleared
   site data — the visitor lands on the login shell.
   The plaintext password is never stored, sent or logged anywhere. */

const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const enc = s => new TextEncoder().encode(s);

const isSelfVisit = /\/sp-resume\.(html|js)$/.test(location.pathname);

/** The preview scope root (where sp-sw.js, index.html and manifest.json
    live), derived from the controlling worker's own script URL so nested
    client paths resolve correctly. */
function scopeBase() {
  try {
    const ctrl = navigator.serviceWorker.controller;
    if (ctrl && ctrl.scriptURL) return new URL('.', new URL(ctrl.scriptURL, location.href));
  } catch { /* fall back below */ }
  // Self-visit fallback: sp-resume.* lives at the scope root, so the
  // document's own directory IS the scope root. Every other caller runs only
  // after the controlling worker has been established.
  return new URL('.', location.href);
}

function goShell() {
  location.replace(new URL('index.html?spv-login=1', scopeBase()).href);
}

/** Path relative to the preview scope for the CURRENT document ('' -> the
    encrypted home page's own rel name). */
function currentRel() {
  let rel;
  try {
    const scopePath = scopeBase().pathname;
    rel = decodeURIComponent(location.pathname.slice(scopePath.length));
  } catch {
    return null;
  }
  rel = rel.split('#')[0].replace(/[?#].*$/, '');
  return rel === '' ? 'index.html' : rel;
}

async function awaitAck(controller, ackType, message) {
  await new Promise((resolve, reject) => {
    const ch = new MessageChannel();
    ch.port1.onmessage = e => (e.data && e.data.type === ackType ? resolve() : reject(new Error('handshake mismatch')));
    setTimeout(() => reject(new Error('handshake timeout')), 6000);
    controller.postMessage(message, [ch.port2]);
  });
}

async function main() {
  if (isSelfVisit) return goShell(); // only meaningful when served FOR a site path

  let rawB64 = null;
  let version = null;
  try {
    rawB64 = sessionStorage.getItem('spv-k');
    version = sessionStorage.getItem('spv-v');
  } catch { /* storage unavailable: fall through to the login */ }
  if (!rawB64 || version !== '2') return goShell();

  let manifest = null;
  let key = null;
  let tree = null;
  try {
    const res = await fetch('./manifest.json', { cache: 'no-store' });
    if (!res.ok) throw new Error('manifest unavailable');
    manifest = await res.json();
    key = await crypto.subtle.importKey('raw', unb64(rawB64), 'AES-GCM', false, ['encrypt', 'decrypt']);

    // Re-verify the key against the encrypted routing table: AES-GCM
    // authentication doubles as the password check, so a stale, corrupted or
    // revoked session record fails closed instead of unlocking anything.
    const ct = new Uint8Array(await (await fetch('./p/0.enc', { cache: 'no-store' })).arrayBuffer());
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: unb64(manifest.entries[0].iv), additionalData: enc(`${manifest.aadPrefix}|0`), tagLength: 128 },
      key, ct,
    );
    tree = JSON.parse(new TextDecoder().decode(plain));
  } catch {
    // stale or invalid session record: drop it and require a fresh login
    try {
      sessionStorage.removeItem('spv-k');
      sessionStorage.removeItem('spv-v');
    } catch { /* ignore */ }
    return goShell();
  }

  let controller = navigator.serviceWorker.controller;
  if (!controller) {
    // The worker exists (it served this document) but is momentarily absent:
    // re-register and wait rather than failing the unlock handshake.
    const reg = await navigator.serviceWorker.register('./sp-sw.js', { scope: './' });
    await navigator.serviceWorker.ready;
    controller = reg.active || navigator.serviceWorker.controller;
  }
  if (!controller) return goShell();

  try {
    await awaitAck(controller, 'spv-ack-unlock', { type: 'spv-unlock', key });
    await awaitAck(controller, 'spv-ack-payload', {
      type: 'spv-payload', tree, aadPrefix: manifest.aadPrefix, entries: manifest.entries,
    });
  } catch {
    // worker unreachable or unwilling: fail closed to the login
    return goShell();
  }

  const rel = currentRel();
  const entry = rel === null ? null : tree[rel];
  if (typeof entry !== 'number') {
    // Unknown paths end the same way as any other navigation from here: at
    // the login shell. No route information is observable.
    return goShell();
  }

  try {
    const meta = manifest.entries[entry];
    const ct = new Uint8Array(await (await fetch(`./p/${entry}.enc`, { cache: 'no-store' })).arrayBuffer());
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: unb64(meta.iv), additionalData: enc(`${manifest.aadPrefix}|${entry}`), tagLength: 128 },
      key, ct,
    );
    const html = new TextDecoder().decode(plain);
    const deliver = () => {
      document.open();
      document.write(html);
      document.close();
    };
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', deliver, { once: true });
    } else {
      deliver();
    }
  } catch {
    // In-place delivery failed: end the navigation at the login (fail-safe).
    // The login shell drops this tab's session record, so a retry is a
    // normal re-login.
    return goShell();
  }
}

main();
