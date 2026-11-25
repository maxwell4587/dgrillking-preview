/* Scarlett Preview — login application logic (public shell).
   Runs BEFORE authentication on every visit. It never stores the password.
   After a verified unlock it hands the derived key to the service worker for
   this tab and keeps the key bits in this tab's sessionStorage, so a reload
   of the same tab resumes without re-login. Session storage is never shared
   with another tab, is re-verified against the encrypted routing table at
   every resume, and is dropped when the tab closes, when the session ends
   through /lock, when cleared site data removes it, or if it ever fails
   verification. */

const enc = s => new TextEncoder().encode(s);
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const toB64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));

const $ = id => document.getElementById(id);
const form = $('login-form');
const pw = $('password');
const errEl = $('error-msg');
const statusEl = $('status-msg');
const statusText = $('status-text');
const submitBtn = $('submit-btn');
const toggleBtn = $('toggle-visibility');

let manifest = null;

/* The login shell is the unauthenticated face of the preview. Whatever
   session record this tab still carries is dropped here: /lock lands on this
   document, as does any navigation that failed verification, and a deliberate
   login on this screen must never silently inherit an old key. */
function clearSessionRecord() {
  try {
    sessionStorage.removeItem('spv-k');
    sessionStorage.removeItem('spv-v');
  } catch { /* storage unavailable: nothing to clear */ }
}
clearSessionRecord();

function showError(msg) {
  errEl.textContent = msg || 'Incorrect password. Access denied.';
  errEl.hidden = false;
  document.querySelector('.card').classList.remove('shake');
  void document.querySelector('.card').offsetWidth; /* restart animation */
  document.querySelector('.card').classList.add('shake');
}

function setStatus(text) {
  statusText.textContent = text;
  statusEl.hidden = false;
}

function clearStatus() { statusEl.hidden = true; }

async function loadManifest() {
  const res = await fetch('./manifest.json', { cache: 'no-store' });
  if (!res.ok) throw new Error('manifest unavailable');
  return res.json();
}

async function loadShell() {
  const res = await fetch('./sp-view.json', { cache: 'no-store' });
  const shell = await res.json();
  $('client-name').textContent = shell.displayName || shell.client;
  if (shell.status && shell.status !== 'active') {
    form.hidden = true;
    $('blocked-msg').hidden = false;
    throw new Error('preview disabled');
  }
}

async function deriveKey(password, { iterations, salt }) {
  /* Derive the raw 256-bit key and import a non-extractable CryptoKey: the
     key used for crypto cannot be dumped from devtools, while the raw bits
     exist in this tab only long enough to base64-encode them into the tab's
     session record (spv-k), which lets the SAME tab resume after a
     service-worker restart without re-typing anything. */
  const material = await crypto.subtle.importKey('raw', enc(password), 'PBKDF2', false, ['deriveBits']);
  const raw = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: unb64(salt), iterations, hash: 'SHA-256' },
    material, 256,
  );
  const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  return { key, keyB64: toB64(raw) };
}

async function decryptTree(key, manifest) {
  const res = await fetch('./p/0.enc', { cache: 'no-store' });
  if (!res.ok) throw new Error('payload missing');
  const ct = new Uint8Array(await res.arrayBuffer());
  const aad = enc(`${manifest.aadPrefix}|0`);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: unb64(manifest.entries[0].iv), additionalData: aad, tagLength: 128 },
    key, ct,
  );
  return JSON.parse(new TextDecoder().decode(plain));
}

/* Browsing session design: each tab's session is its own sessionStorage
   record (the derived key, tab-scoped) plus a per-tab key binding in the
   service worker. A new tab never sees this tab's record and always shows
   the login; a reload of this tab re-arms the worker transparently. */

async function registerAndHandshake(key, tree, manifest) {
  const reg = await navigator.serviceWorker.register('./sp-sw.js', { scope: './' });
  await navigator.serviceWorker.ready;
  const worker = reg.active || navigator.serviceWorker.controller;
  if (!worker) throw new Error('service worker unavailable');

  /* Deliver the key + routing table and WAIT for both acknowledgements. The
     worker binds the key per tab, and every document of this tab re-binds it
     through the resume step as needed; navigating before the worker confirms
     state would leave the next document hitting an unbound worker. */
  const awaitAck = (ackType, message) => new Promise((resolve, reject) => {
    const ch = new MessageChannel();
    ch.port1.onmessage = e => (e.data && e.data.type === ackType ? resolve() : reject(new Error('handshake mismatch')));
    setTimeout(() => reject(new Error('handshake timeout')), 6000);
    worker.postMessage(message, [ch.port2]);
  });
  await awaitAck('spv-ack-unlock', { type: 'spv-unlock', key });
  await awaitAck('spv-ack-payload', { type: 'spv-payload', tree, aadPrefix: manifest.aadPrefix, entries: manifest.entries });
}

/* Unauthenticated workers always redirect navigations to the plain shell URL
   (no return-to parameter: it would leak which site paths exist). */
function redirectToProtected() {
  location.replace(new URL('index.html', location.href).pathname);
}

form.addEventListener('submit', async ev => {
  ev.preventDefault();
  errEl.hidden = true;
  clearStatus();
  const password = pw.value;
  if (!password) { pw.focus(); return; }

  submitBtn.disabled = true;
  pw.disabled = true;
  try {
    setStatus('Verifying…');
    await loadShell();
    manifest = manifest || await loadManifest();

    setStatus('Deriving key…');
    const { key, keyB64 } = await deriveKey(password, manifest.kdf);

    setStatus('Decrypting preview…');
    const tree = await decryptTree(key, manifest); // GCM auth == password check

    setStatus('Opening preview…');
    await registerAndHandshake(key, tree, manifest);
    /* Write the tab's session record only after the handshake was fully
       acknowledged: from this point a reload of THIS tab resumes without a
       re-login, while a new tab (no session record of its own) always sees
       the login. */
    try {
      sessionStorage.setItem('spv-k', keyB64);
      sessionStorage.setItem('spv-v', '2');
    } catch { /* storage unavailable: this tab simply re-logins after reloads */ }
    redirectToProtected();
  } catch (e) {
    clearStatus();
    if (e && e.message === 'preview disabled') return;
    showError('Incorrect password. Access denied.');
  } finally {
    submitBtn.disabled = false;
    pw.disabled = false;
    pw.value = '';
    pw.focus();
  }
});

toggleBtn.addEventListener('click', () => {
  const showing = pw.type === 'text';
  pw.type = showing ? 'password' : 'text';
  toggleBtn.setAttribute('aria-pressed', String(!showing));
  toggleBtn.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
  toggleBtn.querySelector('.ic-eye').hidden = !showing;
  toggleBtn.querySelector('.ic-eye-off').hidden = showing;
});

loadShell().catch(e => {
  if (e.message === 'preview disabled') return;
  /* manifest/shell unreachable: let the UI stay visible; submit will show error */
});

/* If a live unlocked worker exists on this device (session opened in another
   tab), surface the lock control on the shell. */
if (navigator.serviceWorker && navigator.serviceWorker.controller) {
  const w = navigator.serviceWorker.controller;
  const ch = new MessageChannel();
  ch.port1.onmessage = e => {
    if (e.data && e.data.type === 'spv-pong' && e.data.hasTree) {
      const hint = document.querySelector('.lockhint');
      if (hint) hint.hidden = false;
    }
  };
  w.postMessage({ type: 'spv-ping' }, [ch.port2]);
}
