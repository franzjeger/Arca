// Tests for the extension's passkey path. Runs the REAL extension files (the
// service worker, the isolated relay and the main-world shim) in vm contexts
// wired together the way Chromium wires them — no mocks of our own logic, only
// of the browser around it.
//
//     node extension/test/passkey.test.mjs
//
// Two classes of bug live here, both of which shipped once and were invisible
// from inside the extension:
//
//   • the gate. A ceremony that starts on a page the browser has just navigated
//     to (Entra sends you to login.microsoft.com/common/bridge/fido, which fires
//     get() on load) has no gesture in its own document. Getting that wrong
//     hands every such sign-in to the browser.
//   • the credential handed back. A bare object literal passes every field
//     check and still breaks the relying party, because real WebAuthn code
//     calls toJSON() and tests instanceof. The prototypes below are
//     brand-checked exactly like the browser's, so a missed shadow throws here
//     instead of in production.
//
// The fake native host always answers "locked", so an ALLOWED ceremony logs
// `app:locked` — which proves the gate passed *and* the request reached the
// native layer, rather than merely that it was not refused.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import * as bookmarksModule from "../chromium/bookmarks.js";
import * as mirrorModule from "../chromium/mirror.js";
import assert from "node:assert/strict";

const EXT = fileURLToPath(new URL("../chromium/", import.meta.url));
const raw = (f) => readFileSync(EXT + f, "utf8");

// background.js is a MODULE — the manifest says so, and it has to be: a service
// worker forbids dynamic `import()`, so its dependencies can only arrive as
// static imports. This harness runs that file in a vm as a classic script,
// which cannot parse one.
//
// So the imports are stripped here and the real exports are injected into the
// context instead. The alternative was to keep background.js loading its
// modules dynamically to suit this file, and that shipped an extension whose
// bookmark cleanup threw on every single call. The harness bends; the code
// that has to run in a browser does not.
const src = (f) =>
  f === "background.js"
    ? raw(f).replace(/^import\s+\{[^}]*\}\s+from\s+"\.\/[^"]+";$/gm, "")
    : raw(f);

const CLAIMED = "app:locked";

// What the fake native host answers. Defaults to a locked vault; the shape
// tests swap in a real assertion.
let NATIVE_ANSWER = { type: "error", message: "locked" };
let PROVIDER_CONNECTED = true;
let NATIVE_PLATFORM = false;
let APP_LAUNCHABLE = false;
let UNLOCK_HANDLER = () => ({ type: "error", message: "unlock_cancelled" });
const NATIVE_CALLS = [];
// The last ceremony that reached the native host, as the desktop would read it.
let LAST_NATIVE = null;

// Brand-checked stand-ins for the browser's WebAuthn classes: every prototype
// member throws unless the receiver carries the internal brand, exactly like
// the real accessors. A shaped credential that forgot to shadow one of them
// therefore blows up here instead of silently in production.
const BRAND = Symbol("brand");
function makeWebAuthnClasses() {
  const brandCheck = (name) =>
    function () {
      if (!this || !this[BRAND]) {
        throw new TypeError(`Illegal invocation: ${name}`);
      }
      return undefined;
    };
  const define = (ctor, members) => {
    for (const m of members) {
      Object.defineProperty(ctor.prototype, m, {
        get: brandCheck(m),
        configurable: true,
      });
    }
    return ctor;
  };
  const PublicKeyCredential = define(function PublicKeyCredential() {}, [
    "id",
    "rawId",
    "type",
    "response",
    "authenticatorAttachment",
  ]);
  for (const m of ["getClientExtensionResults", "toJSON"]) {
    PublicKeyCredential.prototype[m] = brandCheck(m);
  }
  PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => NATIVE_PLATFORM;
  PublicKeyCredential.getClientCapabilities = async () => ({
    userVerifyingPlatformAuthenticator: NATIVE_PLATFORM, conditionalCreate: false,
    hybridTransport: true,
  });
  const AuthenticatorAssertionResponse = define(
    function AuthenticatorAssertionResponse() {},
    ["clientDataJSON", "authenticatorData", "signature", "userHandle"],
  );
  const AuthenticatorAttestationResponse = define(
    function AuthenticatorAttestationResponse() {},
    ["clientDataJSON", "attestationObject"],
  );
  return {
    PublicKeyCredential,
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
  };
}

// ── Controllable clock, shared by every context ─────────────────────────────
let NOW = 1_000_000;
const advance = (ms) => (NOW += ms);
const fakeDate = () =>
  new Proxy(Date, { get: (t, p) => (p === "now" ? () => NOW : t[p]) });

const tick = () => new Promise((r) => setTimeout(r, 5));

// ── The background service worker ───────────────────────────────────────────
const swListeners = [];
const storage = { local: new Map(), session: new Map() };
const mapArea = (m) => ({
  get: async (k) => (m.has(k) ? { [k]: m.get(k) } : {}),
  set: async (o) => void Object.entries(o).forEach(([k, v]) => m.set(k, v)),
  remove: async (k) => void m.delete(k),
});

// The version the LIVE extension reports. An update replaces the service
// worker, so this is where a new generation appears; the shim already sitting
// in a page learns about it from the gate's answer.
let swVersion = "0.3.0";

const swChrome = {
  runtime: {
    onMessage: { addListener: (fn) => swListeners.push(fn) },
    getManifest: () => ({ version: swVersion }),
    // BOTH call shapes, because the real API has both: a callback, and a
    // promise when none is given. The stub only knew the first, so the error
    // reporter — which uses the promise form — threw inside the harness while
    // being perfectly correct in a browser.
    sendNativeMessage: (_host, _msg, cb) => {
      if (_msg.type === "passkey_get" || _msg.type === "passkey_create") LAST_NATIVE = _msg;
      NATIVE_CALLS.push(_msg.type);
      const answer = _msg.type === 'list_matching_logins'
        ? { type: 'logins', app_connected: PROVIDER_CONNECTED, items: NATIVE_ANSWER.type === 'passkey_assertion' ? [{kind:'passkey'}] : [] }
        : _msg.type === "hello" ? { type: "hello", app_connected: PROVIDER_CONNECTED, app_launchable: APP_LAUNCHABLE }
        : _msg.type === "request_unlock" ? UNLOCK_HANDLER() : NATIVE_ANSWER;
      if (typeof cb === "function") {
        Promise.resolve(answer).then(cb);
        return undefined;
      }
      return Promise.resolve(answer);
    },
    lastError: null,
  },
  storage: { local: mapArea(storage.local), session: mapArea(storage.session) },
  tabs: {
    onRemoved: { addListener: () => {} },
    onCreated: { addListener: (fn) => tabCreatedListeners.push(fn) },
  },
};
/** A click opened a new tab: what chrome.tabs.onCreated delivers for it. */
const tabCreatedListeners = [];
const openTab = (id, openerTabId) => {
  for (const fn of tabCreatedListeners) fn({ id, openerTabId });
};

const swCtx = vm.createContext({
  globalThis: null,
  chrome: swChrome,
  // The symbols background.js would have imported. The REAL ones, so the
  // behaviour under test is the behaviour that ships.
  ...bookmarksModule,
  ...mirrorModule,
  console,
  setTimeout,
  clearTimeout,
  queueMicrotask,
  Date: fakeDate(),
  Map,
});
swCtx.globalThis = swCtx;
// background.js is an ES module (it imports the bookmark reconciler), and
// `vm.runInContext` runs scripts, not modules. The import is stripped and the
// two names it brings in are supplied on the context instead — the same thing
// the harness already does for every browser API. The bookmark logic has its
// own tests in bookmarks.test.mjs; nothing here exercises it.
swCtx.readAll = async () => [];
swCtx.apply = async () => ({ added: 0, removed: 0, refused: null });
vm.runInContext(
  src("background.js").replace(/^import\s[^\n]*\n/m, ""),
  swCtx,
);

/** Deliver a message to the worker the way chrome.runtime.sendMessage does. */
function toWorker(msg, tabId) {
  return new Promise((resolve) => {
    const sender = { tab: { id: tabId } };
    for (const fn of swListeners) {
      let replied = false;
      const sendResponse = (r) => {
        replied = true;
        resolve(r);
      };
      if (fn(msg, sender, sendResponse) === true || replied) return;
    }
    resolve(undefined);
  });
}

// ── One browser document: isolated relay + main-world shim ──────────────────
function makeDocument({ host, tabId, nativeGetError = null }) {
  let relayVersion = "0.3.0";
  const isolated = [];
  const main = [];
  const logs = [];

  const loc = { origin: `https://${host}`, hostname: host };

  // A postMessage is seen by both worlds, each with e.source === its own window.
  const deliver = (data) => {
    for (const { type, fn } of [...isolated])
      if (type === "message") fn({ source: relayWindow, data });
    for (const { type, fn } of [...main])
      if (type === "message") fn({ source: mainWindow, data });
  };
  const post = (data) => queueMicrotask(() => deliver(data));

  const relayWindow = {
    addEventListener: (type, fn) => isolated.push({ type, fn }),
    postMessage: post,
    location: loc,
  };
  const mainWindow = {
    addEventListener: (type, fn) => main.push({ type, fn }),
    postMessage: post,
    location: loc,
  };

  // A live extension context. `id` is what `contextAlive()` reads, and its
  // ABSENCE is the orphan signal, so the harness must model both states or the
  // retirement path is untestable — and, worse, every other test would run
  // against a relay that believes it has been reloaded.
  const relayRuntime = {
    id: "arca-test-extension",
    sendMessage: (m) => toWorker(m, tabId),
    getManifest: () => ({ version: relayVersion }),
  };
  const relayCtx = vm.createContext({
    globalThis: null,
    chrome: { runtime: relayRuntime },
    window: relayWindow,
    location: loc,
    console,
    setTimeout,
    clearTimeout,
    queueMicrotask,
    Date: fakeDate(),
    // The relay builds the signed client data itself.
    TextEncoder,
    btoa,
    crypto: globalThis.crypto,
  });
  relayCtx.globalThis = relayCtx;
  vm.runInContext(src("passkey-relay.js"), relayCtx);

  let realGetCalls = 0;
  let browserAborts = 0;
  let realCreateCalls = 0;
  const navigatorStub = {
    credentials: {
      create: async () => {
        realCreateCalls++;
        return { __real: "create" };
      },
      get: async (opts) => {
        realGetCalls++;
        if (nativeGetError) throw new DOMException('Native passkey unavailable', nativeGetError);
        // A CONDITIONAL request stays pending while the browser offers autofill
        // — it does not resolve until the user picks something, or never. The
        // stub used to return at once, which is a browser that does not exist
        // and which quietly ended the ceremony before anyone could choose.
        if (opts && (opts.mediation === "conditional" || opts.mediation === "silent")) {
          return new Promise((_resolve, reject) => {
            if (opts.signal) {
              opts.signal.addEventListener("abort", () => { browserAborts++; reject(new Error("aborted")); }, {
                once: true,
              });
            }
          });
        }
        return { __real: "get" };
      },
    },
  };

  const webauthn = makeWebAuthnClasses();
  const mainCtx = vm.createContext({
    globalThis: null,
    window: mainWindow,
    navigator: navigatorStub,
    console: { debug: (...a) => logs.push(String(a[0])) },
    setTimeout,
    clearTimeout,
    queueMicrotask,
    Date: fakeDate(),
    Map,
    TextEncoder,
    btoa,
    crypto: globalThis.crypto,
    DOMException,
    Object,
    Uint8Array,
    // Conditional autofill is RACED against the browser, and the loser is
    // aborted — so the shim needs the same abort primitives every browser has.
    // Absent here, the harness modelled a browser that does not exist.
    AbortController,
    AbortSignal,
    Promise,
    ...webauthn,
  });
  mainCtx.globalThis = mainCtx;
  vm.runInContext(src("passkey.js"), mainCtx);

  // Ask the shim to answer the live conditional request with `credentialId`.
  let seq = 0;
  const postUse = (credentialId) =>
    new Promise((resolve) => {
      const id = `use-${seq++}`;
      isolated.push({
        type: "message",
        fn: (e) => {
          const d = e && e.data;
          if (d && d.__sybrPasskey === "use-result" && d.id === id) resolve(!!d.ok);
        },
      });
      post({ __sybrPasskey: "use", id, credentialId: credentialId || null });
    });

  return {
    // `isTrusted: true` is what the BROWSER sets on real input. The relay
    // checks it, so a harness that omits it is not simulating a user — see
    // `fakeGesture` below, which deliberately does omit it.
    gesture: () => {
      for (const { type, fn } of isolated) {
        if (type === "pointerdown") fn({ isTrusted: true });
      }
    },
    /** What a page script can produce: `dispatchEvent` sets isTrusted false. */
    fakeGesture: () => {
      for (const { type, fn } of isolated) {
        if (type === "pointerdown") fn({ isTrusted: false });
      }
    },
    fellBackTo: () => {
      const m = (logs[logs.length - 1] || "").match(/\(([^)]+)\)/);
      return m ? m[1] : null;
    },
    realGetCalls: () => realGetCalls,
    browserAborts: () => browserAborts,
    realCreateCalls: () => realCreateCalls,
    /// The extension was RELOADED: this tab's isolated half is orphaned and its
    /// `runtime.id` is gone, while the page-world shim keeps running.
    orphan: () => {
      relayRuntime.id = undefined;
    },
    /// The extension was UPDATED: the context still works, but the live worker
    /// answering the gate belongs to a newer generation than the shim wrapping
    /// WebAuthn in this page.
    upgrade: (v) => {
      swVersion = v;
      relayVersion = v;
    },
    create: () =>
      mainCtx.navigator.credentials.create({
        publicKey: {
          challenge: new Uint8Array([1, 2, 3]).buffer,
          rp: { id: host, name: host },
          user: { id: new Uint8Array([9]).buffer, name: "frank", displayName: "Frank" },
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        },
      }),
    webauthn,
    lastLog: () => logs[logs.length - 1] || "",
    get: (mediation, { signal, allowCredentials = [] } = {}) =>
      mainCtx.navigator.credentials.get({
        mediation, signal,
        publicKey: { challenge: new Uint8Array([1, 2, 3]).buffer, rpId: host, allowCredentials },
      }),
    // A trusted click on a passkey row in Arca's picker: content.js records the
    // pick with the relay (same isolated world), then asks the shim to answer
    // the live conditional request with it.
    pickPasskey: (credentialId) => {
      relayWindow.__sybrPasskeyPicked(credentialId);
      return postUse(credentialId);
    },
    /// The same request posted by page script: no click on Arca's UI behind it.
    postUse: (credentialId) => postUse(credentialId),
    /// Only the pick, as content.js records it on a trusted click.
    notePick: (credentialId) => relayWindow.__sybrPasskeyPicked(credentialId),
    /// A page script doing by hand what the shim does: ask the gate (for
    /// `gateAs`), then post the ceremony with any payload it likes.
    pageCeremony: (kind, payload, gateAs = kind) =>
      new Promise((resolve) => {
        const gateId = `page-gate-${seq}`;
        const reqId = `page-req-${seq++}`;
        isolated.push({
          type: "message",
          fn: (e) => {
            const d = e && e.data;
            if (!d || d.__sybrPasskey !== "response") return;
            if (d.id === gateId) post({ __sybrPasskey: "request", id: reqId, kind, payload });
            if (d.id === reqId) resolve(d);
          },
        });
        post({
          __sybrPasskey: "request",
          id: gateId,
          kind: "gate",
          payload: { isCreate: gateAs === "create" },
        });
      }),
    /// A page script posting a ceremony STRAIGHT at the relay, skipping the
    /// gate. Any script on the page can do exactly this; nothing about it
    /// requires our shim's cooperation.
    rawCeremony: (kind) =>
      new Promise((resolve) => {
        const id = "raw1";
        isolated.push({
          type: "message",
          fn: (e) => {
            const d = e && e.data;
            if (d && d.__sybrPasskey === "response" && d.id === id) resolve(d);
          },
        });
        post({ __sybrPasskey: "request", id, kind, payload: {} });
      }),
  };
}

// ── Cases ───────────────────────────────────────────────────────────────────
let pass = 0;
const check = (name, got, want) => {
  assert.equal(got, want, `${name}: got ${got}, want ${want}`);
  console.log(`  ok  ${name} → ${got}`);
  pass++;
};

console.log("\nMicrosoft flow: gesture on one origin, ceremony on the next");
{
  const a = makeDocument({ host: "login.microsoftonline.com", tabId: 7 });
  a.gesture();
  await tick();
  advance(1200); // click → server round trip → navigation → load
  const b = makeDocument({ host: "login.microsoft.com", tabId: 7 });
  await b.get();
  check("carried across the navigation", b.fellBackTo(), CLAIMED);
  await b.get();
  check("and is consumed, so a re-fire is not claimed", b.fellBackTo(), "no_gesture");
}

console.log("\nIn-document gesture keeps its old, tighter window");
{
  const d = makeDocument({ host: "example.com", tabId: 8 });
  d.gesture();
  await tick();
  advance(500);
  await d.get();
  check("fresh in-document gesture", d.fellBackTo(), CLAIMED);

  d.gesture();
  await tick();
  advance(4000); // past the 3s in-document window, inside the 10s carry TTL
  await d.get();
  check("stale one is NOT widened to the carry TTL", d.fellBackTo(), "gesture_stale");
}

console.log("\nNo gesture at all");
{
  const d = makeDocument({ host: "nowhere.example", tabId: 9 });
  await d.get();
  check("untouched tab defers to the browser", d.fellBackTo(), "no_gesture");
  check("and the browser really was called", d.realGetCalls(), 1);
}

console.log("\nPer-site policy");
{
  storage.local.set("passkeyPolicy", {
    "github.com": "never",
    "id.example": "always",
  });

  const never = makeDocument({ host: "github.com", tabId: 10 });
  never.gesture();
  await tick();
  await never.get();
  check("never overrides a real gesture", never.fellBackTo(), "site_never");

  const always = makeDocument({ host: "id.example", tabId: 11 });
  await always.get();
  check("always claims with no gesture at all", always.fellBackTo(), CLAIMED);
}

console.log("\nConditional mediation still defers before any round trip");
{
  const d = makeDocument({ host: "example.org", tabId: 12 });
  d.gesture();
  await tick();
  // NOT awaited: a conditional request stays pending while autofill is offered,
  // which is the point. What matters here is that the browser was handed it
  // before any round trip to the app.
  void d.get("conditional");
  await tick();
  check("conditional UI", d.fellBackTo(), "mediation:conditional");
}

console.log("\nPicking a passkey in Arca's own list answers the live request");
{
  const d = makeDocument({ host: "example.org", tabId: 21 });
  NATIVE_ANSWER = {
    type: "passkey_assertion",
    credential_id: [1, 2, 3, 4],
    authenticator_data: Array.from({ length: 37 }, (_, i) => (i === 32 ? 0x05 : i)),
    signature: [9, 9, 9],
    user_handle: [7, 7],
  };
  d.gesture();
  await tick();
  // The page arms conditional autofill; the browser is offered it as before.
  const ceremony = d.get("conditional");
  await tick();
  d.gesture();
  await tick();
  const used = await d.pickPasskey([1, 2, 3, 4]);
  check("the picker's choice was accepted", used, true);
  const credential = await ceremony;
  // The PAGE's promise resolves with our credential — the whole point. Before
  // this, a passkey row could only print a sentence.
  check("the page received a credential", credential.type, "public-key");
  check("browser leg was still offered it", d.realGetCalls() > 0, true);
  check("browser prompt is aborted after Arca answers", d.browserAborts(), 1);
}

console.log("\nConditional passkeys respect account restrictions and cancellation");
{
  const d = makeDocument({ host: "example.org", tabId: 31 });
  const controller = new AbortController();
  const ceremony = d.get("conditional", { signal: controller.signal,
    allowCredentials: [{ type: "public-key", id: new Uint8Array([1,2,3,4]) }] });
  d.gesture();
  check("another account's passkey is refused", await d.pickPasskey([9,9]), false);
  d.gesture();
  check("the requested account still works", await d.pickPasskey([1,2,3,4]), true);
  check("the requested account reaches the page", (await ceremony).id, "AQIDBA");
}
{
  const d = makeDocument({ host: "example.org", tabId: 32 });
  const controller = new AbortController();
  const ceremony = d.get("conditional", { signal: controller.signal }).catch(error => error.name);
  controller.abort();
  check("page cancellation settles the ceremony", await ceremony, "AbortError");
  d.gesture();
  check("cancelled request cannot be used", await d.pickPasskey([1,2,3,4]), false);
}
{
  const d = makeDocument({ host: "example.org", tabId: 33 });
  const old = d.get("conditional").catch(error => error.name);
  const current = d.get("conditional");
  check("replacing the request cancels its old browser prompt", await old, "AbortError");
  d.gesture();
  check("the new request accepts the choice", await d.pickPasskey([1,2,3,4]), true);
  check("the new request receives a credential", (await current).type, "public-key");
}

console.log("\nNative autofill failure leaves Arca available");
{
  const d = makeDocument({ host: "example.org", tabId: 34, nativeGetError: "NotAllowedError" });
  const ceremony = d.get("conditional");
  await tick();
  d.gesture();
  check("Arca can answer after native refusal", await d.pickPasskey([1,2,3,4]), true);
  check("the website receives the passkey instead of an error", (await ceremony).type, "public-key");
}
{
  const d = makeDocument({ host: "example.org", tabId: 35, nativeGetError: "NotSupportedError" });
  const controller = new AbortController();
  const ceremony = d.get("conditional", { signal: controller.signal }).catch(error => error.name);
  await tick();
  controller.abort();
  check("page cancellation still works after native refusal", await ceremony, "AbortError");
  d.gesture();
  check("cancelled fallback cannot sign in", await d.pickPasskey([1,2,3,4]), false);
}

console.log("\nUnavailable providers preserve the site's native failure");
{
  storage.local.set("passkeyPolicy", { "disabled.example": "never" });
  const d = makeDocument({ host: "disabled.example", tabId: 36, nativeGetError: "NotAllowedError" });
  check("site policy never is respected before fallback", await d.get("conditional").catch(error => error.name), "NotAllowedError");
  storage.local.set("passkeyPolicy", {});
}
{
  NATIVE_ANSWER = { type: "error", message: "locked" };
  const d = makeDocument({ host: "empty.example", tabId: 37, nativeGetError: "NotSupportedError" });
  check("no matching key leaves the site free to continue", await d.get("conditional").catch(error => error.name), "NotSupportedError");
}
{
  const d = makeDocument({ host: "invalid.example", tabId: 38, nativeGetError: "SecurityError" });
  check("invalid WebAuthn requests still fail", await d.get("conditional").catch(error => error.name), "SecurityError");
}

console.log("\nA page cannot summon a ceremony by posting the message itself");
{
  const d = makeDocument({ host: "example.org", tabId: 22 });
  // Conditional armed, but the user has touched nothing in this tab.
  d.get("conditional");
  await tick();
  const used = await d.postUse([1, 2, 3, 4]);
  check("refused without a gesture", used, false);
}

// The desktop signs with no prompt of its own when told the user picked the
// account in Arca's picker, and signs whatever client data hash it is given.
// Both have to be the relay's word, never the page's.
const ASSERTION = {
  type: "passkey_assertion",
  credential_id: [1, 2, 3, 4],
  authenticator_data: Array.from({ length: 37 }, (_, i) => (i === 32 ? 0x05 : i)),
  signature: [9, 9, 9],
  user_handle: [7, 7],
};
const sha256 = async (bytes) =>
  Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(bytes))));
const clientData = (bytes) => JSON.parse(new TextDecoder().decode(new Uint8Array(bytes)));

console.log("\nThe page cannot say what was signed, or that the user picked");
{
  NATIVE_ANSWER = ASSERTION;
  const d = makeDocument({ host: "sub.example.org", tabId: 40 });
  d.gesture();
  await tick();
  const forged = await d.pageCeremony("get", {
    challenge: [1, 2, 3],
    rpId: "example.org",
    allowCredentials: [[1, 2, 3, 4]],
    picked: true,
    clientDataHash: [0, 0, 0],
    origin: "https://example.org",
  });
  check("the page's ceremony still reaches the app", forged.ok, true);
  check("without its picked flag", LAST_NATIVE.picked, false);
  check("with the relay's origin, not the page's", LAST_NATIVE.origin, "https://sub.example.org");
  check(
    "signing the relay's client data, not the page's hash",
    LAST_NATIVE.client_data_hash.join(),
    (await sha256(forged.clientDataJSON)).join(),
  );
  const cd = clientData(forged.clientDataJSON);
  check("whose origin is the frame's own", cd.origin, "https://sub.example.org");
  check("whose type is a sign-in", cd.type, "webauthn.get");
  check("and whose challenge is the page's", cd.challenge, "AQID");

  d.gesture();
  await tick();
  const noChallenge = await d.pageCeremony("get", { rpId: "example.org" });
  check("a request without a challenge is refused", noChallenge.error, "bad_request");
}

console.log("\nA pick in Arca's picker is one approval, for one account");
{
  NATIVE_ANSWER = ASSERTION;
  const d = makeDocument({ host: "example.org", tabId: 41 });
  const ceremony = d.get("conditional");
  await tick();
  d.gesture();
  check("picking signs in", await d.pickPasskey([1, 2, 3, 4]), true);
  check("and the desktop is told it was picked", LAST_NATIVE.picked, true);
  check(
    "the page receives the client data that was signed",
    (await sha256((await ceremony).response.clientDataJSON)).join(),
    LAST_NATIVE.client_data_hash.join(),
  );

  d.gesture();
  await tick();
  await d.pageCeremony("get", { challenge: [4], rpId: "example.org", allowCredentials: [[1, 2, 3, 4]] });
  check("the pick is spent by the ceremony it approved", LAST_NATIVE.picked, false);

  d.notePick([1, 2, 3, 4]);
  d.gesture();
  await tick();
  await d.pageCeremony("get", { challenge: [4], rpId: "example.org", allowCredentials: [[9, 9]] });
  check("a pick of one account does not approve another", LAST_NATIVE.picked, false);

  d.notePick([1, 2, 3, 4]);
  d.gesture();
  await tick();
  await d.pageCeremony("get", { challenge: [4], rpId: "example.org", allowCredentials: [] });
  check("nor a request that names no account", LAST_NATIVE.picked, false);

  d.notePick([1, 2, 3, 4]);
  advance(16000);
  d.gesture();
  await tick();
  await d.pageCeremony("get", { challenge: [4], rpId: "example.org", allowCredentials: [[1, 2, 3, 4]] });
  check("and an old pick approves nothing", LAST_NATIVE.picked, false);
  NATIVE_ANSWER = { type: "error", message: "locked" };
}

console.log("\nAn approval for a sign-in does not buy a registration");
{
  // site=always lets a get through the gate with no gesture; a create never.
  storage.local.set("passkeyPolicy", { "always.example": "always" });
  const d = makeDocument({ host: "always.example", tabId: 42 });
  const r = await d.pageCeremony("create", { challenge: [1], rpId: "always.example" }, "get");
  check("a get approval spent on a create is refused", r.error, "no_gate_approval");
  storage.local.set("passkeyPolicy", {});
}

console.log("\nRegistration hands back the relay's client data too");
{
  NATIVE_ANSWER = { type: "passkey_credential", credential_id: [5, 6], attestation_object: [1] };
  const d = makeDocument({ host: "reg.example", tabId: 43 });
  d.gesture();
  await tick();
  const cred = await d.create();
  const cd = clientData(cred.response.clientDataJSON);
  check("of type create", cd.type, "webauthn.create");
  check("for the frame's origin", cd.origin, "https://reg.example");
  check("over the page's challenge", cd.challenge, "AQID");
  NATIVE_ANSWER = { type: "error", message: "locked" };
}

console.log("\nThe credential handed to the relying party");
{
  // A real assertion, sized like the one measured off the live bridge:
  // 16-byte credential id, 37-byte authenticatorData, 72-byte DER signature,
  // 51-byte user handle.
  const bytes = (n, seed) => Array.from({ length: n }, (_, i) => (i * 7 + seed) & 0xff);
  NATIVE_ANSWER = {
    type: "passkey_assertion",
    credential_id: bytes(16, 1),
    authenticator_data: bytes(37, 2),
    signature: [0x30, ...bytes(71, 3)],
    user_handle: bytes(51, 4),
  };

  const d = makeDocument({ host: "login.microsoft.com", tabId: 20 });
  d.gesture();
  await tick();
  const cred = await d.get();

  check("Arca answered (no fallback)", d.fellBackTo(), null);
  check("is a PublicKeyCredential", cred instanceof d.webauthn.PublicKeyCredential, true);
  check(
    "response is an AuthenticatorAssertionResponse",
    cred.response instanceof d.webauthn.AuthenticatorAssertionResponse,
    true,
  );
  check("exposes toJSON()", typeof cred.toJSON, "function");

  // Reading every field must NOT hit the brand-checked prototype accessors.
  for (const f of ["id", "rawId", "type", "response", "authenticatorAttachment"]) {
    assert.doesNotThrow(() => cred[f], `reading cred.${f} hit the prototype`);
  }
  for (const f of ["clientDataJSON", "authenticatorData", "signature", "userHandle"]) {
    assert.doesNotThrow(() => cred.response[f], `reading response.${f} hit the prototype`);
  }
  console.log("  ok  every field reads from our own properties");
  pass++;

  const j = cred.toJSON();
  check("toJSON type", j.type, "public-key");
  check("toJSON id matches", j.id, j.rawId);
  check("toJSON has clientExtensionResults", typeof j.clientExtensionResults, "object");
  for (const f of ["clientDataJSON", "authenticatorData", "signature", "userHandle"]) {
    assert.equal(typeof j.response[f], "string", `toJSON response.${f} is not base64url`);
    assert.ok(!/[+/=]/.test(j.response[f]), `toJSON response.${f} is not URL-safe`);
  }
  console.log("  ok  toJSON response fields are unpadded base64url");
  pass++;
  check("getClientExtensionResults()", JSON.stringify(cred.getClientExtensionResults()), "{}");

  NATIVE_ANSWER = { type: "error", message: "locked" };
}

console.log("\nRegistration: a click here, or a fresh arrival carrying one");
{
  // Two flows pull in opposite directions, and the rule has to serve both.
  //
  // Microsoft: the "add a passkey" click lands on the account page, the browser
  // navigates to login.microsoft.com/…/fido/create, and THAT page fires
  // create() on load. Nobody clicks in it. Refusing the carried gesture handed
  // every one of those to the browser's QR dialog.
  //
  // GitHub: "add a passkey" is re-offered on a timer in a page the user has
  // long since arrived at. Any blanket stand-in for a real click turned every
  // one of those offers into a Touch ID prompt on a machine whose owner had
  // done nothing.
  storage.local.set("passkeyPolicy", { "gh.example": "always" });

  // Microsoft's shape: gesture in the previous document, ceremony fired within
  // moments of the next one loading, untouched.
  const a = makeDocument({ host: "gh.example", tabId: 20 });
  a.gesture();
  await tick();
  advance(1200); // click → server round trip → navigation → load
  const b = makeDocument({ host: "gh.example", tabId: 20 });
  advance(800); // the arrival page fetching its challenge before create()
  await b.create();
  check("a carried gesture registers on a fresh arrival page", b.fellBackTo(), CLAIMED);
  await b.create();
  check("it is spent: a re-fire is not claimed", b.fellBackTo(), "create_needs_local_gesture");

  // GitHub's shape, one: the page has been open a while. The carried gesture is
  // still inside the 10s ledger TTL; the document is past the arrival window.
  const g1 = makeDocument({ host: "gh.example", tabId: 25 });
  g1.gesture();
  await tick();
  advance(1200);
  const g2 = makeDocument({ host: "gh.example", tabId: 25 });
  advance(6000); // 7.2s after the click, 6s into the page — a timer, not a load
  await g2.create();
  check("an old page cannot ride a carried gesture", g2.fellBackTo(), "create_needs_local_gesture");
  check("the browser got the ceremony instead", g2.realCreateCalls(), 1);

  // GitHub's shape, two: the user HAS touched the page, and the in-document
  // window already said no. The ledger must not overrule that.
  const h1 = makeDocument({ host: "gh.example", tabId: 26 });
  h1.gesture();
  await tick();
  advance(1200);
  const h2 = makeDocument({ host: "gh.example", tabId: 26 });
  h2.gesture();
  await tick();
  advance(3500); // past the 3s in-document window, inside the arrival window
  await h2.create();
  check("a touched page is judged on its own gesture", h2.fellBackTo(), "create_needs_local_gesture");

  // A click that OPENS a tab carries into that tab: the ceremony page is new,
  // and from the ledger's view untouched.
  const o = makeDocument({ host: "gh.example", tabId: 27 });
  o.gesture();
  await tick();
  openTab(28, 27);
  await tick();
  advance(1000);
  const n = makeDocument({ host: "gh.example", tabId: 28 });
  await n.create();
  check("a gesture follows the click into the tab it opened", n.fellBackTo(), CLAIMED);
  const n2 = makeDocument({ host: "gh.example", tabId: 27 });
  advance(500);
  await n2.create();
  check("and left the opener, so it cannot be spent twice", n2.fellBackTo(), "create_needs_local_gesture");

  // "always" means "sign me in here", not "register whatever you like here".
  const c = makeDocument({ host: "gh.example", tabId: 21 });
  await c.create();
  check("site=always cannot register either", c.fellBackTo(), "create_needs_local_gesture");

  // ...while a real click in the page still registers normally.
  const d = makeDocument({ host: "gh.example", tabId: 22 });
  d.gesture();
  await tick();
  advance(300);
  await d.create();
  check("a real in-document click still registers", d.fellBackTo(), CLAIMED);

  // And sign-in on that same site is untouched by the create rule.
  const e = makeDocument({ host: "gh.example", tabId: 23 });
  await e.get();
  check("sign-in still honours site=always", e.fellBackTo(), CLAIMED);

  storage.local.set("passkeyPolicy", {});
}

console.log("\nA shim retires itself once the extension moves on without it");
{
  // Reloading or updating the extension does NOT evict code already injected
  // into an open tab. The old shim keeps wrapping WebAuthn with the rules that
  // shipped that day, which is why "close the tab" was the only known cure for
  // a passkey bug that had already been fixed.
  const reloaded = makeDocument({ host: "stale.example", tabId: 24 });
  reloaded.gesture();
  await tick();
  reloaded.orphan(); // the extension was reloaded; runtime.id is gone
  await reloaded.get();
  check("an orphaned tab hands the ceremony back", reloaded.fellBackTo(), "shim_retired");
  check("and the browser really ran it", reloaded.realGetCalls(), 1);

  // Retirement is permanent: no second chance, no waiting on a dead relay.
  reloaded.gesture();
  await tick();
  await reloaded.create();
  check("retirement outlives a fresh gesture", reloaded.fellBackTo(), "shim_retired");
  check("registration went to the browser too", reloaded.realCreateCalls(), 1);

  // The other way it goes stale: the context still answers, but from a newer
  // generation than the code running in this page.
  const updated = makeDocument({ host: "updated.example", tabId: 25 });
  updated.gesture();
  await tick();
  advance(300);
  await updated.get();
  check("a matching version claims normally", updated.fellBackTo(), CLAIMED);

  updated.upgrade("0.4.0");
  updated.gesture();
  await tick();
  advance(300);
  await updated.get();
  check("a newer extension retires the old shim", updated.fellBackTo(), "shim_retired");
}

console.log("\nWhat a service worker is allowed to contain");
{
  // `import() is disallowed on ServiceWorkerGlobalScope by the HTML
  // specification`. This shipped: a dynamic import added to keep THIS harness
  // happy made every bookmark cleanup and every mirror call throw in the real
  // extension, and the only symptom a user saw was a checkbox that would not
  // stay ticked.
  //
  // The harness is what adapts to a module (see `src` above). The worker does
  // not get to.
  assert.ok(
    !/\bawait\s+import\s*\(/.test(raw("background.js")),
    "background.js uses dynamic import(), which a service worker refuses at runtime",
  );
  console.log("  ok  background.js has no dynamic import()");
  pass++;
}

console.log("\nThe gate is enforced, not merely offered");
{
  // Until this was closed, the gate ran only because our own shim chose to ask
  // it. A page could post the ceremony itself and reach the desktop app, which
  // answered the only way it can: by raising a Touch ID prompt at whoever was
  // sitting there.
  const a = makeDocument({ host: "github.com", tabId: 21 });
  const create = await a.rawCeremony("create");
  check("an ungated create is refused", create.error, "no_gate_approval");
  check("and never reaches the app", a.realCreateCalls(), 0);

  const b = makeDocument({ host: "github.com", tabId: 22 });
  const get = await b.rawCeremony("get");
  check("an ungated get too", get.error, "no_gate_approval");
}

console.log("\nA gesture the page made up is not a gesture");
{
  // `dispatchEvent` from page script produces an event the browser marks
  // untrusted. Accepting it would have let a page satisfy the gate's own
  // gesture rule and then pass through it legitimately.
  const a = makeDocument({ host: "github.com", tabId: 23 });
  a.fakeGesture();
  await tick();
  await a.create();
  check(
    "a synthetic click does not open the gate",
    a.fellBackTo(),
    "create_needs_local_gesture",
  );

  const b = makeDocument({ host: "github.com", tabId: 24 });
  b.gesture();
  await tick();
  await b.create();
  check(
    "a real one still does",
    b.fellBackTo() === "create_needs_local_gesture",
    false,
  );
}

{
  NATIVE_ANSWER = { type: "error", message: "account_selection_cancelled" };
  const d = makeDocument({ host: "accounts.google.com", tabId: 90 });
  d.gesture();
  await tick();
  check("cancelled account choice rejects the ceremony", await d.get().catch(error => error.name), "NotAllowedError");
  check("cancelled account choice never falls back to another provider", d.realGetCalls(), 0);
}

console.log(`\n${pass} checks passed\n`);

// Registration capability probes must work before the account has any key.
{
  const doc = makeDocument({ host: "registration.example", tabId: 901 });
  NATIVE_ANSWER = { type: "error", message: "locked" };
  PROVIDER_CONNECTED = true;
  assert.equal(await doc.webauthn.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(), true);
  const caps = await doc.webauthn.PublicKeyCredential.getClientCapabilities();
  assert.equal(caps.userVerifyingPlatformAuthenticator, true);
  assert.equal(caps.conditionalCreate, false);
  assert.equal(caps.hybridTransport, true);
  assert.equal(doc.realCreateCalls(), 0);
  assert.equal(doc.realGetCalls(), 0);
  storage.local.set("passkeyPolicy", { "registration.example": "never" });
  assert.equal(await doc.webauthn.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(), false);
  storage.local.set("passkeyPolicy", {});
  PROVIDER_CONNECTED = false;
  assert.equal(await doc.webauthn.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(), false);
  NATIVE_PLATFORM = true;
  assert.equal(await doc.webauthn.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(), true);
  NATIVE_PLATFORM = false;
  PROVIDER_CONNECTED = true;
  doc.orphan();
  assert.equal(await doc.webauthn.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(), false);
  PROVIDER_CONNECTED = true;
}
console.log("PASS provider capability probes: first key, disconnected, native fallback, orphaned relay, unchanged unrelated capabilities");

// An installed, stopped/locked provider remains discoverable without waking it.
{
  swVersion = "0.3.0";
  PROVIDER_CONNECTED = false;
  APP_LAUNCHABLE = true;
  NATIVE_CALLS.length = 0;
  const doc = makeDocument({ host: "startup.example", tabId: 950 });
  assert.equal(await doc.webauthn.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(), true);
  assert.equal(NATIVE_CALLS.includes("request_unlock"), false);
  await doc.get(); // no trusted gesture: cannot wake Arca
  assert.equal(NATIVE_CALLS.includes("request_unlock"), false);

  UNLOCK_HANDLER = () => { PROVIDER_CONNECTED = true; return { type: "unlock_requested" }; };
  NATIVE_CALLS.length = 0;
  doc.gesture();
  await doc.create();
  assert.equal(NATIVE_CALLS.filter(x => x === "request_unlock").length, 1);
  assert.equal(NATIVE_CALLS.filter(x => x === "passkey_create").length, 1);
  assert.ok(NATIVE_CALLS.indexOf("request_unlock") < NATIVE_CALLS.indexOf("passkey_create"));

  PROVIDER_CONNECTED = false;
  UNLOCK_HANDLER = () => ({ type: "error", message: "unlock_cancelled" });
  NATIVE_CALLS.length = 0;
  const cancelled = makeDocument({ host: "cancel-startup.example", tabId: 951 });
  cancelled.gesture();
  assert.equal(await cancelled.get().catch(e => e.name), "NotAllowedError");
  assert.equal(NATIVE_CALLS.includes("passkey_get"), false);
  assert.equal(cancelled.realGetCalls(), 0);

  // Abort while the native prompt is open: its eventual success cannot sign.
  let releaseUnlock;
  UNLOCK_HANDLER = () => new Promise(resolve => { releaseUnlock = resolve; });
  NATIVE_CALLS.length = 0;
  const aborted = makeDocument({ host: "abort-startup.example", tabId: 952 });
  const controller = new AbortController();
  aborted.gesture();
  const pending = aborted.get(undefined, { signal: controller.signal }).catch(e => e.name);
  await tick();
  assert.equal(typeof releaseUnlock, "function");
  controller.abort();
  assert.equal(await pending, "AbortError");
  PROVIDER_CONNECTED = true;
  releaseUnlock({ type: "unlock_requested" });
  await tick();
  assert.equal(NATIVE_CALLS.includes("passkey_get"), false);
  APP_LAUNCHABLE = false;
}
console.log("PASS startup: passive discovery, gesture gate, one unlock, one ceremony, cancel/abort without signing");
