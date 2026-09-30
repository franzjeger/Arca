// The background worker's pending-save ledger, driven for real.
//
//     node extension/test/pending-save.test.mjs
//
// This is the half of save-on-submit that has to survive things the content
// script cannot see: an MV3 service worker evicted while the user waits on a
// push approval, and a login that redirects through pages where the prompt
// cannot be shown yet. Both used to end with the password quietly gone, and
// neither is reachable from the browser E2E, which replaces this file with a
// stub. So it runs here, against the real module.
//
// It is also where the ledger's trust rules live: the browser's `sender`, not
// the message, says which page is asking, and the password a login page
// submitted never travels to the page that lands after it.
import assert from "node:assert/strict";

let checks = 0;
const check = (condition, message) => {
  assert.ok(condition, message);
  console.log(`  ok  ${message}`);
  checks++;
};

// A fake `chrome` with only what the worker touches. Everything else is
// reached through optional chaining, so it stays absent and unused.
const session = new Map();
const native = [];
let listener = null;
globalThis.chrome = {
  runtime: {
    onMessage: {
      addListener: (fn) => {
        listener = fn;
      },
    },
    getManifest: () => ({ version: "test" }),
    getURL: (path) => `chrome-extension://arca/${path}`,
    sendNativeMessage: (_host, message, callback) => {
      native.push(message);
      callback({ ok: true, response: { type: "save_decision", action: "new" } });
    },
  },
  storage: {
    local: {
      get: async () => ({}),
      set: async () => {},
      remove: async () => {},
    },
    session: {
      get: async (key) =>
        session.has(key) ? { [key]: session.get(key) } : {},
      set: async (obj) => {
        for (const [k, v] of Object.entries(obj)) session.set(k, v);
      },
      remove: async (key) => {
        session.delete(key);
      },
    },
  },
};

await import("../chromium/background.js");
assert.ok(listener, "background.js registered no message listener");

const TAB = 7;
/** A message from the top-level page at `origin`, as the browser reports it. */
const from = (origin, tabId = TAB) => ({
  tab: { id: tabId },
  frameId: 0,
  origin,
  url: `${origin}/somewhere`,
});
const send = (msg, sender = from("https://example.test")) =>
  new Promise((resolve) => {
    const kept = listener(msg, sender, resolve);
    if (kept !== true) resolve(undefined);
  });

const candidate = {
  cmd: "capturePending",
  url: "https://example.test/login",
  username: "alice",
  password: "s3cret",
};
const KEY = `pendingSave:${TAB}`;

await send(candidate);
check(
  session.get(KEY)?.candidate.password === "s3cret",
  "a captured candidate is mirrored into storage.session, not just a Map",
);
check(
  session.get(KEY)?.origin === "https://example.test",
  "it remembers the page that captured it",
);

const landing = await send({ cmd: "peekPending" }, from("https://www.example.test"));
check(
  landing.candidate?.username === "alice" && typeof landing.candidate.ts === "number",
  "the landing page on the same host learns who and when",
);
check(
  landing.candidate && !("password" in landing.candidate),
  "but never the password, which stays in the worker",
);
check(session.has(KEY), "peeking does not consume: a page that cannot offer leaves it");

const elsewhere = await send({ cmd: "peekPending" }, from("https://evil.test"));
check(elsewhere.candidate === null, "a page on another host is not told about it");

const refusedClaim = await send({ cmd: "claimPending" }, from("https://evil.test"));
check(!refusedClaim.ok, "and cannot claim it");

const claim = await send({ cmd: "claimPending" }, from("https://example.test"));
check(claim.ok, "the page that offers it claims it");
check(
  typeof session.get(KEY)?.claimedAt === "number",
  "claiming starts the bar's own lifetime",
);
const again = await send({ cmd: "peekPending" }, from("https://example.test"));
check(again.candidate === null, "so no later page offers it a second time");

native.length = 0;
await send(
  { cmd: "saveLogin", pending: true, url: "https://example.test/login" },
  from("https://example.test"),
);
check(
  native[0]?.type === "save_login" && native[0].password === "s3cret",
  "a save of the claimed candidate sends the password the worker kept",
);

native.length = 0;
const stolen = await send(
  { cmd: "saveProbe", pending: true, url: "https://example.test/login" },
  from("https://evil.test"),
);
check(
  stolen?.ok === false && native.length === 0,
  "another page cannot probe or save the claimed candidate",
);

await send({ cmd: "clearPending" }, from("https://evil.test"));
check(session.has(KEY), "nor clear it");
await send({ cmd: "clearPending" }, from("https://example.test"));
check(!session.has(KEY), "its own page can");

// A capture must come from the page whose form it read.
await send(candidate, from("https://evil.test"));
check(!session.has(KEY), "a capture naming another page is refused");

// A generated password is offered where sign-up lands, often another host.
await send({ ...candidate, generated: true });
const generated = await send({ cmd: "peekPending" }, from("https://app.other.test"));
check(
  generated.candidate?.generated === true,
  "a generated password may be offered on the host a sign-up lands on",
);

// Past the TTL it is gone, however it is asked for.
session.set("pendingSave:55", {
  candidate: { url: "https://example.test/login", username: "old", password: "pw0" },
  ts: Date.now() - 91000,
  origin: "https://example.test",
});
const expired = await send({ cmd: "peekPending" }, from("https://example.test", 55));
check(
  expired.candidate === null && !session.has("pendingSave:55"),
  "a candidate past the TTL is dropped instead of being revived",
);

// Once a page shows the save bar, the password lives as long as the bar can
// be answered. The 90 seconds used to keep running under it, and an Update
// clicked after them was refused with "origin_mismatch".
const claimedEntry = (claimedAgo) => ({
  candidate: { url: "https://example.test/login", username: "carol", password: "pw3" },
  ts: Date.now() - claimedAgo - 30000,
  origin: "https://example.test",
  claimedBy: "https://example.test",
  claimedAt: Date.now() - claimedAgo,
});
session.set("pendingSave:60", claimedEntry(4 * 60 * 1000));
native.length = 0;
await send(
  { cmd: "saveLogin", pending: true, url: "https://example.test/login" },
  from("https://example.test", 60),
);
check(
  native[0]?.type === "save_login" && native[0].password === "pw3",
  "an Update clicked minutes after the sign-in still saves",
);
session.set("pendingSave:61", claimedEntry(11 * 60 * 1000));
native.length = 0;
const late = await send(
  { cmd: "saveLogin", pending: true, url: "https://example.test/login" },
  from("https://example.test", 61),
);
check(
  late?.ok === false && native.length === 0,
  "but not after the bar's own ten minutes",
);

// The eviction case. A previous worker generation captured this; the Map in
// THIS one has never seen the tab, exactly as after an eviction.
session.set(`pendingSave:99`, {
  candidate: { url: "https://slow.test/", username: "bob", password: "pw2" },
  ts: Date.now(),
  origin: "https://slow.test",
});
const evicted = await send({ cmd: "peekPending" }, from("https://slow.test", 99));
check(
  evicted.candidate?.username === "bob",
  "a candidate stored before the worker was evicted is still found",
);

// A tab with nothing pending must not invent one.
const none = await send({ cmd: "peekPending" }, from("https://example.test", 1234));
check(none.candidate === null, "an unknown tab has no pending candidate");

console.log(`pending-save ledger: ${checks} checks passed`);
process.exit(0);
