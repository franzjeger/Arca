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
let listener = null;
globalThis.chrome = {
  runtime: {
    onMessage: {
      addListener: (fn) => {
        listener = fn;
      },
    },
    getManifest: () => ({ version: "test" }),
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
const send = (msg, tabId = TAB) =>
  new Promise((resolve) => {
    const kept = listener(msg, { tab: { id: tabId } }, resolve);
    assert.equal(kept, true, `${msg.cmd} must keep the response channel open`);
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

const first = await send({ cmd: "consumePending" });
check(
  first.candidate?.password === "s3cret" && !session.has(KEY),
  "consuming returns the candidate and clears the stored copy",
);
check(
  typeof first.candidate.ts === "number",
  "the candidate carries the age it was captured at",
);

// The landing page could not offer it (an interstitial that redirects again),
// so the content script puts it back. The age has to come back with it, or a
// redirect chain would refresh the TTL at every hop and the plaintext password
// would outlive its 90 seconds forever.
await send({ ...candidate, ts: first.candidate.ts });
check(
  session.get(KEY)?.ts === first.candidate.ts,
  "a re-stashed candidate keeps its original timestamp",
);
const second = await send({ cmd: "consumePending" });
check(
  second.candidate?.password === "s3cret",
  "a re-stashed candidate is still offered on the next page",
);

// Same re-stash, but the value is now older than the TTL: it must not come
// back to life.
await send({ ...candidate, ts: Date.now() - 91000 });
const expired = await send({ cmd: "consumePending" });
check(
  expired.candidate === null && !session.has(KEY),
  "a re-stash past the TTL is dropped instead of being revived",
);

// The eviction case. A previous worker generation captured this; the Map in
// THIS one has never seen the tab, exactly as after an eviction.
session.set(`pendingSave:99`, {
  candidate: { url: "https://slow.test/", username: "bob", password: "pw2" },
  ts: Date.now(),
});
const evicted = await send({ cmd: "consumePending" }, 99);
check(
  evicted.candidate?.password === "pw2",
  "a candidate stored before the worker was evicted is still found",
);
check(
  !session.has("pendingSave:99"),
  "and consuming it clears the stored copy too",
);

// A tab with nothing pending must not invent one.
const none = await send({ cmd: "consumePending" }, 1234);
check(none.candidate === null, "an unknown tab has no pending candidate");

console.log(`pending-save ledger: ${checks} checks passed`);
process.exit(0);
