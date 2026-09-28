// Which page is asking comes from the browser, not from the message.
//
//     node extension/test/sender.test.mjs
//
// A content script runs in the page's renderer, so a compromised renderer can
// send any message it could. Before this, `msg.url` and `msg.origin` decided
// which site's logins and passkeys a message was answered with, and a content
// script could send the popup's bookmark commands. Driven against the real
// background.js with a fake `chrome`, like pending-save.test.mjs.
import assert from "node:assert/strict";

let checks = 0;
const check = (condition, message) => {
  assert.ok(condition, message);
  console.log(`  ok  ${message}`);
  checks++;
};

const native = [];
let listener = null;
globalThis.chrome = {
  runtime: {
    onMessage: { addListener: (fn) => (listener = fn) },
    getManifest: () => ({ version: "test" }),
    getURL: (path) => `chrome-extension://arca/${path}`,
    sendNativeMessage: (_host, message, callback) => {
      native.push(message);
      callback({ ok: true, response: { type: "logins", items: [] } });
    },
  },
  storage: {
    local: { get: async () => ({}), set: async () => {}, remove: async () => {} },
    session: { get: async () => ({}), set: async () => {}, remove: async () => {} },
  },
  bookmarks: {
    getTree: async () => [{ id: "0", children: [] }],
    search: async () => [],
  },
};

await import("../chromium/background.js");

const page = (origin, frameId = 0) => ({
  tab: { id: 3 },
  frameId,
  origin,
  url: `${origin}/login`,
});
const popup = { url: "chrome-extension://arca/popup.html" };
const ask = (msg, sender) =>
  new Promise((resolve) => {
    native.length = 0;
    if (listener(msg, sender, resolve) !== true) resolve(undefined);
  }).then((reply) => ({ reply, sent: [...native] }));

const bank = "https://bank.example";
const evil = "https://evil.example";

let r = await ask({ cmd: "listLogins", url: `${bank}/login` }, page(bank));
check(r.sent[0]?.type === "list_matching_logins", "a page may list its own logins");

r = await ask({ cmd: "listLogins", url: `${bank}/login` }, page(evil));
check(r.reply?.ok === false && r.sent.length === 0, "but not another site's");

r = await ask({ cmd: "listLogins", url: `${bank}/login` }, page(bank, 4));
check(r.sent.length === 0, "nor from a subframe, where no content script runs");

r = await ask({ cmd: "listLogins", url: "https://x.example/" }, page("null"));
check(r.sent.length === 0, "nor from a page with an opaque origin");

r = await ask({ cmd: "fill", id: "1", url: `${bank}/login` }, page(evil));
check(r.reply?.ok === false && r.sent.length === 0, "a fill is only for the page that asks");

for (const cmd of ["passkeyGet", "passkeyCreate"]) {
  r = await ask({ cmd, origin: bank, rpId: "bank.example" }, page(evil));
  check(r.reply?.ok === false && r.sent.length === 0, `${cmd} is only for the page's own origin`);
}

r = await ask({ cmd: "passkeyGate", host: "bank.example" }, page(evil));
check(r.reply?.allow === false && r.reply.reason === "origin_mismatch", "the passkey gate checks the host too");

r = await ask({ cmd: "saveProbe", url: `${bank}/login`, username: "", password: "guess" }, page(evil));
check(r.reply?.ok === false && r.sent.length === 0, "a save probe cannot ask about another site");

r = await ask({ cmd: "bookmarksFromArca", deletions: true, confirmed: true }, page(bank));
check(r.reply?.ok === false && r.sent.length === 0, "a page cannot send the popup's bookmark commands");

r = await ask({ cmd: "mirrorSetting", allowed: true }, page(bank));
check(r.reply?.ok === false, "nor change the bookmark mirror setting");

r = await ask({ cmd: "bookmarksFromArca", deletions: false, confirmed: false }, popup);
check(r.sent[0]?.type === "list_bookmarks", "the popup still can");

console.log(`sender checks: ${checks} passed`);
process.exit(0);
