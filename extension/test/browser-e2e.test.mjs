// Real-browser regression test for the content script. It loads an unpacked
// copy of Arca in Chromium, replaces only the native bridge with deterministic
// replies, then drives normal and open-Shadow-DOM forms using trusted mouse
// input over the Chrome DevTools Protocol.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const extensionSource = path.resolve(here, "../chromium");
const candidates = [
  process.env.CHROME_BIN,
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  // Chrome 151 on macOS currently starts headless but does not inject unpacked
  // extensions. Brave uses the same Chromium engine and supports this harness,
  // so prefer it when both are installed; CHROME_BIN can always override.
  "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
].filter(Boolean);
const browser = candidates.find((candidate) => fs.existsSync(candidate));
// The CDP connection needs a WebSocket client. Node 20.10 added one but kept
// it behind --experimental-websocket; it is only on by default from Node 22.
// So "20.10+" was never a condition a plain `node` on 20 could satisfy, and
// the required run on CI failed with a message pointing at a version that
// would not have helped.
const hasWebSocketClient = typeof globalThis.WebSocket === "function";

if (!browser || !hasWebSocketClient) {
  if (process.env.ARCA_REQUIRE_BROWSER_E2E === "1") {
    throw new Error(
      !browser
        ? "Chromium/Chrome is required but was not found"
        : `This test needs a built-in WebSocket client: Node 22+, or Node 20.10+ run with --experimental-websocket (this is ${process.version})`,
    );
  }
  console.log(
    `browser e2e: skipped (${!browser ? "Chromium/Chrome not installed" : `no WebSocket client in ${process.version}`})`,
  );
  process.exit(0);
}

const fixture = `<!doctype html>
<html><head><meta charset="utf-8"><title>Arca E2E</title>
<script>
window.query = (selector) => document.querySelector('.sybr-panel')?.shadowRoot?.querySelector(selector.replace(/^\.sybr-panel /, '')) || document.querySelector(selector);
</script>
<style>
  body { margin: 0; min-height: 1200px; font: 16px sans-serif; }
  input { display: block; box-sizing: border-box; width: 260px; height: 34px; margin: 8px; }
  #shadow-host { position: fixed; right: 2px; bottom: 2px; width: 190px; height: 90px; }
  #change { position: fixed; left: 300px; bottom: 4px; }
  #portainer-change { position: fixed; left: 300px; top: 160px; }
  #named-user { position: fixed; left: 570px; top: 8px; }
  #synthetic { position: fixed; left: 570px; top: 120px; }
  #widgets { position: fixed; left: 570px; top: 232px; }
  #named-user input, #synthetic input, #widgets input { width: 210px; }
</style></head><body>
<form id="sign-in">
  <input id="sign-user" autocomplete="username">
  <input id="sign-password" type="password" autocomplete="current-password">
</form>
<div id="shadow-host"></div>
<form id="change">
  <input id="current" type="password" autocomplete="current-password">
  <input id="new" type="password" autocomplete="new-password">
  <input id="confirm" type="password" autocomplete="new-password">
</form>
<form id="portainer-change">
  <input id="current_password" type="password">
  <input id="new_password" name="new_password" type="password">
  <input id="confirm_password" type="password">
  <button id="update-password" type="submit">Update password</button>
</form>
<form id="named-user">
  <input id="named-login" type="text" name="login">
  <input id="named-pw" type="password" name="user_password">
</form>
<form id="synthetic">
  <input id="syn-user" autocomplete="username">
  <input id="syn-password" type="password" autocomplete="current-password">
</form>
<!-- No <form> anywhere: two independent widgets, the shape every React sign-in
     page has. Sign-up is rendered first, so "the first password box on the
     page" is the wrong answer for the sign-in identifier below it. -->
<div id="widgets">
  <input id="signup-user" autocomplete="username">
  <input id="signup-pw" type="password" autocomplete="new-password">
  <input id="signin-user" autocomplete="username">
  <input id="signin-pw" type="password" autocomplete="current-password">
</div>
<script>
  const root = query("#shadow-host").attachShadow({ mode: "open" });
  root.innerHTML = '<style>form{width:190px}input{box-sizing:border-box;width:188px;height:34px;display:block}</style>' +
    '<form><input id="user" autocomplete="username"><input id="password" type="password" autocomplete="current-password"></form>';
  query("#portainer-change").addEventListener("submit", (event) => {
    event.preventDefault();
    // Portainer keeps the account form mounted after a successful API call and
    // clears the three values. This is the success shape Arca must recognize.
    setTimeout(() => {
      query("#current_password").value = "";
      query("#new_password").value = "";
      query("#confirm_password").value = "";
    }, 100);
  });
</script></body></html>`;

const stepFixture = `<!doctype html><html><head><meta charset="utf-8"><title>Sign in</title>
<script>${fixture.match(/<script>([\s\S]*?)<\/script>/)[1]}</script>
<style nonce="arca-fixture">
 body { margin: 0; transform: translate(28px, 18px); font: 16px sans-serif; }
 input { display: block; width: 260px; height: 32px; box-sizing: border-box; margin: 6px 0; }
 form { margin: 12px; width: 280px; }
 #unrelated { position: absolute; left: 410px; top: 0; }
 #newsletter { position: absolute; left: 410px; top: 100px; }
 #generic { margin-top: 30px; }
 #scroller { height: 160px; width: 300px; overflow: auto; margin: 12px; }
 #scroller form { padding-top: 60px; padding-bottom: 200px; }
 /* Website rules must not inflate or reposition Arca's suggestions. */
 button { padding: 8px; }
 .sybr-row { height: 400px !important; font-size: 60px !important; }
 .sybr-panel { transform: translate(300px, 200px) !important; }
</style></head><body>
<form id="step"><h1>Logg inn</h1><input id="identifierId" autofocus><button type="button" id="next">Next</button></form>
<form id="unrelated"><input type="password" id="unrelated-password"></form>
<form id="newsletter"><h2>Newsletter</h2><input type="email" id="newsletter-email"><button>Subscribe</button></form>
<form id="generic"><h2>Sign in</h2><label for="address">E-mail</label><input id="address"><button type="button">Continue</button></form>
<div id="scroller"><form><input autocomplete="username" id="scroll-user"><input type="password" id="scroll-password"></form></div>
<script>
 query('#next').addEventListener('click', () => {
   query('#step').innerHTML = '<h1>Password</h1><input type="password" id="step-password" required>';
   query('#step-password').focus();
 });
</script></body></html>`;
const passkeyFixture = `<!doctype html><html><head><title>Passkey sign in</title>
<script>${fixture.match(/<script>([\s\S]*?)<\/script>/)[1]}</script>
<style>body{font:16px sans-serif;padding:30px}input{display:block;width:260px;height:34px;margin:8px}</style>
</head><body><form><h1>Sign in</h1>
<input id="pk-user" autocomplete="username webauthn" required>
<input id="pk-password" type="password" required><button>Sign in with password</button></form>
<output id="passkey-result"></output>
<script>
 window.submitted = false;
 query('form').addEventListener('submit', event => { event.preventDefault(); window.submitted = true; });
 window.ceremony = navigator.credentials.get({ mediation: 'conditional', publicKey: {
   challenge: new Uint8Array([1,2,3]), rpId: 'localhost', userVerification: 'required'
 }}).then(credential => {
   window.passkeyCredential = credential.toJSON();
   query('#passkey-result').textContent = 'Signed in with passkey';
 }).catch(error => { query('#passkey-result').textContent = error.name; });
</script></body></html>`;

const server = http.createServer((request, response) => {
  response.writeHead(200, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    ...(request.url.startsWith('/steps') ? { 'content-security-policy': "style-src 'nonce-arca-fixture'" } : {}),
  });
  response.end(request.url.startsWith("/passkey") ? passkeyFixture : request.url.startsWith("/steps") || request.url.startsWith("/slow") ? stepFixture : fixture);
});
await new Promise((resolve, reject) => {
  server.once("error", reject);
  server.listen(0, "127.0.0.1", resolve);
});
const { port } = server.address();
const pageUrl = `http://localhost:${port}/`;

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "arca-browser-e2e-"));
const extensionDir = path.join(tempRoot, "extension");
const profileDir = path.join(tempRoot, "profile");
fs.cpSync(extensionSource, extensionDir, { recursive: true });
fs.mkdirSync(profileDir);
fs.writeFileSync(
  path.join(extensionDir, "background.js"),
  `chrome.runtime.onMessage.addListener((message, _sender, reply) => {
    if (message.cmd === "listLogins") {
      const passkey = message.url.includes('passkey');
      const count = message.url.includes('/steps') || message.url.includes('/slow') ? 12 : 1;
      setTimeout(() => reply({ ok: true, response: { type: "logins", app_connected: true,
        items: Array.from({ length: count }, (_, index) => ({ id: "login-" + index,
          kind: passkey ? "passkey" : "login", title: "Fixture", credential_id: [1,2,3,4],
          username: "alice@example.test", url: "http://127.0.0.1" })) } }), message.url.includes('/slow') ? 450 : 0);
    } else if (message.cmd === "passkeyAvailable") {
      reply({ available: true });
    } else if (message.cmd === "passkeyGate") {
      reply({ ok: true, allow: !!message.localGesture, reason: 'gesture', version: chrome.runtime.getManifest().version });
    } else if (message.cmd === "passkeyGet") {
      // Answers only a pick the relay itself saw in Arca's picker: the click
      // in content.js has to reach the relay through the shared isolated world.
      reply({ ok: true, response: message.picked === true
        ? { type: 'passkey_assertion', credential_id: [1,2,3,4],
            authenticator_data: Array.from({length:37}, (_, i) => i === 32 ? 5 : 0),
            signature: [9,9,9], user_handle: [7,7] }
        : { type: 'error', message: 'not_picked' } });
    } else if (message.cmd === "fill") {
      reply({ ok: true, response: { type: "credentials",
        username: "alice@example.test", password: "stored-secret" } });
    } else if (message.cmd === "generatePassword") {
      reply({ ok: true, response: { type: "generated_password",
        password: "Generated-Strong-123!" } });
    } else if (message.cmd === "saveProbe") {
      const valid = message.multiPassword === true &&
        message.password === "Manually-Changed-456!";
      reply({ ok: true, response: valid
        ? { type: "save_decision", action: "update", username: "admin" }
        : { type: "error", message: "wrong candidate" } });
    } else if (message.cmd === "saveLogin") {
      const valid = message.multiPassword === true &&
        message.password === "Manually-Changed-456!";
      reply({ ok: true, response: valid
        ? { type: "saved" }
        : { type: "error", message: "wrong candidate" } });
    } else if (message.cmd === "consumePending") {
      reply({ ok: true, candidate: null });
    } else if (message.cmd === "getShadowRootMode") {
      reply({ mode: "open" });
    } else {
      reply({ ok: true, response: {} });
    }
    return true;
  });\n`,
);

let stderr = "";
let stdout = "";
const child = spawn(browser, [
  "--headless=new",
  "--no-sandbox",
  "--disable-gpu",
  // CI containers give /dev/shm 64MB. Chrome puts renderer shared memory
  // there and hangs or dies when it runs out — the classic CI-only failure
  // that never reproduces on a desktop.
  "--disable-dev-shm-usage",
  "--disable-background-networking",
  "--no-first-run",
  "--no-default-browser-check",
  "--remote-debugging-port=0",
  `--user-data-dir=${profileDir}`,
  `--disable-extensions-except=${extensionDir}`,
  `--load-extension=${extensionDir}`,
  "--window-size=800,600",
  pageUrl,
]);
child.stderr.setEncoding("utf8");
child.stdout.setEncoding("utf8");
child.stdout.on("data", (chunk) => (stdout += chunk));

// Chrome announces the port two ways: a line on stderr, and DevToolsActivePort
// in the profile (port on line 1, browser path on line 2). Take whichever
// arrives — stderr alone is not dependable, and a build that stays quiet on it
// left nothing to diagnose but an empty string.
const activePortFile = path.join(profileDir, "DevToolsActivePort");
const readActivePort = () => {
  try {
    const [port, browserPath] = fs
      .readFileSync(activePortFile, "utf8")
      .split("\n");
    if (port && browserPath) return `ws://127.0.0.1:${port.trim()}${browserPath.trim()}`;
  } catch {
    /* not written yet */
  }
  return null;
};

// A cold runner installing an unpacked extension is far slower than a warm
// desktop, where this resolves in well under a second.
const START_TIMEOUT_MS = 60000;
const webSocketUrl = await new Promise((resolve, reject) => {
  let settled = false;
  const finish = (fn, value) => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    clearInterval(poll);
    fn(value);
  };
  const fail = (what) =>
    finish(
      reject,
      new Error(
        `${what}\nalive: ${child.exitCode === null}\nstderr:\n${stderr.slice(-2000)}\nstdout:\n${stdout.slice(-2000)}`,
      ),
    );

  const timer = setTimeout(
    () => fail(`Chromium did not expose DevTools within ${START_TIMEOUT_MS}ms`),
    START_TIMEOUT_MS,
  );
  const poll = setInterval(() => {
    const url = readActivePort();
    if (url) finish(resolve, url);
  }, 250);

  child.once("error", (e) => finish(reject, e));
  child.once("exit", (code) => fail(`Chromium exited early (${code})`));
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
    const match = stderr.match(/DevTools listening on (ws:\/\/[^\s]+)/);
    if (match) finish(resolve, match[1]);
  });
});

const socket = new WebSocket(webSocketUrl);
await new Promise((resolve, reject) => {
  socket.addEventListener("open", resolve, { once: true });
  socket.addEventListener("error", reject, { once: true });
});

let nextId = 1;
const pending = new Map();
socket.addEventListener("message", (event) => {
  const message = JSON.parse(event.data);
  if (!message.id || !pending.has(message.id)) return;
  const { resolve, reject } = pending.get(message.id);
  pending.delete(message.id);
  if (message.error) reject(new Error(JSON.stringify(message.error)));
  else resolve(message.result);
});
const send = (method, params = {}, sessionId) =>
  new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
  });

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
let sessionId;
const evaluate = async (expression) => {
  const result = await send(
    "Runtime.evaluate",
    { expression, returnByValue: true, awaitPromise: true },
    sessionId,
  );
  if (result.exceptionDetails) {
    throw new Error(result.exceptionDetails.exception?.description ?? "evaluation failed");
  }
  return result.result.value;
};
const waitFor = async (expression, description) => {
  for (let attempt = 0; attempt < 50; attempt++) {
    const value = await evaluate(expression);
    if (value) return value;
    await sleep(100);
  }
  throw new Error(`Timed out waiting for ${description}`);
};
const trustedClick = async (selector = ".sybr-panel .sybr-row") => {
  const point = await evaluate(`(() => {
    const rect = query(${JSON.stringify(selector)}).getBoundingClientRect();
    return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
  })()`);
  await send("Input.dispatchMouseEvent", {
    type: "mousePressed", x: point.x, y: point.y, button: "left", clickCount: 1,
  }, sessionId);
  await send("Input.dispatchMouseEvent", {
    type: "mouseReleased", x: point.x, y: point.y, button: "left", clickCount: 1,
  }, sessionId);
};

/// Whatever the test found, kept across teardown so cleanup cannot mask it.
let failure = null;

try {
  let page;
  for (let attempt = 0; attempt < 30 && !page; attempt++) {
    const targets = await send("Target.getTargets");
    page = targets.targetInfos.find(
      (target) => target.type === "page" && target.url.startsWith(pageUrl),
    );
    if (!page) await sleep(100);
  }
  assert.ok(page, "fixture page target was not created");
  ({ sessionId } = await send("Target.attachToTarget", {
    targetId: page.targetId,
    flatten: true,
  }));
  await send("Runtime.enable", {}, sessionId);
  // The first thing that proves the extension is actually running. Branded
  // Google Chrome (137+, confirmed on 152) silently ignores --load-extension:
  // it starts, serves the page, and simply never loads Arca, so every
  // assertion below times out with nothing to say why. Name that here rather
  // than let it read as a bug in the content script.
  await waitFor(
    'document.querySelectorAll(".sybr-badge-host").length >= 5',
    `Arca field badges — if this timed out, ${browser} probably never loaded the unpacked extension. Branded Google Chrome ignores --load-extension; use Chromium, Brave, or Chrome for Testing (CHROME_BIN overrides the choice)`,
  );

  await evaluate('query("#sign-password").focus()');
  await waitFor(
    'query(".sybr-panel .sybr-row")?.textContent.includes("Fixture")',
    "normal login picker",
  );
  await trustedClick();
  await waitFor(
    'query("#sign-password").value === "stored-secret"',
    "normal credential fill",
  );
  assert.deepEqual(await evaluate(`[
    query("#sign-user").value,
    query("#sign-password").value,
  ]`), ["alice@example.test", "stored-secret"]);

  await evaluate('query("#shadow-host").shadowRoot.querySelector("#password").focus()');
  await waitFor(
    'query(".sybr-panel .sybr-row")?.textContent.includes("Fixture")',
    "Shadow DOM login picker",
  );
  const bounds = await evaluate(`(() => {
    const rect = query(".sybr-panel").getBoundingClientRect();
    const viewport = window.visualViewport;
    const left = viewport ? viewport.offsetLeft : 0;
    const top = viewport ? viewport.offsetTop : 0;
    const right = left + (viewport ? viewport.width : innerWidth);
    const bottom = top + (viewport ? viewport.height : innerHeight);
    return {
      inside: rect.left >= left && rect.top >= top && rect.right <= right && rect.bottom <= bottom,
      placement: query(".sybr-panel").dataset.placement,
    };
  })()`);
  assert.deepEqual(bounds, { inside: true, placement: "above" });
  await trustedClick();
  await waitFor(
    'query("#shadow-host").shadowRoot.querySelector("#password").value === "stored-secret"',
    "Shadow DOM credential fill",
  );
  assert.deepEqual(await evaluate(`[
    query("#shadow-host").shadowRoot.querySelector("#user").value,
    query("#shadow-host").shadowRoot.querySelector("#password").value,
  ]`), ["alice@example.test", "stored-secret"]);

  await evaluate('query("#confirm").focus()');
  await waitFor(
    'query(".sybr-panel .sybr-row")?.textContent.includes("Use a strong password")',
    "password generator picker",
  );
  await trustedClick();
  await waitFor(
    'query("#confirm").value === "Generated-Strong-123!"',
    "generated password fill",
  );
  assert.deepEqual(await evaluate(`[
    query("#current").value,
    query("#new").value,
    query("#confirm").value,
  ]`), ["", "Generated-Strong-123!", "Generated-Strong-123!"]);
  // The generated value is shown for review, not left as an unreadable secret.
  await waitFor(
    'query(".sybr-generated-value")?.textContent === "Generated-Strong-123!"',
    "generated password shown for review",
  );

  await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Escape', code: 'Escape' }, sessionId);
  // Portainer's account page: current/new/confirm, no autocomplete metadata,
  // no username, and the form remains mounted after the API succeeds.
  await evaluate(`(() => {
    query("#current_password").value = "old-password";
    query("#new_password").value = "Manually-Changed-456!";
    query("#confirm_password").value = "Manually-Changed-456!";
  })()`);
  await trustedClick("#update-password");
  await waitFor(
    'query(".sybr-savebar")?.textContent.includes("Update the password for admin")',
    "Portainer password-change save prompt",
  );
  await trustedClick(".sybr-savebar-yes");
  await waitFor(
    '!query(".sybr-savebar")',
    "confirmed Portainer password save",
  );

  // A password box whose NAME mentions "user" (`user_password`) matched the
  // username tiers, so the field was returned as its own username field: the
  // real login box stayed empty and the password was written twice — and
  // capture then read that password back as the account name.
  await evaluate('query("#named-pw").focus()');
  await waitFor(
    'query(".sybr-panel .sybr-row")?.textContent.includes("Fixture")',
    "picker on a user_password-named field",
  );
  await trustedClick();
  await waitFor(
    'query("#named-pw").value === "stored-secret"',
    "fill into a user_password-named field",
  );
  assert.deepEqual(
    await evaluate(`[
      query("#named-login").value,
      query("#named-pw").value,
    ]`),
    ["alice@example.test", "stored-secret"],
    "the username belongs in the login box, not in the password box",
  );

  // The picker sits in the page's own DOM and opens on focus, so a script on
  // the page could focus the password box, click a row and read the credential
  // back out of the input. Only a real click may release one.
  await evaluate('query("#syn-password").focus()');
  await waitFor(
    'query(".sybr-panel .sybr-row")?.textContent.includes("Fixture")',
    "picker for the synthetic-click check",
  );
  await evaluate('query(".sybr-panel .sybr-row").click()');
  await sleep(500);
  assert.deepEqual(
    await evaluate(`[
      query("#syn-user").value,
      query("#syn-password").value,
    ]`),
    ["", ""],
    "a synthetic click must not fill a credential",
  );
  // ...and the same row still fills for a real one, so the check above is not
  // passing merely because the picker was broken.
  await trustedClick();
  await waitFor(
    'query("#syn-password").value === "stored-secret"',
    "trusted click still fills after a refused synthetic one",
  );

  // Two form-less widgets: picking on the SIGN-IN identifier used to fill the
  // first current-password box on the whole page, which is in an unrelated
  // widget rendered above it.
  await evaluate('query("#signin-user").focus()');
  await waitFor(
    'query(".sybr-panel .sybr-row")?.textContent.includes("Fixture")',
    "picker on a form-less sign-in identifier",
  );
  await trustedClick();
  await waitFor(
    'query("#signin-pw").value === "stored-secret"',
    "fill into the widget the identifier belongs to",
  );
  assert.deepEqual(
    await evaluate(`[
      query("#signin-user").value,
      query("#signup-pw").value,
      query("#shadow-host").shadowRoot.querySelector("#password").value,
    ]`),
    ["alice@example.test", "", "stored-secret"],
    "no other widget on the page may be filled",
  );
  const navigate = async (route) => {
    await send('Page.navigate', { url: pageUrl + route }, sessionId);
    await waitFor(`location.pathname === ${JSON.stringify('/' + route)} && document.querySelector('.sybr-badge-host')`, 'new fixture badges');
  };
  const pickerAt = (selector) => `(() => {
    const panel = query('.sybr-panel'), field = query(${JSON.stringify(selector)});
    if (!panel || !field || !query('.sybr-panel .sybr-row')) return false;
    const p = panel.getBoundingClientRect(), f = field.getBoundingClientRect();
    return Math.abs(p.left - f.left) < 2 && (p.bottom <= f.top - 5 || p.top >= f.bottom + 5) &&
      p.top >= 0 && p.bottom <= innerHeight;
  })()`;
  await navigate('steps');
  await waitFor("query('#identifierId').dataset.sybrAttached && query('.sybr-panel .sybr-row')", 'autofocused identifier with implicit text type');
  assert.equal(await evaluate("!!query('#address').dataset.sybrAttached"), true, 'labelled email field in sign-in form is detected');
  assert.equal(await evaluate("!!query('#newsletter-email').dataset.sybrAttached"), false, 'newsletter email remains untouched');
  await waitFor(pickerAt('#identifierId'), 'picker outside the active field despite transformed body and hostile CSS');
  assert.equal(await evaluate("getComputedStyle(query('.sybr-panel .sybr-row')).fontSize"), '13px', 'website CSS and CSP cannot break picker styles');
  if (process.env.ARCA_AUTOFILL_SCREENSHOT) {
    const shot = await send('Page.captureScreenshot', { format: 'png' }, sessionId);
    fs.writeFileSync(process.env.ARCA_AUTOFILL_SCREENSHOT, Buffer.from(shot.data, 'base64'));
  }
  await trustedClick();
  assert.deepEqual(await evaluate("[query('#identifierId').value, query('#unrelated-password').value]"),
    ['alice@example.test', ''], 'identifier-only fill must leave unrelated passwords empty');
  await trustedClick('#next');
  await waitFor("query('.sybr-panel .sybr-row') && query('#step-password')", 'dynamically focused password step');
  await trustedClick();
  await waitFor("query('#step-password').value === 'stored-secret'", 'password fill after advancing from the username step');
  // Cached suggestions survive the ordinary focus + click event sequence.
  await trustedClick('#address');
  await waitFor(pickerAt('#address'), 'cached picker stays open at the clicked field');
  await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Escape', code: 'Escape' }, sessionId);
  assert.equal(await evaluate("!!query('.sybr-panel')"), false);
  // Nested scrolling must move both the badge and the open picker.
  await evaluate("query('#scroll-password').focus(); query('#scroller').scrollTop = 35");
  await waitFor(pickerAt('#scroll-password'), 'picker follows nested scroll');
  assert.equal(await evaluate(`(() => {
    const f = query('#scroll-password').getBoundingClientRect();
    return [...document.querySelectorAll('.sybr-badge-host')].some(host => {
      const r = host.getBoundingClientRect();
      return Math.abs(r.top + 11 - (f.top + f.height / 2)) < 2 && Math.abs(r.left - (f.right - 28)) < 2;
    });
  })()`), true, 'badge follows the same input during nested scroll');
  await trustedClick('.sybr-panel button[aria-label="Close suggestions"]');
  assert.equal(await evaluate("!!query('.sybr-panel')"), false);
  await evaluate("query('#scroll-user').focus(); query('#scroll-password').focus(); query('#scroller').scrollTop = 260");
  await waitFor("!query('.sybr-panel')", 'picker hides when its field is clipped by a scrolling container');
  await navigate('slow');
  await evaluate("query('#identifierId').focus(); query('#address').focus()");
  await waitFor(pickerAt('#address'), 'late result belongs to the most recently focused field');
  await navigate('slow-dismiss');
  await evaluate("query('#identifierId').focus(); query('#newsletter-email').focus()");
  await sleep(650);
  assert.equal(await evaluate("!!query('.sybr-panel')"), false, 'late lookup cannot reopen dismissed suggestions');
  await navigate('steps-passkey');
  await waitFor("query('.sybr-panel .sybr-kind-passkey')", 'passkey account on username-only step');
  await trustedClick();
  await waitFor("query('#identifierId').value === 'alice@example.test'", 'passkey account fills its first-step username');
  assert.equal(await evaluate("query('#unrelated-password').value"), '', 'passkey first step never fills another form');
  await send('WebAuthn.enable', {}, sessionId);
  await send('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true,
  } }, sessionId);
  await navigate('passkey');
  // A pick is the approval, so it only counts for a row the browser itself
  // reports as painted, unobscured and unfaded, for a moment before the click.
  // Each attack below is a real trusted click that lands on the row; the stub
  // desktop refuses an unpicked request, so the ceremony stays live and the
  // page is not signed in.
  const showPasskeys = async () => {
    await evaluate("document.activeElement?.blur()");
    await trustedClick('#pk-user');
    await waitFor("query('.sybr-panel .sybr-kind-passkey')", 'passkey suggestion');
  };
  const refused = "query('.sybr-panel-content')?.textContent.includes('could not complete')";
  // Flashed: the page opens the picker under a click already on its way. By
  // 300 ms the browser has reported the row visible, so only the half-second
  // rule stands between this click and a pick.
  await evaluate(`window.__pickerAt = 0; new MutationObserver(() => {
    if (!window.__pickerAt && document.querySelector('.sybr-panel')) window.__pickerAt = performance.now();
  }).observe(document.documentElement, { childList: true })`);
  await showPasskeys();
  await sleep(Math.max(0, 300 - await evaluate("performance.now() - window.__pickerAt")));
  await trustedClick();
  await waitFor(refused, 'a row on screen for under half a second is not a pick');
  await showPasskeys();
  await evaluate("document.querySelector('.sybr-panel').style.setProperty('opacity', '0.01', 'important')");
  await sleep(800);
  await trustedClick();
  await waitFor(refused, 'a row the page faded is not a pick');
  await showPasskeys();
  await evaluate(`(() => {
    const decoy = document.createElement('div');
    decoy.id = 'decoy';
    decoy.popover = 'manual';
    decoy.style.cssText = 'position:fixed;inset:0;margin:0;border:0;width:100vw;height:100vh;background:#fff;pointer-events:none';
    document.body.append(decoy);
    decoy.showPopover();
  })()`);
  await sleep(800);
  await trustedClick();
  await waitFor(refused, 'a row under a click-through layer is not a pick');
  await evaluate("document.getElementById('decoy').remove()");
  assert.equal(await evaluate("query('#passkey-result').textContent"), '', 'no attack signed the page in');
  await showPasskeys();
  await sleep(800);
  await trustedClick();
  await waitFor("query('#passkey-result').textContent === 'Signed in with passkey'", 'passkey completes the website ceremony');
  assert.deepEqual(await evaluate("[query('#pk-user').value, query('#pk-password').value, window.submitted, window.passkeyCredential.type]"),
    ['', '', false, 'public-key'], 'passkey sign-in must neither fill nor submit the required password form');
  const clientData = JSON.parse(Buffer.from(
    await evaluate("window.passkeyCredential.response.clientDataJSON"), "base64url").toString());
  assert.deepEqual([clientData.type, clientData.origin, clientData.challenge],
    ['webauthn.get', `http://localhost:${port}`, 'AQID'],
    'the relying party receives client data the relay built for this origin');
} catch (error) {
  // Held, not rethrown yet: teardown runs next, and a failure THERE must not
  // replace this one. It did once — a cleanup ENOTEMPTY on CI was all that
  // reached the log, and whatever the test actually found was lost.
  try { console.error('Fixture state:', await evaluate(`({ url: location.pathname, result: query('#passkey-result')?.textContent,
    panel: query('.sybr-panel')?.shadowRoot?.querySelector('.sybr-panel-content')?.textContent, hooked: window.__sybrPasskeyHooked })`)); } catch {}
  failure = error;
} finally {
  const exited = new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) resolve();
    else child.once("exit", resolve);
  });
  // Ask the browser to flush and close its profile before terminating it.
  // SIGTERM alone can leave Chromium's subprocesses writing during removal.
  try {
    await Promise.race([send("Browser.close"), sleep(5000)]);
  } catch { /* the connection may close before the protocol reply arrives */ }
  let died = await Promise.race([
    exited.then(() => true),
    sleep(5000).then(() => false),
  ]);
  if (!died) {
    child.kill("SIGTERM");
    died = await Promise.race([exited.then(() => true), sleep(5000).then(() => false)]);
  }
  if (!died) {
    child.kill("SIGKILL");
    await Promise.race([exited, sleep(5000)]);
  }
  socket.close();
  await new Promise((resolve) => server.close(resolve));
  try {
    await fs.promises.rm(tempRoot, {
      recursive: true,
      force: true,
      maxRetries: 10,
      retryDelay: 100,
    });
  } catch (cleanupError) {
    // A leftover temp dir is worth reporting, but never at the cost of the
    // test result: /tmp on a CI runner is discarded with the machine.
    if (failure) console.error(`(cleanup also failed: ${cleanupError.message})`);
    else failure = cleanupError;
  }
}

if (failure) throw failure;

console.log(
  "browser e2e: fill, generator, Portainer password change, trusted-click gate, " +
    "identifier-first forms, focus races, nested scrolling, isolated picker bounds and password-free passkeys passed",
);
