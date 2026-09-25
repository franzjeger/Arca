// Popup: show whether the native messaging host (and thus the desktop app) is
// reachable, by performing the hello handshake through the background worker —
// and let the user say, per site, whether Arca should answer passkey ceremonies
// there at all.

const api = globalThis.browser ?? globalThis.chrome;

const dot = document.getElementById("dot");
const statusText = document.getElementById("statusText");
const detail = document.getElementById("detail");

api.runtime.sendMessage({ cmd: "hello" }).then((result) => {
  if (result && result.ok && result.response && result.response.type === "hello") {
    const appConnected = !!result.response.app_connected;
    const extensionVersion = api.runtime.getManifest().version;
    const hostVersion = result.response.version;
    const appVersion = result.response.app_version;
    const versions = [extensionVersion, hostVersion, appVersion].filter(Boolean);
    const versionsMatch = new Set(versions).size <= 1;
    dot.classList.add(appConnected ? "ok" : "bad");
    statusText.textContent = appConnected
      ? `Connected — extension v${extensionVersion}, host v${hostVersion}, app v${appVersion ?? "unknown"}`
      : `Host v${hostVersion} (app not running)`;
    if (!appConnected) {
      detail.textContent =
        "Native host is installed and responding. Open and unlock the Arca desktop app to enable autofill.";
    } else if (!versionsMatch) {
      detail.textContent =
        "Arca components have different versions. The protocol is compatible, but reinstall Arca and reload this extension to keep them in sync.";
    }
  } else if (
    result &&
    result.ok &&
    result.response &&
    result.response.type === "error" &&
    result.response.message === "unsupported_protocol"
  ) {
    dot.classList.add("bad");
    statusText.textContent = "Incompatible extension and native host";
    detail.textContent =
      "Reinstall Arca and reload this extension so every component uses the same protocol.";
  } else {
    dot.classList.add("bad");
    statusText.textContent = "Native host not found";
    detail.textContent =
      "Install the native messaging host manifest and the vault-native-host binary. See extension/README.md.";
  }
});

// ── Per-site passkey policy ─────────────────────────────────────────────────
//
// Mirrors `POLICY_KEY` in background.js. This decides only WHO ANSWERS a
// ceremony, never whether a credential may be released: an assertion still
// needs the vault unlocked and the desktop app's own approval, and the app's
// "Handle passkeys" switch overrides everything here.

const POLICY_KEY = "passkeyPolicy";

const siteEl = document.getElementById("site");
const hostEl = document.getElementById("host");
const policyEl = document.getElementById("policy");
const hintEl = document.getElementById("policyHint");
const listEl = document.getElementById("siteList");

const HINTS = {
  ask: "Arca answers when you started the sign-in — including when the site sends you to a separate page to finish it.",
  // Deliberately narrower than it used to read. "Always" no longer covers
  // registration: sites that re-offer "add a passkey" on a timer turned this
  // setting into a stream of unprompted Touch ID prompts, so creating a
  // credential now always needs a click in the page, whatever this says.
  always:
    "Arca answers every sign-in here, even one the page fires on its own. Registering a new passkey still needs a click from you.",
  never: "Ceremonies here go straight to the browser or your security key.",
};

/** The active tab's hostname, or null for pages Arca never touches. */
async function currentHost() {
  try {
    const tabs = await api.tabs.query({ active: true, currentWindow: true });
    const url = tabs && tabs[0] && tabs[0].url;
    if (!url) return null;
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:"
      ? u.hostname.toLowerCase()
      : null;
  } catch (_e) {
    return null;
  }
}

async function readPolicies() {
  try {
    const got = await api.storage.local.get(POLICY_KEY);
    return got[POLICY_KEY] || {};
  } catch (_e) {
    return {};
  }
}

async function writePolicies(map) {
  try {
    await api.storage.local.set({ [POLICY_KEY]: map });
  } catch (_e) {
    /* the gate falls back to "ask", which is the safe default anyway */
  }
}

/** The sites that deviate from the default, so a forgotten one is findable. */
function renderList(policies, host) {
  listEl.replaceChildren();
  const entries = Object.entries(policies).sort(([a], [b]) => a.localeCompare(b));
  for (const [site, policy] of entries) {
    if (site === host) continue; // already shown by the selector above
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.className = "name";
    name.textContent = site;
    const state = document.createElement("span");
    state.textContent = policy;
    const reset = document.createElement("button");
    reset.type = "button";
    reset.textContent = "×";
    reset.title = `Reset ${site} to ask`;
    reset.addEventListener("click", async () => {
      const next = await readPolicies();
      delete next[site];
      await writePolicies(next);
      renderList(next, host);
    });
    li.append(name, state, reset);
    listEl.append(li);
  }
}

(async () => {
  const host = await currentHost();
  const policies = await readPolicies();
  if (host) {
    hostEl.textContent = host;
    policyEl.value = policies[host] || "ask";
    hintEl.textContent = HINTS[policyEl.value];
    policyEl.addEventListener("change", async () => {
      const next = await readPolicies();
      if (policyEl.value === "ask") delete next[host];
      else next[host] = policyEl.value;
      await writePolicies(next);
      hintEl.textContent = HINTS[policyEl.value];
      renderList(next, host);
    });
  } else {
    // No site to scope to (a browser page, a file:// URL). Keep the list so an
    // override set elsewhere is still reachable.
    siteEl.querySelector("h2").textContent = "Passkey site overrides";
    policyEl.hidden = true;
    hintEl.textContent = Object.keys(policies).length
      ? ""
      : "No sites overridden.";
  }
  renderList(policies, host);
  siteEl.hidden = false;
})();


// ── Bookmarks ───────────────────────────────────────────────────────────────
//
// Push-out is the one thing Arca does that can destroy something the vault
// cannot restore, so it is a button a person presses, never a timer — and
// removing anything needs the checkbox AND a confirmation naming the number.

const bmStatus = document.getElementById("bmStatus");
const say = (msg) => {
  bmStatus.textContent = msg;
};

document.getElementById("bmUp").addEventListener("click", () => {
  say("Reading this browser…");
  // `.then`, not a callback: Firefox's `browser.runtime.sendMessage` returns a
  // promise and ignores the callback form entirely, so a callback here would
  // simply never fire there. The rest of this file already does it this way.
  api.runtime
    .sendMessage({ cmd: "bookmarksToArca" })
    .then((r) => {
      if (!r || !r.ok) {
        say(`Could not import: ${(r && r.error) || "no answer from Arca"}`);
        return;
      }
      say(
        r.added === 0
          ? "Nothing new — Arca already had them all."
          : `Added ${r.added} bookmark${r.added === 1 ? "" : "s"} to Arca.`,
      );
    })
    .catch((e) => say(`Could not import: ${e}`));
});

document.getElementById("bmDown").addEventListener("click", () => {
  const deletions = document.getElementById("bmDelete").checked;
  say("Applying Arca's list…");
  const run = (confirmed) =>
    api.runtime
      .sendMessage({ cmd: "bookmarksFromArca", deletions, confirmed })
      .then((r) => {
        if (!r || !r.ok) {
          say(`Could not apply: ${(r && r.error) || "no answer from Arca"}`);
          return;
        }
        if (r.refused) {
          // The refusal carries the numbers, so the confirmation asks about a
          // real quantity rather than an abstract "are you sure".
          if (r.pendingRemovals && confirm(`${r.refused}\n\nGo ahead?`)) {
            run(true);
          } else {
            say(r.refused);
          }
          return;
        }
        say(`Added ${r.added}, removed ${r.removed}.`);
      })
      .catch((e) => say(`Could not apply: ${e}`));
  run(false);
});


// ── The bookmark mirror ─────────────────────────────────────────────────────
//
// Off until the user says the browser's own sync is off, because Arca cannot
// read that setting and a wrong guess uploads their bookmarks to a server they
// cannot clean. Asking is not a cop-out here; it is the only honest option.

const mirrorEl = document.getElementById("mirrorAllowed");
const confirmBox = document.getElementById("mirrorConfirm");

const setMirror = async (allowed) => {
  const r = await api.runtime.sendMessage({ cmd: "mirrorSetting", allowed });
  if (r && r.ok) mirrorEl.checked = !!r.allowed;
  confirmBox.hidden = true;
};

api.runtime.sendMessage({ cmd: "mirrorSetting" }).then((r) => {
  if (r && r.ok) mirrorEl.checked = !!r.allowed;
});

// INLINE confirmation, not `confirm()`.
//
// A modal dialog takes focus, and an extension popup closes the moment it
// loses focus — so the rest of the handler never ran, the setting was never
// stored, and the checkbox was back to unticked next time the popup opened.
// From the outside that looked exactly like "turning it on does nothing".
mirrorEl.addEventListener("change", () => {
  if (!mirrorEl.checked) {
    void setMirror(false);
    return;
  }
  confirmBox.hidden = false;
});

document.getElementById("mirrorYes").addEventListener("click", () => setMirror(true));
document.getElementById("mirrorNo").addEventListener("click", () => {
  mirrorEl.checked = false;
  confirmBox.hidden = true;
});
