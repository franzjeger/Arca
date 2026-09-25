// Background service worker (Chromium) / event page (Firefox).
//
// It is the only context allowed to talk to the native-messaging host. Content
// scripts and the popup send it messages; it relays them to the Rust host and
// returns the response. The vault stays owned by the desktop app, which only
// releases a credential on an explicit "fill" for a matching origin while
// unlocked; "listLogins" only ever returns metadata.

// STATIC imports, and they have to be. A service worker forbids dynamic
// `import()` outright — "import() is disallowed on ServiceWorkerGlobalScope by
// the HTML specification" — so the one-line trick that kept the passkey suite
// happy shipped an extension where cleanup and mirroring threw on every call.
// The manifest declares this worker as a module precisely so these are legal;
// the test harness is what has to bend, not the code that has to run.
import {
  readAll,
  apply,
  planCleanup,
  barRootId,
  OWNED_FOLDER_TITLE,
} from "./bookmarks.js";
import {
  buildTree,
  creationOrder,
  fingerprint,
  mirrorGate,
  serialExecutor,
  vaultVerdict,
} from "./mirror.js";

const api = globalThis.browser ?? globalThis.chrome;

// Must match the native messaging host manifest `name`.
const NATIVE_HOST = "no.sybr.vault";
// Must match PROTOCOL_VERSION in extension/native-host. A mismatch is refused
// explicitly instead of letting requests fail later with misleading errors.
const NATIVE_PROTOCOL = 1;

// ── Telling a terminal what went wrong ──────────────────────────────────────
//
// A service worker's console lives in the browser's memory and nowhere else.
// No file, no `log show`, nothing a terminal can reach — so when the person
// hitting the bug and the person fixing it are not in the same room, an
// exception here is simply invisible. Both of today's other logs exist for the
// same reason and both settled arguments that were otherwise guesswork.
//
// Fire and forget, and never allowed to throw: a reporter that can fail is a
// second bug on top of the first one.
function report(level, message) {
  try {
    const p = api.runtime.sendNativeMessage(NATIVE_HOST, {
      type: "log",
      level,
      message: String(message).slice(0, 2000),
    });
    if (p && typeof p.catch === "function") p.catch(() => {});
  } catch (_e) {
    /* the host is unreachable; there is nowhere left to say so */
  }
}

// Anything the worker throws, and any promise nobody caught. Between them these
// cover the failures that would otherwise show up only as "nothing happened".
// `globalThis`, not `self`. Optional chaining guards a missing PROPERTY, not a
// missing binding — `self?.x` still throws ReferenceError where `self` was
// never declared, and the passkey suite runs this file in a vm context that
// has no `self` at all. One line, 34 checks.
if (typeof globalThis.addEventListener === "function") {
  globalThis.addEventListener("error", (e) =>
    report("error", `${e.message} @ ${e.filename}:${e.lineno}`),
  );
  globalThis.addEventListener("unhandledrejection", (e) =>
    report("error", `unhandled rejection: ${(e.reason && e.reason.stack) || e.reason}`),
  );
}

// A line per worker start, before anything else can fail.
//
// The reporter used to be installed at the BOTTOM of this file, after startup
// work had already run — so the one window worth seeing into, the moments
// between the worker booting and it being ready, reported nothing at all. When
// the alarm silently stopped firing there was no way to tell a worker that had
// crashed on boot from one that was never started.
report(
  "info",
  "worker start — triggers: " +
    [
      api.alarms ? "alarms" : null,
      api.windows && api.windows.onFocusChanged ? "focus" : null,
      api.tabs && api.tabs.onActivated ? "tabs" : null,
    ]
      .filter(Boolean)
      .join(", "),
);

// A poll, not a subscription, because there is nothing to subscribe to: the app
// cannot call into the extension. `alarms` rather than setInterval — a service
// worker is evicted when idle, and an interval dies with it while an alarm
// wakes it back up.
// Created ONLY IF MISSING. `alarms.create` with an existing name REPLACES it
// and restarts the countdown — and this runs at module scope, on every worker
// wake. So any other reason to wake (a message, a tab event, a popup opening)
// pushed the next fire out another full minute, and a browser being used
// deferred it forever. The mirror then only caught up when the browser had
// been left alone for a whole minute, which looked exactly like "locking Arca
// does nothing".
api.alarms?.get?.("arca-mirror", (existing) => {
  if (!existing) api.alarms.create("arca-mirror", { periodInMinutes: 1 });
});
api.alarms?.onAlarm.addListener((a) => {
  if (a.name === "arca-mirror") reconcileMirror("tick");
});

// The alarm is the BACKSTOP, not the mechanism. Once a minute is fine for
// catching up, and far too slow for the moment that matters: locking the vault
// and walking away should not leave the bookmarks sitting there for another
// fifty seconds.
//
// The app cannot call into the extension — there is no channel that way — so
// the next best trigger is the user arriving. Focusing a window or switching a
// tab means someone is looking at this browser, which is exactly when a stale
// folder would be seen. Reconciling then makes it feel immediate without
// polling harder.
//
// Cheap by construction: when nothing has changed the fingerprint matches and
// reconcile returns before touching a single bookmark. Only a real change
// costs anything.
api.windows?.onFocusChanged?.addListener((id) => {
  // -1 is "left every window of this browser". Nothing to show, nobody
  // looking, and reconciling on the way out would race the way back in.
  if (id !== -1) reconcileMirror("window focus");
});
api.tabs?.onActivated?.addListener(() => reconcileMirror("tab switch"));

// ── Bookmarks the USER puts in Arca's folder ────────────────────────────────
//
// Dropping them was bad design and worse manners: a bookmark saved into a
// folder that is visibly Arca's, silently gone at the next rebuild, with no
// warning and nothing to undo. "It is only a view" is an explanation, not an
// excuse — the folder looks writable because it IS writable, and a person is
// entitled to expect that what they put in a folder stays there.
//
// So anything created inside it is handed to Arca, which makes it part of the
// master list, which means the next rebuild puts it back rather than dropping
// it.
api.bookmarks?.onCreated?.addListener(async (id, node) => {
  // Our own rebuild fires this 128 times. Ignoring our own writes is what
  // separates "the user added something" from "Arca is redrawing".
  if (applying > 0) return;
  if (!node || !node.url) return; // a folder; it carries no bookmark to save
  try {
    const { id: ownedId } = await readMirrorState();
    if (!(await insideOwnedFolder(node.parentId, ownedId))) return;

    // The folder path this landed in, relative to Arca's own folder, so it
    // comes back to the same place it was filed.
    const folder = await pathWithinOwned(node.parentId, ownedId);
    const answer = await sendNative({
      type: "import_bookmarks",
      items: [{ title: node.title || node.url, url: node.url, folder }],
    });
    const added =
      answer.ok && answer.response && answer.response.type === "imported_bookmarks"
        ? answer.response.added
        : null;
    report(
      added === null ? "error" : "info",
      added === null
        ? `could not save a bookmark added to Arca's folder: ${
            (answer.response && answer.response.message) || answer.error
          }`
        : `saved a bookmark added to Arca's folder (${added} new)`,
    );
    // The fingerprint is now stale by construction — Arca holds one more than
    // the mirror does. Clearing it makes the next reconcile rebuild rather
    // than decide nothing has changed.
    await api.storage.local.remove(MIRROR_STAMP_KEY);
  } catch (e) {
    report("error", `capture failed: ${(e && e.stack) || e}`);
  }
});

// Deleting inside Arca's folder deletes from Arca.
//
// Without this the entry came straight back on the next rebuild, which is its
// own kind of broken: the folder accepts the gesture, appears to obey, and
// then undoes it. Half a feature is worse than none, because it teaches people
// the wrong model.
//
// `onRemoved` carries the node that went, so a single bookmark is matched on
// url plus folder — the key the import already deduplicates on — and a whole
// folder is matched by path prefix. The vault delete is SOFT and snapshots
// first: a browser event is a thin thing to destroy data on, and this one can
// arrive while a rebuild is in flight.
api.bookmarks?.onRemoved?.addListener(async (id, info) => {
  // Our own rebuild removes the entire tree. Without this the first rebuild
  // after a lock would retract all 128 from the vault.
  if (applying > 0) return;
  try {
    const { id: ownedId } = await readMirrorState();
    if (!ownedId) return;
    // The node is already gone, so ownership is judged from the parent it was
    // removed FROM, which still exists.
    if (String(info.parentId) !== String(ownedId)) {
      if (!(await insideOwnedFolder(info.parentId, ownedId))) return;
    }
    const node = info.node || {};
    const folder = await pathWithinOwned(info.parentId, ownedId);
    const payload = node.url
      ? { url: node.url, folder }
      : // A folder: everything at or under its path goes.
        { url: "", folder: folder ? `${folder}/${node.title}` : node.title || "" };
    if (!payload.url && !payload.folder) return;

    const answer = await sendNative({ type: "delete_bookmarks", ...payload });
    const removed =
      answer.ok && answer.response && answer.response.type === "deleted_bookmarks"
        ? answer.response.removed
        : null;
    report(
      removed === null ? "error" : "info",
      removed === null
        ? `could not retract a deleted bookmark: ${
            (answer.response && answer.response.message) || answer.error
          }`
        : `retracted ${removed} from Arca after a deletion in the folder`,
    );
    await api.storage.local.remove(MIRROR_STAMP_KEY);
  } catch (e) {
    report("error", `retract failed: ${(e && e.stack) || e}`);
  }
});

/// The `/`-separated path from Arca's folder down to `id`, exclusive.
async function pathWithinOwned(id, ownedId) {
  const parts = [];
  let cursor = id;
  for (let hop = 0; hop < 32 && cursor; hop++) {
    if (String(cursor) === String(ownedId)) break;
    let node;
    try {
      [node] = await api.bookmarks.get(String(cursor));
    } catch (_e) {
      break;
    }
    if (!node) break;
    parts.unshift(node.title || "");
    cursor = node.parentId;
  }
  return parts.filter(Boolean).join("/");
}

// Registered HERE, near the top, and not at the end of the file. Anything that
// throws at module scope stops everything below it — so an alarm declared last
// is an alarm that never exists on exactly the runs where it is needed most.
// That is not hypothetical: the periodic reconcile went silent for ten minutes
// and looked like a feature refusing, when nothing was running at all.



// Lightweight schema validator (Zod-like) for IPC strictness
const z = {
  string: () => ({ type: "string" }),
  number: () => ({ type: "number" }),
  boolean: () => ({ type: "boolean" }),
  any: () => ({ type: "any" }),
  array: (schema) => ({ type: "array", schema }),
  object: (shape) => ({ type: "object", shape }),
  optional: (schema) => ({ ...schema, optional: true }),
  parse: (schema, data) => {
    if (schema.optional && (data === undefined || data === null)) return data;
    switch (schema.type) {
      case "string":
        if (typeof data !== "string") throw new Error("Expected string");
        return data;
      case "number":
        if (typeof data !== "number") throw new Error("Expected number");
        return data;
      case "boolean":
        if (typeof data !== "boolean") throw new Error("Expected boolean");
        return data;
      case "any":
        return data;
      case "array":
        if (!Array.isArray(data)) throw new Error("Expected array");
        return data.map((item) => z.parse(schema.schema, item));
      case "object":
        if (typeof data !== "object" || data === null) throw new Error("Expected object");
        const res = {};
        for (const [key, propSchema] of Object.entries(schema.shape)) {
          if (data[key] !== undefined) {
            res[key] = z.parse(propSchema, data[key]);
          } else if (!propSchema.optional) {
            throw new Error(`Missing required field: ${key}`);
          }
        }
        return res;
    }
  }
};

/** Send one message to the native host and resolve a uniform result object. */
function sendNative(message, schema = null) {
  return new Promise((resolve) => {
    let settled = false;

    // Timeout to improve session robustness: if the desktop app/bridge hangs,
    // we don't want the extension to hang indefinitely and block the user flow.
    const timeout = setTimeout(() => {
      if (!settled) {
        settled = true;
        resolve({ ok: false, error: "IPC timeout (no response from desktop app)" });
      }
    }, 60000); // 60s timeout

    try {
      api.runtime.sendNativeMessage(NATIVE_HOST, message, (response) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);

        const err = api.runtime.lastError;
        if (err) {
          resolve({ ok: false, error: err.message });
        } else {
          if (schema && response) {
            try {
              response = z.parse(schema, response);
            } catch (e) {
              resolve({ ok: false, error: "IPC schema validation failed: " + e.message });
              return;
            }
          }
          resolve({ ok: true, response });
        }
      });
    } catch (e) {
      if (!settled) {
        settled = true;
        clearTimeout(timeout);
        resolve({ ok: false, error: String(e) });
      }
    }
  });
}

// `storage.session` is in-memory (never written to disk) and, unlike a plain
// Map, survives the service worker being evicted mid-flow. Both ledgers below
// use it, with their Map as a same-turn fast path and as the fallback where
// `storage.session` is missing.
const sessionStore = api.storage && api.storage.session;

// Per-tab "a login was just submitted" candidate, so the save prompt can be
// shown after the form navigates. Held briefly, and never on disk.
//
// The Map alone was not enough. MV3 evicts an idle service worker after ~30 s,
// and a sign-in that waits on a push-approval prompt before navigating is idle
// by that measure — the worker died holding the only copy, and the save prompt
// the user was waiting for never came. `storage.session` is in-memory too (it
// is cleared when the browser closes and is never written to disk) but it
// outlives the worker, so the candidate does as well. Same pattern, and same
// reasoning, as the gesture ledger below.
const pendingSaves = new Map(); // tabId -> { candidate, ts }
const PENDING_TTL_MS = 90000;
const pendingKey = (tabId) => `pendingSave:${tabId}`;

async function putPending(tabId, entry) {
  pendingSaves.set(tabId, entry);
  if (sessionStore) {
    try {
      await sessionStore.set({ [pendingKey(tabId)]: entry });
    } catch (_e) {
      /* fast path already holds it */
    }
  }
}

async function dropPending(tabId) {
  if (tabId == null) return;
  pendingSaves.delete(tabId);
  if (sessionStore) {
    try {
      await sessionStore.remove(pendingKey(tabId));
    } catch (_e) {
      /* nothing to undo */
    }
  }
}

async function readPending(tabId) {
  if (tabId == null) return null;
  let entry = pendingSaves.get(tabId) || null;
  if (!entry && sessionStore) {
    try {
      const got = await sessionStore.get(pendingKey(tabId));
      entry = got[pendingKey(tabId)] || null;
    } catch (_e) {
      entry = null;
    }
  }
  return entry;
}

// ── The passkey gate ────────────────────────────────────────────────────────
//
// A WebAuthn ceremony often does not run in the document the user clicked in.
// Microsoft Entra is the clean example: the click lands on
// login.microsoftonline.com, the browser navigates to
// login.microsoft.com/common/bridge/fido, and *that* document fires
// credentials.get() on load. A gesture tracked inside the page dies with the
// page, so the shim saw no gesture and handed every M365 sign-in back to the
// browser — which on Linux means the QR / security-key dialog, because there is
// no platform authenticator to quietly catch it.
//
// So the gesture is remembered per TAB, here, where it outlives the navigation.
// It is still CONSUMED: one gesture, one ceremony, so a page that re-fires
// get() in a loop gets exactly one shot at a prompt.
const GESTURE_TTL_MS = 10000;

// How young an untouched document must be for a create() fired in it to count
// as "the page finishing what a click elsewhere started" rather than "a page
// that has been sitting open deciding to register something". Microsoft's
// fido/create page fires within a second or two of load; GitHub's re-offer
// comes on a timer in a page the user has long since arrived at.
const CREATE_ARRIVAL_WINDOW_MS = 5000;

const memGestures = new Map(); // tabId -> ts
const gestureKey = (tabId) => `gesture:${tabId}`;

async function recordGesture(tabId) {
  if (tabId == null) return;
  const ts = Date.now();
  memGestures.set(tabId, ts);
  if (sessionStore) {
    try {
      await sessionStore.set({ [gestureKey(tabId)]: ts });
    } catch (_e) {
      /* fast path already holds it */
    }
  }
}

async function clearGesture(tabId) {
  if (tabId == null) return;
  memGestures.delete(tabId);
  if (sessionStore) {
    try {
      await sessionStore.remove(gestureKey(tabId));
    } catch (_e) {
      /* nothing to undo */
    }
  }
}

/** The timestamp of this tab's unspent gesture, or 0. Does not consume it. */
async function peekGesture(tabId) {
  if (tabId == null) return 0;
  let ts = memGestures.get(tabId) || 0;
  if (!ts && sessionStore) {
    try {
      const got = await sessionStore.get(gestureKey(tabId));
      ts = got[gestureKey(tabId)] || 0;
    } catch (_e) {
      ts = 0;
    }
  }
  return ts;
}

/** Consume this tab's gesture. True only if one was recorded and is fresh. */
async function takeGesture(tabId) {
  if (tabId == null) return false;
  const ts = await peekGesture(tabId);
  await clearGesture(tabId);
  return ts > 0 && Date.now() - ts <= GESTURE_TTL_MS;
}

// A click that opens a NEW tab carries its gesture into that tab. Some
// registration flows do exactly this — the account page window.open()s the
// page that runs the ceremony — and from the ledger's point of view the new
// tab is one nobody has ever touched. The gesture MOVES rather than copies:
// one gesture, one ceremony, whichever tab it happens in.
api.tabs?.onCreated?.addListener((tab) => {
  const opener = tab && tab.openerTabId;
  if (opener == null || tab.id == null) return;
  void (async () => {
    const ts = await peekGesture(opener);
    if (!(ts > 0 && Date.now() - ts <= GESTURE_TTL_MS)) return;
    await clearGesture(opener);
    memGestures.set(tab.id, ts);
    if (sessionStore) {
      try {
        await sessionStore.set({ [gestureKey(tab.id)]: ts });
      } catch (_e) {
        /* fast path already holds it */
      }
    }
  })();
});

// Per-site override of the gate, set from the popup. "ask" (the default) means
// the gesture decides; "always" lets a site fire a ceremony Arca answers even
// with no gesture at all; "never" keeps Arca out of a site's way entirely.
//
// This only decides WHO ANSWERS the ceremony. It cannot release a credential,
// cannot bypass the app's rp_id<->origin check, and cannot forge user
// verification: every assertion still needs the vault unlocked and the app's
// own approval. The app's `handle_passkeys` switch still overrides all of it.
const POLICY_KEY = "passkeyPolicy";

async function policyFor(host) {
  if (!host) return "ask";
  try {
    const got = await api.storage.local.get(POLICY_KEY);
    const p = (got[POLICY_KEY] || {})[host.toLowerCase()];
    return p === "always" || p === "never" ? p : "ask";
  } catch (_e) {
    return "ask";
  }
}

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || typeof msg.cmd !== "string") return false;

  const tabId = sender.tab && sender.tab.id;

  switch (msg.cmd) {
    case "capturePending": {
      if (tabId == null) {
        sendResponse({ ok: true });
        return true;
      }
      // A re-stash sends back the age it already had. Without that, a login
      // that redirects three times would refresh the TTL at every hop and the
      // plaintext password would outlive its 90 seconds indefinitely.
      const now = Date.now();
      const ts =
        typeof msg.ts === "number" && msg.ts > 0 && msg.ts <= now
          ? msg.ts
          : now;
      if (now - ts >= PENDING_TTL_MS) {
        void dropPending(tabId);
        sendResponse({ ok: true });
        return true;
      }
      putPending(tabId, {
        candidate: {
          url: msg.url,
          username: msg.username,
          password: msg.password,
          // Set by the content script for a password Arca generated; the
          // post-navigation offer relaxes its gates for those.
          generated: !!msg.generated,
          // A manually entered new+confirm pair. It may land back on a login
          // form after navigation, but unlike a generated value it remains
          // bound to the same site.
          multiPassword: !!msg.multiPassword,
        },
        ts,
      }).then(() => sendResponse({ ok: true }));
      // Actively wipe the stored plaintext password after the TTL, so an
      // abandoned SPA login doesn't retain it indefinitely. The timer dies
      // with the worker, so the freshness check on read is the real guarantee
      // and this is just prompt cleanup.
      const timer = setTimeout(
        async () => {
          const e = await readPending(tabId);
          if (e && Date.now() - e.ts >= PENDING_TTL_MS) await dropPending(tabId);
        },
        Math.max(0, PENDING_TTL_MS - (now - ts)) + 500,
      );
      if (typeof timer?.unref === "function") timer.unref();
      return true;
    }

    case "consumePending":
      readPending(tabId).then(async (entry) => {
        await dropPending(tabId);
        const fresh = entry && Date.now() - entry.ts < PENDING_TTL_MS;
        // The age travels with the candidate: the content script re-stashes it
        // when the landing page cannot offer it yet, and the TTL has to keep
        // counting from the original submit.
        sendResponse({
          ok: true,
          candidate: fresh ? { ...entry.candidate, ts: entry.ts } : null,
        });
      });
      return true;

    case "clearPending":
      dropPending(tabId).then(() => sendResponse({ ok: true }));
      return true;

    case "gesture":
      recordGesture(tabId).then(() => sendResponse({ ok: true }));
      return true;

    case "passkeyProviderAvailable":
      // No credential ids or account metadata cross into the page. A probe
      // neither consumes a gesture nor asks for registration/verification.
      policyFor(msg.host).then(async (policy) => {
        if (policy === "never") return { available: false };
        const result = await sendNative({ type: "list_matching_logins", url: msg.url });
        return { available: !!(result?.ok && result.response?.app_connected) };
      }).then(sendResponse).catch(() => sendResponse({ available: false }));
      return true;

    case "passkeyAvailable":
      // A read-only fallback probe. It never spends a gesture or signs a
      // challenge, and must not hold up sites where Arca has no matching key.
      policyFor(msg.host).then(async (policy) => {
        if (policy === "never") return { available: false };
        const result = await sendNative({ type: "list_matching_logins", url: msg.url });
        return { available: !!(result?.ok && result.response?.items?.some(item => item.kind === "passkey")) };
      }).then(sendResponse).catch(() => sendResponse({ available: false }));
      return true;

    case "passkeyGate":
      // `msg.host` comes from the isolated content script's own `location`,
      // which the page cannot spoof — the same rule the ceremony's origin
      // already follows.
      policyFor(msg.host).then(async (policy) => {
        const version = api.runtime.getManifest().version;
        const reply = (allow, reason) =>
          sendResponse({ ok: true, allow, reason, version });

        if (policy === "never") {
          await clearGesture(tabId);
          reply(false, "site_never");
          return;
        }

        // REGISTRATION IS DIFFERENT, and this is the rule the GitHub prompt
        // loop kept walking through.
        //
        // A create() wants a gesture in the very document that fired it. A
        // site set to "always" never stands in for one: that is a user saying
        // "let Arca sign me in here", not consent to mint a new credential.
        // GitHub re-offers "add a passkey" on a timer, and with "always"
        // standing in, every offer became a Touch ID prompt on a machine whose
        // owner had done nothing.
        //
        // The tab-wide ledger stands in under ONE shape only: an ARRIVAL page.
        // Microsoft's "add a passkey" click lands on the account page, the
        // browser navigates to login.microsoft.com/…/fido/create, and THAT
        // document fires create() on load — nobody ever clicks in it, so the
        // old rule handed every one of those to the browser's QR dialog. An
        // arrival is a document the user has not touched, still within a few
        // seconds of load, with a fresh gesture carried from the page that led
        // here. GitHub's timer fires in a page that is old, touched, or both,
        // and the carried gesture is spent by the first ceremony regardless.
        // (The desktop app also asks before creating anything; this gate only
        // decides who gets to ask.)
        if (msg.isCreate) {
          if (msg.localGesture) {
            await clearGesture(tabId);
            reply(true, "gesture");
            return;
          }
          const arrival =
            !msg.sawLocal &&
            Number.isFinite(msg.documentAgeMs) &&
            msg.documentAgeMs >= 0 &&
            msg.documentAgeMs <= CREATE_ARRIVAL_WINDOW_MS;
          if (arrival) {
            const carried = await takeGesture(tabId);
            reply(carried, carried ? "gesture_carried" : "create_needs_local_gesture");
            return;
          }
          await clearGesture(tabId);
          reply(false, "create_needs_local_gesture");
          return;
        }

        if (policy === "always") {
          // An explicit per-site answer settles it; the gesture is spent either
          // way so it cannot leak into the next ceremony.
          await clearGesture(tabId);
          reply(true, "site_always");
          return;
        }
        if (msg.localGesture) {
          // The relay saw the gesture in this very document. Trust it directly
          // rather than racing our own "gesture" message to this worker.
          await clearGesture(tabId);
          reply(true, "gesture");
          return;
        }
        if (msg.sawLocal) {
          // The user HAS interacted with this document, and the relay's own
          // (tighter) window already said no. A gesture carried from the page
          // that navigated here is stale by construction once the user has
          // moved on, so the ledger must not be allowed to overrule that —
          // otherwise the in-document window silently widens to the carry TTL.
          await clearGesture(tabId);
          reply(false, "gesture_stale");
          return;
        }
        const carried = await takeGesture(tabId);
        reply(carried, carried ? "gesture_carried" : "no_gesture");
      });
      return true;
  }

  switch (msg.cmd) {
    case "hello":
      sendNative({
        type: "hello",
        version: api.runtime.getManifest().version,
        protocol: NATIVE_PROTOCOL,
      }).then(sendResponse);
      return true; // async response

    case "listLogins":
      sendNative({ type: "list_matching_logins", url: msg.url }).then(
        sendResponse,
      );
      return true;

    case "fill":
      // Returns { ok, response: { type: "credentials", username, password } }
      // only if the desktop app authorized it (unlocked + origin match).
      sendNative({ type: "fill", id: msg.id, url: msg.url }).then(sendResponse);
      return true;

    case "passkeyCreate":
      sendNative({
        type: "passkey_create",
        origin: msg.origin,
        rp_id: msg.rpId,
        user_name: msg.userName,
        user_handle: msg.userHandle,
        exclude_credentials: msg.excludeCredentials,
      }).then(sendResponse);
      return true;

    case "passkeyGet":
      sendNative({
        type: "passkey_get",
        origin: msg.origin,
        rp_id: msg.rpId,
        client_data_hash: msg.clientDataHash,
        allow_credentials: msg.allowCredentials,
        picked: !!msg.picked,
      }).then(sendResponse);
      return true;

    case "saveProbe":
      sendNative({
        type: "save_probe",
        url: msg.url,
        username: msg.username,
        password: msg.password,
      }).then(sendResponse);
      return true;

    case "requestUnlock":
      sendNative({ type: "request_unlock" }).then(sendResponse);
      return true;

    case "generatePassword":
      // No url and no id: generating reads nothing from the vault, so there is
      // nothing for the app to scope to an origin.
      sendNative({
        type: "generate_password",
        length: msg.length,
        symbols: msg.symbols,
      }).then(sendResponse);
      return true;

    // ── Bookmarks ─────────────────────────────────────────────────────────
    //
    // Both directions are driven from the popup, never on a timer. Push-out is
    // the only thing Arca does that can DESTROY something the vault cannot
    // restore — bookmarks live in the browser — so it does not happen while
    // nobody is looking.
    case "mirrorSetting":
      (async () => {
        if (typeof msg.allowed === "boolean") {
          await api.storage.local.set({ [MIRROR_ALLOWED_KEY]: msg.allowed });
          // Applied at once: turning it off should take the folder away now,
          // not at the next tick a minute from now.
          await reconcileMirror(msg.allowed ? "enabled" : "disabled");
        }
        const got = await api.storage.local.get(MIRROR_ALLOWED_KEY);
        sendResponse({ ok: true, allowed: got[MIRROR_ALLOWED_KEY] === true });
      })();
      return true;

    case "bookmarksToArca":
      readAll(api)
        .then((items) =>
          sendNative({
            type: "import_bookmarks",
            // Metadata only, and only what a bookmark is: no ids, no dates.
            items: items.map((b) => ({
              title: b.title,
              url: b.url,
              folder: b.folder,
            })),
          }),
        )
        .then((r) =>
          sendResponse(
            r.ok && r.response && r.response.type === "imported_bookmarks"
              ? { ok: true, added: r.response.added, read: true }
              : { ok: false, error: (r.response && r.response.message) || r.error },
          ),
        )
        .catch((e) => sendResponse({ ok: false, error: String(e) }));
      return true;

    case "bookmarksFromArca":
      sendNative({ type: "list_bookmarks" })
        .then(async (r) => {
          if (!r.ok || !r.response || r.response.type !== "bookmarks") {
            return {
              ok: false,
              error: (r.response && r.response.message) || r.error || "unavailable",
            };
          }
          // `deletions` and `confirmed` come from the popup, so removing
          // anything is always something a person chose twice.
          const res = await apply(api, r.response.items, {
            deletions: !!msg.deletions,
            confirmed: !!msg.confirmed,
          });
          return { ok: true, ...res };
        })
        .then(sendResponse)
        .catch((e) => sendResponse({ ok: false, error: String(e) }));
      return true;

    case "saveLogin":
      sendNative({
        type: "save_login",
        url: msg.url,
        username: msg.username,
        password: msg.password,
      }).then(sendResponse);
      return true;

    default:
      return false;
  }
});

// Drop a tab's pending-save candidate and unspent gesture when the tab closes.
api.tabs?.onRemoved?.addListener((tabId) => {
  void dropPending(tabId);
  void clearGesture(tabId);
});

// ── Arca's bookmark folder: cleanup ─────────────────────────────────────────
//
// The mirror is only ephemeral if it actually disappears. A browser that was
// force-quit, an Arca that crashed, a machine that lost power: in every one of
// those the folder is still sitting there next time the browser opens, and the
// whole point of the design is gone.
//
// So cleanup runs at STARTUP, before anything asks whether Arca is reachable.
// Not "clean up if the vault is locked" — clean up first, then let an unlocked
// Arca put the folder back. The failure that matters is the one where nothing
// gets to ask.
const OWNED_ID_KEY = "bookmarkFolderId";
const OWNED_IDS_KEY = "bookmarkFolderIds";
const OWNERSHIP_VERSION_KEY = "bookmarkOwnershipVersion";
const OWNERSHIP_VERSION = 2;
const MIRROR_STAMP_KEY = "bookmarkFingerprint";
const MIRROR_ALLOWED_KEY = "bookmarkMirrorAllowed";
/// When the first of an unbroken run of unreachable reads happened.
const MIRROR_MISS_KEY = "bookmarkUnreachableSince";


// Every event that can touch the mirror shares this queue. Browser event
// listeners are concurrent even though JavaScript itself is single-threaded:
// each `await` lets the next listener observe and mutate the same storage.
const runMirrorTask = serialExecutor();

function cleanupArcaBookmarks(why) {
  return runMirrorTask(() => cleanupArcaBookmarksOnce(why));
}

async function cleanupArcaBookmarksOnce(why) {
  // Nothing to clean where the permission was never granted — and the guard
  // comes before the import so a context without `bookmarks` (the test
  // harness, a browser that refused the permission) never loads the module.
  if (!api.bookmarks) return;
  let ownedId = null;
  let ownedIds = [];
  let ownershipVersion = null;
  try {
    const got = await api.storage.local.get([
      OWNED_ID_KEY,
      OWNED_IDS_KEY,
      OWNERSHIP_VERSION_KEY,
    ]);
    ownedId = got[OWNED_ID_KEY] ?? null;
    ownedIds = normaliseOwnedIds(got[OWNED_IDS_KEY], ownedId);
    ownershipVersion = got[OWNERSHIP_VERSION_KEY] ?? null;
  } catch (_e) {
    /* no record; the sweep below is all we have */
  }
  let tree;
  try {
    tree = await api.bookmarks.getTree();
  } catch (_e) {
    return;
  }
  const { remove, notes } = planCleanup({
    tree,
    ownedId,
    ownedIds,
    // One guarded pass repairs folders orphaned by the old single-id race.
    recoverRelated: ownershipVersion !== OWNERSHIP_VERSION,
  });
  const failed = new Set();
  for (const id of remove) {
    try {
      await whileApplying(() => api.bookmarks.removeTree(id));
    } catch (e) {
      failed.add(String(id));
      // Reported, not swallowed: a folder that will not go is the difference
      // between "ephemeral" and "permanent", and the user deserves to know
      // which one they have.
      console.warn(`[Arca] could not remove bookmark folder ${id}:`, e);
    }
  }
  // Never forget a folder that the browser refused to remove. Version 1 did
  // exactly that and converted a transient removeTree failure into a permanent
  // privacy leak. Re-read after the attempts so already-missing ids are safely
  // retired while live Arca folders remain owned for the next retry.
  const trackedIds = normaliseOwnedIds([...ownedIds, ...remove], ownedId);
  let remainingIds = trackedIds;
  try {
    const after = await api.bookmarks.getTree();
    const live = new Map();
    const index = (nodes) => {
      for (const node of nodes || []) {
        live.set(String(node.id), node);
        if (node.children) index(node.children);
      }
    };
    index(after);
    remainingIds = trackedIds.filter((id) => {
      const node = live.get(String(id));
      return node && !node.url && node.title === OWNED_FOLDER_TITLE;
    });
  } catch (_e) {
    // An unreadable tree is not evidence that a folder disappeared.
  }
  try {
    const forget = [MIRROR_STAMP_KEY];
    if (remainingIds.length > 0) {
      await api.storage.local.set({
        [OWNED_ID_KEY]: remainingIds[remainingIds.length - 1],
        [OWNED_IDS_KEY]: remainingIds,
      });
    } else {
      forget.push(OWNED_ID_KEY, OWNED_IDS_KEY);
    }
    if (failed.size === 0) {
      await api.storage.local.set({ [OWNERSHIP_VERSION_KEY]: OWNERSHIP_VERSION });
    }
    await api.storage.local.remove(forget);
  } catch (_e) {
    /* retain whatever ownership record storage accepted */
  }
  if (remove.length || notes.length) {
    console.debug(`[Arca] bookmark cleanup (${why}):`, { remove, notes });
    // Reported, not just console.debug'd. This was the last step in the chain
    // that said nothing: the log could show the lock being detected and the
    // cleanup being called, and still not answer whether the folder actually
    // went away — which is the only part the user can see.
    report(
      "info",
      `cleanup (${why}): removed ${remove.length}` +
        (notes.length ? ` — ${notes.join("; ")}` : ""),
    );
  } else {
    report("info", `cleanup (${why}): nothing to remove`);
  }
}

// Browser start, and extension install/update/reload. Between them these cover
// every way a session can begin holding a folder from a session that ended
// badly.
api.runtime.onStartup?.addListener(() => cleanupArcaBookmarks("browser startup"));
api.runtime.onInstalled?.addListener(() => cleanupArcaBookmarks("extension loaded"));
// NOT on plain worker start, and this was a real bug.
//
// A service worker is evicted whenever it goes idle and woken for the next
// alarm — many times an hour. Cleaning on every wake meant: wake, delete the
// folder, forget the recorded id, tick, rebuild all 128, sleep, repeat. The
// log showed `mirrored 128 bookmarks` once a minute forever, and the
// fingerprint that exists to prevent exactly that never got a chance, because
// its stored value was thrown away moments earlier.
//
// A worker waking up is not a new session. `onStartup` covers a browser that
// has actually restarted, `onInstalled` covers install, update and reload, and
// between them every way a session can begin holding a stale folder is already
// covered.

/// Write Arca's list into the browser, or take it away. One reconcile, driven
/// by ONE question.
///
/// `list_bookmarks` needs an unlocked vault, so its answer decides both
/// directions at once: a list means write, a refusal means remove. There is no
/// separate "is Arca unlocked" call to disagree with it, and no push channel
/// from the app that could be missed — the extension asks, and what it gets
/// back is the whole truth about what should be on screen.
function reconcileMirror(why) {
  return runMirrorTask(() => reconcileMirrorOnce(why));
}

async function reconcileMirrorOnce(why) {
  if (!api.bookmarks) return;

  const answer = await sendNative({ type: "list_bookmarks" });
  const items =
    answer.ok && answer.response && answer.response.type === "bookmarks"
      ? answer.response.items || []
      : null;

  const store = await readMirrorState();

  // Locked, quit, or unreachable. Every one of those means the same thing to a
  // user looking at their bookmarks bar, so they get the same answer.
  if (items === null) {
    const verdict = vaultVerdict({
      ok: answer.ok,
      message: answer.response && answer.response.message,
      error: answer.error,
      missSince: store.missSince,
      now: Date.now(),
    });
    if (verdict.reason !== "locked") {
      await api.storage.local.set({ [MIRROR_MISS_KEY]: verdict.since });
    }
    if (verdict.action === "wait") {
      report(
        "info",
        `mirror unreachable (${why}) — ${verdict.reason}; leaving the folder alone for now`,
      );
      return;
    }
    if (verdict.reason !== "locked") {
      report("info", `mirror gone (${why}): still silent after grace — ${verdict.reason}`);
      if (store.ids.length > 0) await cleanupArcaBookmarksOnce(`no vault (${why})`);
      return;
    }

    // Logged, and this omission is the whole reason the feature looked broken
    // for an hour. A locked vault is the COMMONEST reason for no bookmarks and
    // it was the one path that returned in silence — so "nothing in the log"
    // meant both "not running" and "running and correctly doing nothing", and
    // there was no way to tell them apart from here.
    report(
      "info",
      `mirror idle (${why}): Arca is locked — taking the folder down`,
    );
    if (store.ids.length > 0) await cleanupArcaBookmarksOnce(`no vault (${why})`);
    return;
  }

  // Arca answered, so whatever silence came before it is over. Left set, one
  // old blip would age past the grace period and delete the folder during a
  // perfectly healthy run.
  if (store.missSince != null) await api.storage.local.remove(MIRROR_MISS_KEY);

  // The sync guard, checked AFTER the cleanup branch above and BEFORE anything
  // is written. Turning the guard on while a folder is already on screen must
  // still take that folder away — a gate that also blocked removal would
  // strand exactly the bookmarks it exists to keep out of a cloud.
  const gate = mirrorGate({ allowed: store.allowed });
  if (!gate.allow) {
    report("info", `mirror skipped (${why}): ${gate.reason}`);
    if (store.ids.length > 0) await cleanupArcaBookmarksOnce(`mirroring off (${why})`);
    return;
  }

  const stamp = fingerprint(items);
  if (
    store.ids.length === 1 &&
    store.id != null &&
    store.fingerprint === stamp &&
    (await recordedMirrorExists(store.id))
  ) return; // already right

  // Rebuild rather than diff. The folder is Arca's own, so throwing it away
  // costs nothing, and a full rebuild cannot drift the way a patch can.
  await cleanupArcaBookmarksOnce(`rebuilding (${why})`);

  const { root, used, dropped } = buildTree(items);
  let folderId;
  try {
    // Resolved from the tree, not assumed. Chromium's bar is "1" and Firefox's
    // is "toolbar_____"; a hardcoded parent is why this wrote nothing at all
    // in Firefox while reporting success.
    const barId = barRootId(await api.bookmarks.getTree());
    const folder = await whileApplying(() =>
      api.bookmarks.create({ parentId: barId, title: OWNED_FOLDER_TITLE }),
    );
    folderId = folder.id;
    // Recorded BEFORE the contents go in. If the browser dies halfway through
    // this, the next startup still knows which folder was ours and can remove
    // it; recording it afterwards would leave a half-built orphan nothing owns.
    const beforeWrite = await readMirrorState();
    const nextOwnedIds = normaliseOwnedIds([...beforeWrite.ids, folderId], folderId);
    await api.storage.local.set({
      [OWNED_ID_KEY]: folderId,
      [OWNED_IDS_KEY]: nextOwnedIds,
      [OWNERSHIP_VERSION_KEY]: OWNERSHIP_VERSION,
    });
    await whileApplying(() => writeNode(root, folderId));
    await api.storage.local.set({ [MIRROR_STAMP_KEY]: stamp });
  } catch (e) {
    console.warn("[Arca] could not mirror bookmarks:", e);
    report("error", `mirror failed (${why}): ${(e && e.stack) || e}`);
    await cleanupArcaBookmarksOnce("mirror failed");
    return;
  }
  const summary =
    `mirrored ${used} bookmarks (${why})` +
    (dropped ? `, ${dropped} not mirrorable` : "");
  console.debug(`[Arca] ${summary}`);
  report("info", summary);
}

// Are WE the ones changing bookmarks right now?
//
// A rebuild deletes and recreates 128 bookmarks, and every one of those fires
// the same `onCreated` a person firing does. Without this, capturing what the
// user adds would immediately capture everything Arca itself writes, on every
// rebuild, forever.
//
// A COUNTER, not a boolean: cleanup and a rebuild overlap, and a boolean would
// be cleared by whichever finished first while the other was still writing.
let applying = 0;
async function whileApplying(fn) {
  applying++;
  try {
    return await fn();
  } finally {
    applying--;
  }
}

/// Is `id` inside Arca's folder? Walks up, because an event carries a parent
/// id and nothing about how deep it sits.
async function insideOwnedFolder(id, ownedId) {
  if (!ownedId) return false;
  let cursor = id;
  for (let hop = 0; hop < 32 && cursor; hop++) {
    if (String(cursor) === String(ownedId)) return true;
    let node;
    try {
      [node] = await api.bookmarks.get(String(cursor));
    } catch (_e) {
      return false;
    }
    if (!node || !node.parentId) return false;
    cursor = node.parentId;
  }
  return false;
}

/// Depth-first creation. Folders before their contents, in the order buildTree
/// settled on.
async function writeNode(node, parentId) {
  for (const entry of creationOrder(node)) {
    if (entry.kind === "link") {
      const link = entry.value;
      await api.bookmarks.create({ parentId, title: link.title, url: link.url });
    } else {
      const child = entry.value;
      const made = await api.bookmarks.create({ parentId, title: child.name });
      await writeNode(child, made.id);
    }
  }
}

async function readMirrorState() {
  try {
    const got = await api.storage.local.get([
      OWNED_ID_KEY,
      OWNED_IDS_KEY,
      OWNERSHIP_VERSION_KEY,
      MIRROR_STAMP_KEY,
      MIRROR_ALLOWED_KEY,
      MIRROR_MISS_KEY,
    ]);
    const id = got[OWNED_ID_KEY] ?? null;
    return {
      id,
      ids: normaliseOwnedIds(got[OWNED_IDS_KEY], id),
      ownershipVersion: got[OWNERSHIP_VERSION_KEY] ?? null,
      fingerprint: got[MIRROR_STAMP_KEY] ?? null,
      missSince: got[MIRROR_MISS_KEY] ?? null,
      // Absent means NOT allowed. A missing setting must never read as consent.
      allowed: got[MIRROR_ALLOWED_KEY] === true,
    };
  } catch (_e) {
    // Unreadable storage is not permission either.
    return {
      id: null,
      ids: [],
      ownershipVersion: null,
      fingerprint: null,
      allowed: false,
      missSince: null,
    };
  }
}

function normaliseOwnedIds(value, extra = null) {
  const values = Array.isArray(value) ? [...value] : value == null ? [] : [value];
  if (extra != null) values.push(extra);
  return values
    .filter((id) => id != null)
    .map(String)
    .filter((id, index, all) => all.indexOf(id) === index);
}

async function recordedMirrorExists(id) {
  try {
    const [node] = await api.bookmarks.get(String(id));
    return !!node && !node.url && node.title === OWNED_FOLDER_TITLE;
  } catch (_e) {
    return false;
  }
}
