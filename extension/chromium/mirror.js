// Turning Arca's list into the folder tree a browser shows.
//
// The ephemeral mirror: Arca's bookmarks exist in the browser only while Arca
// is unlocked. This file is the pure half — flat list in, tree out, plus a
// summary that says whether anything actually changed. No browser API is
// touched here, so the shape of what appears in someone's bookmarks bar is
// decided by code that can be tested without a browser.
//
// Cleanup lives in bookmarks.js next door, and runs first: see `planCleanup`.

/// Most bookmarks Arca will mirror into a browser in one pass.
///
/// Every one is a separate `bookmarks.create` call, and a few thousand of those
/// on every unlock is a visibly janky browser. A collection past this needs
/// paging, not a bigger number set quietly.
export const MAX_MIRRORED = 2000;

/// Deepest folder nesting recreated. Same reason as the desktop importer's cap:
/// the recursion has to end somewhere that is not the stack.
export const MAX_MIRROR_DEPTH = 16;

/// Increment whenever creation order/shape changes. It is part of the stored
/// fingerprint so an already-current mirror is rebuilt after an upgrade.
export const MIRROR_LAYOUT_VERSION = 2;

/// Run asynchronous operations one at a time, in the order they were asked for.
///
/// A service worker may receive an alarm, a window-focus event and a tab event
/// together.  The browser does not serialize those listeners for us.  Two
/// mirror passes used to both observe "no folder", both create one, and then
/// overwrite the single stored owner id.  The loser became a permanent,
/// non-empty Arca folder that locking could no longer prove it owned.
///
/// A failed operation is still returned to its caller, but does not poison the
/// tail: cleanup must get another chance after one transient browser error.
export function serialExecutor() {
  let tail = Promise.resolve();
  return (operation) => {
    const run = tail.then(operation, operation);
    tail = run.catch(() => {});
    return run;
  };
}

/// Whether this is a URL worth putting in a browser at all.
///
/// Deliberately the same rule the importer uses. `javascript:` bookmarklets are
/// executable code and `chrome://` pages mean nothing outside the browser that
/// wrote them; neither belongs in a list Arca hands to an arbitrary browser.
function isWebUrl(url) {
  const lower = String(url || "").trim().toLowerCase();
  return lower.startsWith("http://") || lower.startsWith("https://");
}

/// Turn Arca's flat list into the folder tree to create.
///
/// The only place path-splitting happens. Sorted at every level, so the folder
/// looks the same each time it appears — a list that reshuffles on every unlock
/// reads as corruption even when nothing is wrong.
export function buildTree(bookmarks) {
  const root = { name: "", folders: new Map(), links: [] };
  let used = 0;
  let dropped = 0;

  for (const b of bookmarks || []) {
    if (!b || !isWebUrl(b.url)) {
      dropped++;
      continue;
    }
    if (used >= MAX_MIRRORED) {
      dropped++;
      continue;
    }
    const parts = String(b.folder || "")
      .split("/")
      .map((p) => p.trim())
      .filter(Boolean)
      .slice(0, MAX_MIRROR_DEPTH);
    let node = root;
    for (const part of parts) {
      if (!node.folders.has(part)) {
        node.folders.set(part, { name: part, folders: new Map(), links: [] });
      }
      node = node.folders.get(part);
    }
    node.links.push({ title: b.title || b.url, url: b.url });
    used++;
  }

  const sortNode = (node) => {
    node.links.sort((a, c) => a.title.localeCompare(c.title));
    node.folders = new Map(
      [...node.folders.entries()].sort(([a], [c]) => a.localeCompare(c)),
    );
    for (const child of node.folders.values()) sortNode(child);
  };
  sortNode(root);

  return { root, used, dropped };
}

/// Browser creation order for one level of the mirror.
///
/// Bookmark APIs append new nodes. Returning all folders first is therefore
/// what makes folders appear above loose bookmarks in Chromium and Brave; the
/// alphabetical sorting inside each group was already settled by buildTree.
export function creationOrder(node) {
  return [
    ...[...(node?.folders?.values() || [])].map((value) => ({ kind: "folder", value })),
    ...(node?.links || []).map((value) => ({ kind: "link", value })),
  ];
}

/// A cheap, stable summary of what Arca holds.
///
/// The mirror is rebuilt only when this changes. Without it, every reconcile
/// tick would tear the folder down and build it again — which flickers in the
/// bookmarks bar and throws away the user's place in it, for nothing.
export function fingerprint(bookmarks) {
  const parts = (bookmarks || [])
    .map((b) => [b.folder || "", b.title || "", b.url || ""].join("\0"))
    .sort();
  const s = parts.join("\u0001");
  // djb2. Not cryptographic and not trying to be: this compares a list against
  // its own previous self on one machine, and a collision costs a redundant
  // rebuild, not a wrong answer.
  let h = 5381;
  for (let i = 0; i < s.length; i++) {
    h = (Math.imul(h, 33) + s.charCodeAt(i)) | 0;
  }
  return `v${MIRROR_LAYOUT_VERSION}-${parts.length}-${(h >>> 0).toString(16)}`;
}

/// May the mirror be written into this browser at all?
///
/// THE RISK THIS GUARDS. If the browser's own bookmark sync is on, every
/// bookmark Arca writes is uploaded to Google or Brave and kept there. They
/// would then be neither temporary nor private, and the feature would achieve
/// the exact opposite of its purpose — silently, and on a server the user
/// cannot clean.
///
/// WHY THIS ASKS INSTEAD OF DETECTING. There is no extension API that reports
/// whether the browser syncs bookmarks. `storage.sync` is the extension's own
/// storage area, not the browser's setting, and a signed-in account does not
/// mean bookmarks are among the things being synced. The one thing worse than
/// asking would be a detection that looks authoritative and is a guess: the
/// user would trust it, and be wrong without ever being told.
///
/// So writing is OFF until the user says otherwise, in as many words. Cleanup
/// is never gated — see the caller — because a folder already on screen must
/// still be removable after the guard goes up.
export function mirrorGate({ allowed }) {
  if (allowed !== true) {
    return {
      allow: false,
      reason:
        "waiting for confirmation that this browser's own bookmark sync is off",
    };
  }
  return { allow: true, reason: "confirmed" };
}

/// How long Arca must stay SILENT before its folder is taken down.
///
/// A locked vault is removed instantly — that is the feature, and the app says
/// "locked" in as many words. This grace period is only for silence, which a
/// quit app and a momentary blip produce alike.
export const UNREACHABLE_GRACE_MS = 20000;

/// What to do when a bookmark read did not come back with a list.
///
/// THE BUG THIS EXISTS TO PREVENT. The old code treated locked, quit and
/// unreachable as one thing, on the reasoning that they look identical to
/// someone staring at their bookmarks bar. They do — but they are not
/// identical to the FOLDER: a single missed read deleted it, the next tick
/// rebuilt it, and a bookmark saved in between was destroyed. From the outside
/// that was "saving in the Arca folder doesn't work".
///
/// So: remove on knowledge, wait on silence. `locked` is the app stating its
/// own state. Anything else — no answer, a transport failure, a message we do
/// not recognise — is an absence of information, and absence is not grounds to
/// delete someone's bookmarks.
export function vaultVerdict({ ok, message, error, missSince, now }) {
  const reason = (ok ? message : error) || "refused";
  if (ok && reason === "locked") return { action: "remove", reason: "locked" };
  const since = missSince || now;
  return now - since < UNREACHABLE_GRACE_MS
    ? { action: "wait", reason, since }
    : { action: "remove", reason, since };
}
