// Bookmarks: reading a browser's tree, and applying Arca's list back to it.
//
// Arca is the master list and this pushes it out. That makes this the only
// code in the extension that can DESTROY something the user cares about, and
// bookmarks are not recoverable from a password vault's snapshot the way a
// login is — they live in the browser.
//
// So the reconciler is a pure function. `plan()` takes what the browser has and
// what Arca has and returns what it WOULD do, including a refusal; nothing in
// it touches a browser API. Everything worth arguing about is therefore
// testable without a browser, which is the only way the guards below can be
// trusted.

// Root node ids, per browser. Chromium numbers them; Firefox uses padded
// names. Hardcoding Chromium's "1" as the bookmarks bar is why the mirror wrote
// nothing at all in Firefox — `create({parentId:"1"})` there either fails or
// lands somewhere nobody looks.
//
// Every set holds BOTH spellings, so one lookup answers for either browser and
// there is no per-browser branch anywhere else in this file.
export const ROOT_SETS = {
  bar: new Set(["1", "toolbar_____"]),
  other: new Set(["2", "unfiled_____"]),
  mobile: new Set(["3", "mobile______"]),
  // Firefox only. Chromium has no separate menu root.
  menu: new Set(["menu________"]),
  tree: new Set(["0", "root________"]),
};

/// The label a root contributes to a folder path, or null if `id` is not a root.
///
/// The bar contributes NOTHING: prefixing every bookmark with the bar's name
/// adds a level that means nothing, and that name is localised anyway.
export function rootLabel(id) {
  const key = String(id);
  if (ROOT_SETS.bar.has(key)) return "";
  if (ROOT_SETS.other.has(key)) return "Other";
  if (ROOT_SETS.mobile.has(key)) return "Mobile";
  if (ROOT_SETS.menu.has(key)) return "Menu";
  return null;
}

/// Every root id, in either browser. Nothing here may ever be removed.
export const ROOT_IDS = new Set([
  ...ROOT_SETS.tree,
  ...ROOT_SETS.bar,
  ...ROOT_SETS.other,
  ...ROOT_SETS.mobile,
  ...ROOT_SETS.menu,
]);

/// This browser's bookmarks-bar id, read from a real tree rather than assumed.
///
/// Falls back to Chromium's "1" only when the tree tells us nothing, which
/// keeps the old behaviour for a browser neither list anticipates.
export function barRootId(tree) {
  const seen = [];
  const walk = (nodes) => {
    for (const n of nodes || []) {
      seen.push(String(n.id));
      if (n.children) walk(n.children);
    }
  };
  walk(tree);
  return seen.find((id) => ROOT_SETS.bar.has(id)) ?? "1";
}

/// Flatten a `chrome.bookmarks` tree into `{title, url, folder, id}`.
///
/// The three root nodes have fixed ids in every Chromium browser: 1 is the bar,
/// 2 is "other", 3 is mobile. Their own names are localised, so they are mapped
/// by id and their names never enter a path — matching what the desktop's
/// importer does with the same tree read from disk.
export function flatten(nodes, folder = null, out = []) {
  for (const node of nodes || []) {
    if (node.url) {
      // `javascript:` and `chrome://` are dropped for the same reason the
      // desktop importer drops them: executable code and browser-internal
      // pages do not belong in a list meant to be carried between browsers.
      if (!isWebUrl(node.url)) continue;
      out.push({
        id: node.id,
        title: node.title || node.url,
        url: node.url,
        folder: folder ?? "",
        // Enterprise policy and the roots themselves are read-only; a plan that
        // tries to remove one fails the whole batch at apply time.
        unmodifiable: !!node.unmodifiable,
      });
    } else if (node.children) {
      const label =
        folder === null
          ? (rootLabel(node.id) ?? node.title ?? "")
          : joinFolder(folder, node.title || "");
      flatten(node.children, label, out);
    }
  }
  return out;
}

function joinFolder(parent, name) {
  const safe = String(name).replace(/\//g, "-");
  if (!parent) return safe;
  if (!safe) return parent;
  return `${parent}/${safe}`;
}

function isWebUrl(url) {
  const u = String(url).trim().toLowerCase();
  return u.startsWith("http://") || u.startsWith("https://");
}

/** Identity of a bookmark for reconciliation: the same page filed in two
 *  folders is deliberately two bookmarks, because someone filed it twice. */
const key = (b) => `${b.folder}\0${b.url}`;

// ── The guards ──────────────────────────────────────────────────────────────
//
// A sync bug here empties the bookmark bar in every browser at once, and the
// user finds out days later. These exist so that the failure needs a human to
// agree to it.

/// Below this many removals, a deletion pass is ordinary tidying.
const ALWAYS_ALLOWED_REMOVALS = 10;

/// Above this share of the browser's bookmarks, a deletion pass is a bug until
/// proven otherwise.
const MAX_REMOVAL_FRACTION = 0.2;

/**
 * What applying `master` to `current` would do.
 *
 * Returns `{ additions, removals, refused }`. `refused` is a string reason when
 * the plan is too destructive to run unattended; the caller may re-run with
 * `{ confirmed: true }` once a human has seen the numbers.
 *
 * Additions are always safe and are never refused — a refusal blocks only the
 * removals, so a suspicious plan still adds what is missing instead of doing
 * nothing at all.
 */
export function plan(current, master, opts = {}) {
  const { deletions = false, confirmed = false } = opts;

  const currentByKey = new Map();
  for (const b of current) currentByKey.set(key(b), b);
  const masterKeys = new Set(master.map(key));

  const additions = master.filter((b) => !currentByKey.has(key(b)));

  if (!deletions) {
    return { additions, removals: [], refused: null };
  }

  // An EMPTY master is never an instruction to wipe the browser. It is a locked
  // vault, a failed read, or an import that has not run yet — and every one of
  // those would otherwise clear the bookmark bar completely.
  if (master.length === 0) {
    return {
      additions,
      removals: [],
      refused: "Arca's bookmark list is empty; refusing to clear the browser.",
    };
  }

  const removals = current.filter(
    (b) => !masterKeys.has(key(b)) && !b.unmodifiable,
  );

  const ceiling = Math.max(
    ALWAYS_ALLOWED_REMOVALS,
    Math.floor(current.length * MAX_REMOVAL_FRACTION),
  );
  if (!confirmed && removals.length > ceiling) {
    return {
      additions,
      removals: [],
      refused:
        `This would remove ${removals.length} of ${current.length} bookmarks ` +
        `from the browser. Confirm before Arca does that.`,
      pendingRemovals: removals.length,
    };
  }

  return { additions, removals, refused: null };
}

// ── Browser glue ────────────────────────────────────────────────────────────

/** Read every bookmark in this browser, flattened. */
export async function readAll(api) {
  const tree = await api.bookmarks.getTree();
  // getTree() returns a single unnamed super-root whose children are the real
  // roots; starting at its children is what makes the id-based root mapping in
  // `flatten` line up.
  const roots = (tree && tree[0] && tree[0].children) || [];
  return flatten(roots);
}

/**
 * Apply Arca's list. Returns `{ added, removed, refused }`.
 *
 * Failures on individual nodes are counted, not thrown: one bookmark in a
 * policy-managed folder must not abort the other nine hundred.
 */
export async function apply(api, master, opts = {}) {
  const current = await readAll(api);
  const p = plan(current, master, opts);

  // Where the bar is in THIS browser, read once from the real tree.
  const barId = barRootId(await api.bookmarks.getTree());
  const folders = new Map(); // folder path -> node id
  let added = 0;
  for (const b of p.additions) {
    try {
      const parentId = await ensureFolder(api, b.folder, folders, barId);
      await api.bookmarks.create({ parentId, title: b.title, url: b.url });
      added++;
    } catch (_e) {
      /* a managed folder, or a URL the browser rejects */
    }
  }

  let removed = 0;
  for (const b of p.removals) {
    try {
      await api.bookmarks.remove(b.id);
      removed++;
    } catch (_e) {
      /* already gone, or not ours to remove */
    }
  }

  return { added, removed, refused: p.refused, pendingRemovals: p.pendingRemovals };
}

/** The node id for a folder path, creating the missing levels. */
async function ensureFolder(api, folder, cache, barId) {
  // `barId` is passed in, never assumed: Chromium calls the bar "1" and Firefox
  // calls it "toolbar_____", and a wrong parent is a create that silently lands
  // nowhere the user looks.
  if (!folder) return barId;
  if (cache.has(folder)) return cache.get(folder);

  const parts = folder.split("/");
  let parentId = barId;
  let sofar = "";
  for (const part of parts) {
    sofar = sofar ? `${sofar}/${part}` : part;
    if (cache.has(sofar)) {
      parentId = cache.get(sofar);
      continue;
    }
    const children = await api.bookmarks.getChildren(parentId);
    const hit = (children || []).find((c) => !c.url && c.title === part);
    if (hit) {
      parentId = hit.id;
    } else {
      const made = await api.bookmarks.create({ parentId, title: part });
      parentId = made.id;
    }
    cache.set(sofar, parentId);
  }
  return parentId;
}

// ── The ephemeral mirror ────────────────────────────────────────────────────
//
// A different model from the push-out above, and a better one: Arca's bookmarks
// live in the browser ONLY while Arca is unlocked. The browser becomes a window
// onto the vault rather than a second copy of it.
//
// What makes it safe is ownership. Arca creates ONE folder and owns everything
// inside it; nothing outside is ever touched. Emptying a folder you created is
// not a destructive act, so the thresholds that guard the push-out — ten
// removals, a fifth of the tree — have nothing to guard here. The boundary is
// enforceable instead of estimated.

/// The folder Arca creates. Shown to the user, so it is a plain name.
export const OWNED_FOLDER_TITLE = "Arca";

/// The bookmark-bar root. Fixed in every Chromium browser.
/// What cleanup would do. Pure: `tree` is a `chrome.bookmarks` forest and
/// `ownedIds` are the ids recorded when folders were created. `ownedId` is the
/// legacy single-id spelling and remains accepted during migration.
///
/// THREE RULES, and the last two are deliberately narrow.
///
///   1. The folder whose id we RECORDED is ours by construction. Remove it,
///      whatever it contains. `storage.local` survives browser restarts and
///      extension reloads, so this covers every crash worth covering.
///
///   2. During the one-time v1 migration, a non-empty folder is recovered only
///      when its generated contents almost exactly match a recorded folder.
///
///   3. A folder that merely LOOKS like ours is removed only when it is EMPTY.
///      After the extension is reinstalled the recorded id is gone, and a
///      leftover folder is all that remains — but "it has our name" is not
///      proof it is ours. A user may have made their own. An empty shell costs
///      nothing to remove and nothing to lose; one with bookmarks in it is
///      reported and left alone, because the alternative is deleting someone's
///      bookmarks on a guess.
export function planCleanup({
  tree,
  ownedId = null,
  ownedIds = [],
  recoverRelated = false,
}) {
  const remove = [];
  const notes = [];
  const byId = new Map();
  const index = (nodes) => {
    for (const n of nodes || []) {
      byId.set(String(n.id), n);
      if (n.children) index(n.children);
    }
  };
  index(tree);

  const removable = (node) => {
    if (!node) return false;
    if (ROOT_IDS.has(String(node.id))) return false;
    // Enterprise-policy folders refuse removal, and a failed remove aborts the
    // whole batch — so one of these would take the real cleanup down with it.
    if (node.unmodifiable) return false;
    return true;
  };

  const recordedIds = [ownedId, ...(Array.isArray(ownedIds) ? ownedIds : [])]
    .filter((id) => id != null)
    .map(String)
    .filter((id, index, all) => all.indexOf(id) === index);
  const ownedNodes = [];

  for (const recordedId of recordedIds) {
    const owned = byId.get(recordedId);
    // The TITLE is checked as well as the id, and that is not belt-and-braces.
    // Chromium reuses bookmark ids within a profile after a deletion, so an id
    // recorded weeks ago can come to point at a folder the user made
    // yesterday. The id says "this was ours"; the title says "and it still is".
    if (owned && owned.title !== OWNED_FOLDER_TITLE) {
      notes.push(
        `recorded id ${owned.id} now points at "${owned.title}" — id reused, leaving it alone`,
      );
    } else if (owned && owned.url) {
      notes.push(`recorded id ${owned.id} is a bookmark, not our folder`);
    } else if (owned && removable(owned)) {
      remove.push(String(owned.id));
      ownedNodes.push(owned);
      notes.push(`owned folder ${owned.id}`);
    } else if (owned) {
      notes.push(`owned folder ${owned.id} is not removable`);
    }
  }

  // Version-1 stored only ONE id. Concurrent reconciles could each create an
  // Arca folder and then overwrite that value; locking removed the winner and
  // stranded the others. During the ownership-v2 migration, a recorded folder
  // is an anchor from which those old copies can be identified safely.
  //
  // This is intentionally narrow:
  //   * exact title and top level of the bookmarks bar;
  //   * at least 20 ordinary web bookmarks, with no duplicate/foreign nodes;
  //   * at least 98% overlap and no material size difference;
  //   * and a live, recorded folder to compare against.
  // A personal folder merely called "Arca" therefore remains untouched.
  if (recoverRelated && ownedNodes.length > 0) {
    const bar = byId.get(barRootId(tree));
    const anchors = ownedNodes.map(mirrorShape).filter(Boolean);
    for (const child of (bar && bar.children) || []) {
      if (remove.includes(String(child.id))) continue;
      if (child.url || child.title !== OWNED_FOLDER_TITLE || !removable(child)) continue;
      const candidate = mirrorShape(child);
      if (!candidate) continue;
      if (!anchors.some((anchor) => mirrorShapesMatch(anchor, candidate))) continue;
      remove.push(String(child.id));
      notes.push(`recovered related folder ${child.id}`);
    }
  }

  // The timid sweep: top level of the bar only, exact title, empty only.
  const bar = byId.get(barRootId(tree));
  for (const child of (bar && bar.children) || []) {
    if (remove.includes(String(child.id))) continue;
    if (child.url) continue; // a bookmark, not a folder
    if (child.title !== OWNED_FOLDER_TITLE) continue;
    const childCount = (child.children || []).length;
    if (childCount === 0 && removable(child)) {
      remove.push(String(child.id));
      notes.push(`empty leftover ${child.id}`);
    } else if (childCount > 0) {
      notes.push(
        `left a non-empty "${OWNED_FOLDER_TITLE}" folder (${child.id}, ${childCount} items) alone — not provably ours`,
      );
    }
  }

  return { remove, notes };
}

/// Canonical contents of a folder generated by the mirror, or null when the
/// shape contains something the generator itself would never have written.
function mirrorShape(root) {
  const entries = new Set();
  let urlCount = 0;
  let valid = true;
  const walk = (node, folder) => {
    for (const child of node.children || []) {
      if (child.url) {
        urlCount++;
        if (!isWebUrl(child.url)) {
          valid = false;
          continue;
        }
        entries.add(`${folder}\0${child.title || child.url}\0${child.url}`);
        continue;
      }
      // buildTree never emits an empty folder.
      if (!child.children || child.children.length === 0) {
        valid = false;
        continue;
      }
      const name = String(child.title || "");
      walk(child, folder ? `${folder}/${name}` : name);
    }
  };
  walk(root, "");
  // A Set collapsing two nodes is another shape buildTree cannot produce: the
  // vault de-duplicates bookmarks by folder + URL before they reach this code.
  if (!valid || urlCount < 20 || entries.size !== urlCount) return null;
  return entries;
}

function mirrorShapesMatch(a, b) {
  const larger = Math.max(a.size, b.size);
  const smaller = Math.min(a.size, b.size);
  if (larger - smaller > Math.max(2, Math.ceil(larger * 0.05))) return false;
  let common = 0;
  const [left, right] = a.size <= b.size ? [a, b] : [b, a];
  for (const entry of left) if (right.has(entry)) common++;
  return common / smaller >= 0.98;
}
