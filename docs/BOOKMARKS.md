# Bookmarks

Arca holds the master list of bookmarks and pushes it out to browsers. It is
not a two-way sync, and that is a decision rather than a stage: two-way means
reconciling a folder tree with moves, renames and deletions on both sides, and
the vault's merge already loses the older edit when two devices touch the same
item. Bookmarks would exercise that far harder than passwords do.

So: import once from each browser to seed the list, edit in Arca, write it back.
A bookmark changed directly in a browser is overwritten the next time the list
is written there.

## Where bookmarks come from

Two routes, and the first one is the real one.

### The extension (primary)

`chrome.bookmarks` gives read and write access to Chrome, Brave, Edge, Vivaldi,
Opera and Firefox, with no file paths, no per-OS profile hunting, and no
permission prompt beyond the one the extension already asks for. Both directions
are buttons in the popup.

### The file reader (`apps/desktop/src-tauri/src/bookmarks.rs`)

Reads Chromium's `Bookmarks` JSON straight off disk. This is the path on **Linux
and Windows** where it works with no permission at all.

On **macOS it is mostly unusable**, and that was measured rather than assumed:
reading another app's `~/Library/Application Support/<app>` returns EPERM
without Full Disk Access. Asking the user of a password manager to grant Full
Disk Access, so it can read files an extension hands over for free, is a bad
trade. The reader stays because Linux and Windows have no such wall, and because
Safari will eventually need it.

### Safari

Safari web extensions have **no bookmarks API at all**. Safari can only ever be
a read source, via `~/Library/Safari/Bookmarks.plist`, and that needs Full Disk
Access too. Nothing can write bookmarks into Safari.

## Folders are paths, not trees

A bookmark stores `folder` as `"Bar/Arbeid/Kunder"`. The vault has no hierarchy
and does not want one: a tree here would mean node ids, parent pointers and
reparenting rules in a store that has no other use for them. A path sorts
naturally, survives browsers whose root folders are named in different
languages, and is rebuilt into a tree on the way out.

The three Chromium roots are mapped by **id** (1 = the bar, 2 = other, 3 =
mobile), never by name, because their names are localised. The bar's own name is
dropped so its contents sit at the top level.

## What is deliberately not carried

`javascript:` bookmarklets and `chrome://` pages. One is executable code and the
other means nothing in a different browser; carrying either between browsers is
useless at best.

## The deletion guards

Push-out is the only thing Arca does that can destroy something the vault cannot
restore. Bookmarks live in the browser, so a snapshot of the vault does not get
them back. Three guards, all in `extension/chromium/bookmarks.js` and all
covered by `extension/test/bookmarks.test.mjs`:

1. **Deletions are off by default.** Additions never need permission; removing
   anything needs the checkbox in the popup.
2. **An empty master list never clears a browser.** A locked vault, a failed
   read and an import that has not run yet all look like "Arca has no
   bookmarks", and none of them mean "delete everything".
3. **A large removal needs a human.** Above ten removals *and* a fifth of the
   browser's bookmarks, the pass refuses and reports the numbers; the popup then
   asks with those numbers in the question. Below that, ordinary tidying goes
   through unattended — a confirmation that fires every time is one people learn
   to click through.

Bookmarks marked `unmodifiable` (enterprise policy, and the roots themselves)
are never proposed for removal.

## Identity

A bookmark is identified by **folder plus URL**. The same page filed under both
"Arbeid" and "Privat" is two bookmarks, because whoever filed it twice meant to.
Import is idempotent on that key, so re-importing a browser adds nothing.
