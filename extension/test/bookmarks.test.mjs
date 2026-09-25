// Tests for the bookmark reconciler.
//
//     node extension/test/bookmarks.test.mjs
//
// This is the only code in Arca that can destroy something the user cannot get
// back from the vault: bookmarks live in the browser, and a bad push-out empties
// the bookmark bar in every browser at once. The guards against that are the
// point of this file, so they are tested against the real module rather than a
// description of it.
import assert from "node:assert/strict";
import { flatten, plan, apply, planCleanup, OWNED_FOLDER_TITLE, barRootId, rootLabel, ROOT_IDS } from "../chromium/bookmarks.js";

let pass = 0;
const check = (name, got, want) => {
  assert.deepEqual(got, want, `${name}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
  console.log(`  ok  ${name}`);
  pass++;
};

const bm = (folder, url) => ({ folder, url, title: url, id: `${folder}|${url}` });

console.log("\nFlattening a browser tree");
{
  // The real shape: root ids 1/2/3, localised names, nested folders.
  const roots = [
    {
      id: "1",
      title: "Bokmerkelinje",
      children: [
        { id: "10", title: "Sybr", url: "https://sybr.no" },
        {
          id: "11",
          title: "Arbeid",
          children: [{ id: "12", title: "RMM", url: "https://rmm.example" }],
        },
        { id: "13", title: "bad", url: "javascript:alert(1)" },
      ],
    },
    {
      id: "2",
      title: "Andre bokmerker",
      children: [{ id: "20", title: "Later", url: "https://later.example" }],
    },
  ];
  const flat = flatten(roots);
  // The bar's own name is localised and must never enter a path — that is why
  // the roots are mapped by id and not by title.
  check("bar entries sit at the top level", flat.find((b) => b.title === "Sybr").folder, "");
  check("nested folders become paths", flat.find((b) => b.title === "RMM").folder, "Arbeid");
  check("the other root keeps a stable name", flat.find((b) => b.title === "Later").folder, "Other");
  check("bookmarklets are dropped", flat.some((b) => b.url.startsWith("javascript:")), false);
}

console.log("\nAdditions need no permission and are never refused");
{
  const current = [bm("", "https://a.example")];
  const master = [bm("", "https://a.example"), bm("Arbeid", "https://b.example")];
  const p = plan(current, master, { deletions: false });
  check("adds what is missing", p.additions.map((b) => b.url), ["https://b.example"]);
  check("removes nothing without deletions", p.removals, []);
}

console.log("\nAn empty master never clears the browser");
{
  // A locked vault, a failed read, or an import that has not run yet all look
  // exactly like "Arca has no bookmarks" from here. None of them mean "delete
  // everything", and treating them that way loses the bar in every browser.
  const current = [bm("", "https://a.example"), bm("", "https://b.example")];
  const p = plan(current, [], { deletions: true, confirmed: true });
  check("removals are refused outright", p.removals, []);
  check("and the reason says why", /empty/.test(p.refused), true);
}

console.log("\nA large deletion pass needs a human");
{
  const current = Array.from({ length: 100 }, (_, i) => bm("", `https://x${i}.example`));
  // Arca knows about 50 of them; the other 50 would go.
  const master = current.slice(0, 50);
  const p = plan(current, master, { deletions: true });
  check("nothing is removed unconfirmed", p.removals, []);
  check("the count is reported so it can be shown", p.pendingRemovals, 50);
  check("the refusal names the numbers", /50 of 100/.test(p.refused), true);

  const confirmed = plan(current, master, { deletions: true, confirmed: true });
  check("confirming lets it through", confirmed.removals.length, 50);
}

console.log("\nOrdinary tidying is not blocked");
{
  // Removing a handful is normal use and must not need a dialog every time,
  // or the confirmation becomes something people click through blindly.
  const current = Array.from({ length: 100 }, (_, i) => bm("", `https://x${i}.example`));
  const master = current.slice(0, 95);
  const p = plan(current, master, { deletions: true });
  check("five removals go through unattended", p.removals.length, 5);
  check("with no refusal", p.refused, null);
}

console.log("\nPolicy-managed bookmarks are never touched");
{
  const managed = { ...bm("", "https://corp.example"), unmodifiable: "managed" };
  const current = [managed, bm("", "https://mine.example")];
  const p = plan(current, [bm("", "https://mine.example")], {
    deletions: true,
    confirmed: true,
  });
  check("a managed entry is not proposed for removal", p.removals, []);
}

console.log("\nThe same page filed twice stays two bookmarks");
{
  // Identity is folder + url on purpose: someone who filed a page under both
  // "Arbeid" and "Privat" meant to.
  const current = [bm("Arbeid", "https://p.example")];
  const master = [bm("Arbeid", "https://p.example"), bm("Privat", "https://p.example")];
  const p = plan(current, master, { deletions: true, confirmed: true });
  check("the second filing is an addition", p.additions.length, 1);
  check("and the first is not a removal", p.removals, []);
}

console.log("\napply() survives a node the browser refuses");
{
  // One bookmark in a managed folder must not abort the other additions.
  const api = {
    bookmarks: {
      getTree: async () => [{ id: "0", children: [{ id: "1", children: [] }] }],
      getChildren: async () => [],
      create: async ({ url }) => {
        if (url === "https://boom.example") throw new Error("managed");
        return { id: `n${url}` };
      },
      remove: async () => {},
    },
  };
  const res = await apply(api, [
    bm("", "https://ok1.example"),
    bm("", "https://boom.example"),
    bm("", "https://ok2.example"),
  ]);
  check("the good ones still landed", res.added, 2);
}




// ── Cleanup at startup ──────────────────────────────────────────────────────
//
// The ephemeral mirror is only private if the bookmarks actually go away. A
// browser that crashes, or an Arca that dies, must not leave them lying there —
// so cleanup runs at startup, before anything else, and these decide what it
// may touch.

const bar = (children) => [{ id: "1", title: "Bookmarks bar", children }];

console.log("\nCleanup removes what we can prove is ours");
{
  const tree = bar([
    { id: "10", title: "Arca", children: [{ id: "11", title: "x", url: "https://x.test" }] },
    { id: "20", title: "Frank sine", children: [{ id: "21", title: "y", url: "https://y.test" }] },
  ]);
  const { remove } = planCleanup({ tree, ownedId: "10" });
  check("the recorded folder goes, contents and all", remove.join(), "10");
  check("and nothing else is touched", remove.includes("20"), false);
}

console.log("\nA folder that only LOOKS like ours");
{
  // After a reinstall the recorded id is gone. Sharing a name is not proof of
  // ownership, and a user may well have made their own "Arca" folder.
  const tree = bar([
    { id: "30", title: "Arca", children: [{ id: "31", title: "mine", url: "https://mine.test" }] },
  ]);
  const { remove, notes } = planCleanup({ tree, ownedId: null });
  check("a non-empty lookalike is LEFT ALONE", remove.length, 0);
  check("and says so", notes.some((n) => n.includes("not provably ours")), true);

  // An empty shell costs nothing to remove and nothing to lose.
  const empty = bar([{ id: "40", title: "Arca", children: [] }]);
  check("an empty leftover is swept", planCleanup({ tree: empty, ownedId: null }).remove.join(), "40");
}

console.log("\nOwnership v2 repairs folders orphaned by the single-id race");
{
  const links = (count, omitLast = false) =>
    Array.from({ length: count - (omitLast ? 1 : 0) }, (_, i) => ({
      id: `b${i}`,
      title: `Site ${i}`,
      url: `https://site-${i}.test`,
    }));
  const tree = bar([
    { id: "70", title: "Arca", children: links(25, true) },
    { id: "80", title: "Arca", children: links(25) },
    {
      id: "90",
      title: "Arca",
      children: Array.from({ length: 25 }, (_, i) => ({
        id: `personal${i}`,
        title: `Personal ${i}`,
        url: `https://personal-${i}.test`,
      })),
    },
  ]);
  const migrated = planCleanup({
    tree,
    ownedIds: ["70"],
    recoverRelated: true,
  });
  check("the recorded folder is removed", migrated.remove.includes("70"), true);
  check("a near-identical orphan is recovered", migrated.remove.includes("80"), true);
  check("an unrelated personal Arca folder stays", migrated.remove.includes("90"), false);

  const ordinary = planCleanup({ tree, ownedIds: ["70"], recoverRelated: false });
  check("the broad repair is migration-only", ordinary.remove.includes("80"), false);
  const unanchored = planCleanup({ tree, ownedIds: [], recoverRelated: true });
  check("recovery never guesses without a recorded anchor", unanchored.remove.length, 0);
}

console.log("\nEvery recorded owner id is cleaned");
{
  const tree = bar([
    { id: "100", title: "Arca", children: [{ id: "101", title: "a", url: "https://a.test" }] },
    { id: "110", title: "Arca", children: [{ id: "111", title: "b", url: "https://b.test" }] },
  ]);
  const result = planCleanup({ tree, ownedIds: ["100", "110"] });
  check("both ledger entries are removed", result.remove.sort(), ["100", "110"]);
}

console.log("\nThings cleanup must never remove");
{
  // A root removal throws, and one throw aborts the whole batch — so a
  // policy-managed folder would take the real cleanup down with it.
  const managed = bar([{ id: "50", title: "Arca", children: [], unmodifiable: "managed" }]);
  check("policy-managed folders are refused", planCleanup({ tree: managed, ownedId: "50" }).remove.length, 0);

  const roots = [{ id: "1", title: "Arca", children: [] }];
  check("a root is never removed", planCleanup({ tree: roots, ownedId: "1" }).remove.length, 0);

  const other = bar([{ id: "60", title: "Frank sine", children: [] }]);
  check("an id that no longer exists removes nothing", planCleanup({ tree: other, ownedId: "99" }).remove.length, 0);

  // Chromium REUSES bookmark ids after a deletion, so an id recorded weeks ago
  // can come to point at a folder the user made yesterday. Without the title
  // check this deleted it. The first version of this test asserted the
  // deletion and called it "never hits a stranger", which is how the hole
  // survived being written down.
  const reused = planCleanup({ tree: other, ownedId: "60" });
  check("a REUSED id is refused", reused.remove.length, 0);
  check("and names what it found instead", reused.notes.some((n) => n.includes("id reused")), true);
}


// ── Firefox ────────────────────────────────────────────────────────────────
//
// Chromium numbers its roots ("1" is the bar); Firefox pads names
// ("toolbar_____"). Hardcoding Chromium's is why the mirror wrote nothing at
// all in Firefox while reporting success — a create with an unknown parentId
// does not land anywhere a person looks.

const ffTree = [
  {
    id: "root________",
    children: [
      { id: "toolbar_____", title: "Bokmerkeverktøylinje", children: [] },
      { id: "menu________", title: "Bokmerkemeny", children: [] },
      { id: "unfiled_____", title: "Andre bokmerker", children: [] },
      { id: "mobile______", title: "Mobile bokmerker", children: [] },
    ],
  },
];
const crTree = [
  {
    id: "0",
    children: [
      { id: "1", title: "Bookmarks bar", children: [] },
      { id: "2", title: "Other bookmarks", children: [] },
      { id: "3", title: "Mobile bookmarks", children: [] },
    ],
  },
];

console.log("\nThe bar is found, not assumed");
{
  check("Firefox", barRootId(ffTree), "toolbar_____");
  check("Chromium", barRootId(crTree), "1");
  // A browser neither list anticipates still gets the old behaviour rather
  // than a crash or a write into nowhere.
  check("an unknown browser falls back", barRootId([{ id: "x", children: [] }]), "1");
}

console.log("\nRoot labels are the same in both");
{
  // The bar contributes NOTHING to a path: its name is localised, and
  // prefixing every bookmark with it adds a level that means nothing. That has
  // to hold for "Bokmerkeverktøylinje" exactly as it does for "Bookmarks bar".
  check("Firefox bar", rootLabel("toolbar_____"), "");
  check("Chromium bar", rootLabel("1"), "");
  check("Firefox other", rootLabel("unfiled_____"), "Other");
  check("Chromium other", rootLabel("2"), "Other");
  check("a normal folder is not a root", rootLabel("42"), null);
}

console.log("\nNo root is removable, in either browser");
{
  for (const id of ["0", "1", "2", "3", "root________", "toolbar_____", "unfiled_____"]) {
    assert.ok(ROOT_IDS.has(id), `${id} must be protected`);
  }
  console.log("  ok  every root id in both browsers is protected");
  pass++;

  // The cleanup sweep looks at the bar's top level; in Firefox that is a
  // different node, and a plan that looked at "1" would find nothing to clean.
  const ff = [
    {
      id: "root________",
      children: [
        {
          id: "toolbar_____",
          children: [{ id: "99", title: "Arca", children: [] }],
        },
      ],
    },
  ];
  check("an empty leftover is swept in Firefox too", planCleanup({ tree: ff, ownedId: null }).remove.join(), "99");
}

console.log(`\n${pass} checks passed\n`);
