// Tests for the ephemeral mirror's pure half.
//
//     node extension/test/mirror.test.mjs
//
// What appears in someone's bookmarks bar is decided here, so it is decided by
// code that runs without a browser.
import assert from "node:assert/strict";
import {
  buildTree,
  creationOrder,
  fingerprint,
  mirrorGate,
  serialExecutor,
  vaultVerdict,
  MAX_MIRRORED,
  UNREACHABLE_GRACE_MS,
} from "../chromium/mirror.js";

let pass = 0;
const check = (name, got, want) => {
  assert.deepEqual(got, want, `${name}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
  console.log(`  ok  ${name}`);
  pass++;
};

/// Folder names at one level, for readable assertions.
const names = (node) => [...node.folders.keys()];
const titles = (node) => node.links.map((l) => l.title);
const at = (node, ...path) => path.reduce((n, p) => n.folders.get(p), node);

console.log("\nPaths become folders");
{
  const { root, used } = buildTree([
    { folder: "", title: "Sybr", url: "https://sybr.no" },
    { folder: "Arbeid", title: "RMM", url: "https://rmm.test" },
    { folder: "Arbeid/Kunder", title: "Laugstol", url: "https://laugstol.no" },
  ]);
  check("top level keeps its own links", titles(root), ["Sybr"]);
  check("one folder appears", names(root), ["Arbeid"]);
  check("and nests", names(at(root, "Arbeid")), ["Kunder"]);
  check("with the leaf inside", titles(at(root, "Arbeid", "Kunder")), ["Laugstol"]);
  check("everything was used", used, 3);
}

console.log("\nThe same input always looks the same");
{
  // A bookmarks bar that reshuffles on every unlock reads as corruption even
  // when nothing is wrong, so order is not left to whatever the vault returns.
  const input = [
    { folder: "B", title: "zebra", url: "https://z.test" },
    { folder: "A", title: "apple", url: "https://a.test" },
    { folder: "B", title: "alpha", url: "https://al.test" },
  ];
  const first = buildTree(input);
  const shuffled = buildTree([input[2], input[0], input[1]]);
  check("folders sort", names(first.root), ["A", "B"]);
  check("links sort", titles(at(first.root, "B")), ["alpha", "zebra"]);
  check("input order does not matter", names(shuffled.root), names(first.root));
}

console.log("\nFolders are created before loose bookmarks");
{
  const { root } = buildTree([
    { folder: "Zulu", title: "inside", url: "https://inside-z.test" },
    { folder: "Alpha", title: "inside", url: "https://inside-a.test" },
    { folder: "", title: "A loose bookmark", url: "https://loose-a.test" },
    { folder: "", title: "Z loose bookmark", url: "https://loose-z.test" },
  ]);
  check(
    "mixed levels are folders-first, alphabetic within each group",
    creationOrder(root).map(({ kind, value }) => `${kind}:${value.name || value.title}`),
    [
      "folder:Alpha",
      "folder:Zulu",
      "link:A loose bookmark",
      "link:Z loose bookmark",
    ],
  );
}

console.log("\nWhat never reaches the browser");
{
  const { root, used, dropped } = buildTree([
    { folder: "", title: "code", url: "javascript:alert(1)" },
    { folder: "", title: "internal", url: "chrome://settings" },
    { folder: "", title: "file", url: "file:///etc/passwd" },
    { folder: "", title: "ok", url: "https://ok.test" },
  ]);
  // Executable code and browser-internal pages have no business being written
  // into an arbitrary browser by a password manager.
  check("only the web URL survives", titles(root), ["ok"]);
  check("used counts what landed", used, 1);
  check("dropped counts the rest", dropped, 3);
}

console.log("\nA collection too large to mirror");
{
  const many = Array.from({ length: MAX_MIRRORED + 25 }, (_, i) => ({
    folder: "",
    title: `b${i}`,
    url: `https://b${i}.test`,
  }));
  const { used, dropped } = buildTree(many);
  // Every one is a separate browser API call. Refusing loudly beats a browser
  // that hangs for ten seconds on every unlock.
  check("the cap holds", used, MAX_MIRRORED);
  check("and the remainder is reported, not hidden", dropped, 25);
}

console.log("\nJunk is a tree, not a crash");
{
  for (const input of [null, undefined, [], [null], [{}], [{ url: 1 }]]) {
    const { root } = buildTree(input);
    assert.equal(titles(root).length, 0);
  }
  console.log("  ok  malformed input yields an empty tree");
  pass++;
}

console.log("\nThe fingerprint decides whether to rebuild");
{
  const a = [
    { folder: "A", title: "x", url: "https://x.test" },
    { folder: "B", title: "y", url: "https://y.test" },
  ];
  check("stable across runs", fingerprint(a), fingerprint(a));
  check("and across order", fingerprint(a), fingerprint([a[1], a[0]]));

  const renamed = [{ ...a[0], title: "z" }, a[1]];
  assert.notEqual(fingerprint(a), fingerprint(renamed));
  console.log("  ok  a changed title changes it");
  pass++;

  const moved = [{ ...a[0], folder: "C" }, a[1]];
  assert.notEqual(fingerprint(a), fingerprint(moved));
  console.log("  ok  a moved bookmark changes it");
  pass++;

  assert.notEqual(fingerprint(a), fingerprint([a[0]]));
  console.log("  ok  a removed bookmark changes it");
  pass++;
}

console.log("\nMirror operations cannot overlap");
{
  const serial = serialExecutor();
  const order = [];
  let releaseFirst;
  const gate = new Promise((resolve) => { releaseFirst = resolve; });
  const first = serial(async () => {
    order.push("first start");
    await gate;
    order.push("first end");
  });
  const second = serial(async () => order.push("second"));
  await Promise.resolve();
  check("a second event waits at the first await", order, ["first start"]);
  releaseFirst();
  await Promise.all([first, second]);
  check("events finish in request order", order, ["first start", "first end", "second"]);

  await serial(async () => { throw new Error("transient"); }).catch(() => {});
  await serial(async () => order.push("after failure"));
  check("one failure does not poison later cleanup", order.at(-1), "after failure");
}

console.log("\nThe browser-sync guard");
{
  // If the browser syncs its own bookmarks, everything Arca writes is uploaded
  // and kept — neither temporary nor private, on a server the user cannot
  // clean. There is no extension API that reports that setting, so this asks
  // rather than guesses, and refuses until it has an answer.
  check("off by default", mirrorGate({ allowed: undefined }).allow, false);
  check("and a missing setting is not consent", mirrorGate({}).allow, false);
  check("nor is anything truthy-but-not-true", mirrorGate({ allowed: "yes" }).allow, false);
  check("only an explicit yes opens it", mirrorGate({ allowed: true }).allow, true);
  check(
    "and a refusal says what it is waiting for",
    mirrorGate({ allowed: false }).reason.includes("sync is off"),
    true,
  );
}

console.log("\nSilence is not the same as a locked vault");
{
  const now = 1_000_000;
  // The app stating its own condition. Immediate — that IS the feature.
  check(
    "locked takes the folder down at once",
    vaultVerdict({ ok: true, message: "locked", missSince: null, now }).action,
    "remove",
  );

  // Everything else is an absence of information. The old code deleted the
  // folder on any of these, the next tick rebuilt it, and a bookmark saved in
  // between was lost — which is exactly what "saving doesn't work" was.
  for (const answer of [
    { ok: true, message: "unreachable" },
    { ok: false, error: "native host disconnected" },
    { ok: true, message: "internal" },
    { ok: true },
  ]) {
    assert.equal(
      vaultVerdict({ ...answer, missSince: null, now }).action,
      "wait",
      `should wait on ${JSON.stringify(answer)}`,
    );
  }
  console.log("  ok  a first silence never deletes anything");
  pass++;

  // But a genuinely quit app stays silent, so the folder must still go.
  check(
    "silence that persists past the grace period does",
    vaultVerdict({
      ok: true,
      message: "unreachable",
      missSince: now - UNREACHABLE_GRACE_MS - 1,
      now,
    }).action,
    "remove",
  );
  check(
    "and just under it does not",
    vaultVerdict({
      ok: true,
      message: "unreachable",
      missSince: now - UNREACHABLE_GRACE_MS + 1,
      now,
    }).action,
    "wait",
  );

  // The run has to be anchored to its FIRST miss, or a burst of triggers in one
  // second would each restart the clock and the folder would never come down.
  check(
    "the clock starts at the first silence, not the latest",
    vaultVerdict({ ok: true, message: "unreachable", missSince: null, now }).since,
    now,
  );
  check(
    "and an existing run keeps its start",
    vaultVerdict({ ok: true, message: "unreachable", missSince: 42, now }).since,
    42,
  );
}

console.log(`\n${pass} checks passed\n`);
