// Does every element popup.js reaches for actually exist, and exist YET?
//
//     node extension/test/popup.test.mjs
//
// Two ways to get null from getElementById, and both shipped today: the id is
// not in the HTML, or the script runs before the markup it needs. The second
// one is nastier — the element is right there on screen, the popup renders
// perfectly, and the handler silently never attaches.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const EXT = fileURLToPath(new URL("../chromium/", import.meta.url));
const html = readFileSync(EXT + "popup.html", "utf8");
const js = readFileSync(EXT + "popup.js", "utf8");

let pass = 0;
const ok = (name) => {
  console.log(`  ok  ${name}`);
  pass++;
};

const wanted = [...js.matchAll(/getElementById\("([^"]+)"\)/g)].map((m) => m[1]);
assert.ok(wanted.length > 5, "expected popup.js to reach for several elements");

console.log("\nEvery id popup.js asks for is in the HTML");
{
  const missing = wanted.filter((id) => !html.includes(`id="${id}"`));
  assert.deepEqual(missing, [], `popup.js asks for ids the HTML lacks: ${missing}`);
  ok(`all ${wanted.length} ids present`);
}

console.log("\nAnd the markup exists by the time the script runs");
{
  // `defer` is what makes this safe regardless of where the tag sits; without
  // it, anything below the script tag is invisible to it. The check accepts
  // either guarantee, and today's bug failed both.
  const tag = html.match(/<script[^>]*src="popup\.js"[^>]*>/);
  assert.ok(tag, "popup.html must load popup.js");
  const deferred = /\bdefer\b/.test(tag[0]);
  const scriptAt = html.indexOf(tag[0]);
  const late = wanted.filter((id) => {
    const at = html.indexOf(`id="${id}"`);
    return at > scriptAt;
  });
  assert.ok(
    deferred || late.length === 0,
    `these ids are declared after a non-deferred <script>: ${late}`,
  );
  ok(deferred ? "script is deferred" : "all markup precedes the script");
}

console.log(`\n${pass} checks passed\n`);
