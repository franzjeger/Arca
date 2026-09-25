import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const desktop = path.resolve(here, "../../apps/desktop");
const config = fs.readFileSync(
  path.join(desktop, "src-tauri/tauri.conf.json"),
  "utf8",
);
assert.ok(!config.includes("'unsafe-inline'"), "desktop CSP must reject inline styles");

const components = fs
  .readdirSync(path.join(desktop, "src/components"))
  .filter((name) => name.endsWith(".tsx"));
for (const component of components) {
  const source = fs.readFileSync(path.join(desktop, "src/components", component), "utf8");
  assert.ok(!/style\s*=\s*\{\{/.test(source), `${component} contains an inline style object`);
}

console.log(`desktop CSP: strict policy and ${components.length} components checked`);
