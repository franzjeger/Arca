// Cross-language guard for the constants that cannot share a module: Rust,
// browser JavaScript and JSON manifests are built by different toolchains.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");
const constant = (source, name) => {
  const match = source.match(new RegExp(`const ${name}(?:: u32)? = (\\d+);`));
  assert.ok(match, `${name} is declared`);
  return Number(match[1]);
};

const appBridge = read("apps/desktop/src-tauri/src/bridge.rs");
const cli = read("apps/cli/src/main.rs");
const nativeHost = read("extension/native-host/src/main.rs");
const background = read("extension/chromium/background.js");

assert.equal(
  constant(appBridge, "PROTOCOL_VERSION"),
  constant(nativeHost, "BRIDGE_PROTOCOL"),
  "desktop app and native host bridge protocols drifted",
);
assert.equal(
  constant(appBridge, "PROTOCOL_VERSION"),
  constant(cli, "BRIDGE_PROTOCOL"),
  "desktop app and CLI bridge protocols drifted",
);
assert.equal(
  constant(nativeHost, "PROTOCOL_VERSION"),
  constant(background, "NATIVE_PROTOCOL"),
  "extension and native-messaging host protocols drifted",
);

const cargoVersion = read("Cargo.toml").match(
  /\[workspace\.package\][\s\S]*?\nversion = "([^"]+)"/,
)?.[1];
assert.ok(cargoVersion, "workspace package version is declared");
const componentVersions = [
  JSON.parse(read("apps/desktop/package.json")).version,
  JSON.parse(read("apps/desktop/src-tauri/tauri.conf.json")).version,
  JSON.parse(read("extension/chromium/manifest.json")).version,
  JSON.parse(read("extension/chromium/manifest.firefox.json")).version,
];
assert.deepEqual(
  [...new Set([cargoVersion, ...componentVersions])],
  [cargoVersion],
  "app, CLI/native-host and extension package versions drifted",
);

console.log(
  `protocol/version guard: bridge v${constant(appBridge, "PROTOCOL_VERSION")}, native v${constant(nativeHost, "PROTOCOL_VERSION")}, release ${cargoVersion}`,
);
