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

const bridgeCrate = read("crates/vault-bridge/src/lib.rs");
const appBridge = read("apps/desktop/src-tauri/src/bridge.rs");
const cli = read("apps/cli/src/main.rs");
const nativeHost = read("extension/native-host/src/main.rs");
const background = read("extension/chromium/background.js");

// The bridge protocol has one definition, in vault-bridge, which the app
// and both clients compile against; a local copy is what could drift.
const bridgeProtocol = Number(
  bridgeCrate.match(/pub const PROTOCOL: u32 = (\d+);/)?.[1],
);
assert.ok(bridgeProtocol, "the bridge protocol is declared once");
for (const [name, source, local] of [
  ["app", appBridge, "PROTOCOL_VERSION"],
  ["CLI", cli, "BRIDGE_PROTOCOL"],
  ["native host", nativeHost, "BRIDGE_PROTOCOL"],
]) {
  assert.ok(
    source.includes("vault_bridge::PROTOCOL"),
    `${name} uses the shared bridge protocol`,
  );
  assert.ok(
    !new RegExp(`const ${local}(?:: u32)? = \\d+;`).test(source),
    `${name} declares its own bridge protocol number`,
  );
}
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
  `protocol/version guard: bridge v${bridgeProtocol}, native v${constant(nativeHost, "PROTOCOL_VERSION")}, release ${cargoVersion}`,
);
