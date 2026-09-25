#!/usr/bin/env node
//
// Build the Linux packaging inputs: the native-messaging host binary, plus the
// browser manifests that point at where the .deb/.rpm will install it.
//
// Without this, the Linux bundles ship the desktop app alone and the extension
// fails with "Can't reach Arca. Is the desktop app installed and the extension's
// native host registered?" — the app is fine, but nothing bridges it to the
// browser. `extension/install-linux.sh` fixes that for a dev checkout; this
// script is the packaged equivalent, so a plain `.deb` install just works.
//
// No-op off Linux, so macOS and Windows builds are unaffected.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

if (process.platform !== "linux") process.exit(0);

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const outDir = join(repo, "target", "linux-packaging");

// Where the .deb/.rpm put the host binary. Must stay in sync with the `files`
// maps in apps/desktop/src-tauri/tauri.conf.json.
const HOST_PATH = "/usr/bin/vault-native-host";

// Derive the extension id from the pinned public `key` rather than hardcoding
// it, so the manifests can never drift from the extension. Same derivation as
// extension/install-linux.sh: first 16 bytes of the SHA-256 of the decoded key,
// hex-encoded, then mapped 0-f -> a-p.
const manifestPath = join(repo, "extension/chromium/manifest.json");
const key = JSON.parse(readFileSync(manifestPath, "utf8")).key;
if (!key) {
  console.error(`gen-linux-packaging: no "key" field in ${manifestPath}`);
  process.exit(1);
}
const extId = [...createHash("sha256").update(Buffer.from(key, "base64")).digest().subarray(0, 16)]
  .map((b) => b.toString(16).padStart(2, "0"))
  .join("")
  .replace(/[0-9a-f]/g, (c) => "abcdefghijklmnop"[parseInt(c, 16)]);

// The bundler copies a file that must already exist, and `tauri build` only
// builds the desktop crate, so the host has to be built here.
execFileSync("cargo", ["build", "--locked", "-p", "vault-native-host", "--release"], {
  cwd: repo,
  stdio: "inherit",
});

mkdirSync(outDir, { recursive: true });
const cargoOutput = execFileSync("python3", [join(repo, "scripts/cargo-target-dir.py")], { encoding: "utf8" }).trim();
// Stage the freshly built binary. repo/target/release may contain a stale
// build when Cargo has been configured to put output in a shared cache.
copyFileSync(join(cargoOutput, "release/vault-native-host"), join(outDir, "vault-native-host"));
chmodSync(join(outDir, "vault-native-host"), 0o755);

writeFileSync(
  join(outDir, "no.sybr.vault.chromium.json"),
  JSON.stringify(
    {
      name: "no.sybr.vault",
      description: "Arca native messaging host",
      path: HOST_PATH,
      type: "stdio",
      allowed_origins: [`chrome-extension://${extId}/`],
    },
    null,
    2,
  ) + "\n",
);

// Firefox uses allowed_extensions + a gecko id, so start from the committed
// template and only fix up the path.
const firefox = JSON.parse(
  readFileSync(join(repo, "extension/native-host/no.sybr.vault.firefox.json"), "utf8"),
);
firefox.path = HOST_PATH;
writeFileSync(join(outDir, "no.sybr.vault.firefox.json"), JSON.stringify(firefox, null, 2) + "\n");

console.log(`gen-linux-packaging: host built, manifests written for extension id ${extId}`);
