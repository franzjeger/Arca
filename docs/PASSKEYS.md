# Passkeys (WebAuthn) — architecture

**Status (0.6.2):** browser WebAuthn and native Apple credential providers are
implemented. macOS registration uses a durable encrypted inbox before returning
the credential. See [macOS passkeys and unlock](MACOS-PASSKEYS.md) for the current
storage contract and the manual acceptance checks.

The cryptographic core underneath both is `crates/vault-core/src/passkey.rs`,
implemented and unit-tested.

## How the extension path works

Passwords autofill by typing text into a field, which any content script can do.
Passkeys go through the browser's **WebAuthn** engine
(`navigator.credentials.create/get`), so Arca wraps that API in the page's own
JS world — a `world: "MAIN"` content script at `document_start` — and answers the
ceremony itself via the isolated relay → background worker → native host →
loopback bridge. Anything it cannot service (vault locked, no passkey for this
relying party, a non-ES256 request) falls through to the browser's real handler,
so security keys and phones keep working. Every fallback logs its reason at
`console.debug`, because from the outside they are indistinguishable.

Two things about this path are easy to get wrong, and both shipped broken once:

- **Deciding whether the user asked for it.** A ceremony often does not run in
  the document the user clicked in — Microsoft Entra navigates to
  `login.microsoft.com/common/bridge/fido`, which fires `get()` on load. A
  gesture tracked inside the page dies with the page, so the gesture is kept in
  a per-tab ledger in the background worker, and consumed once. A click that
  opens a new tab moves its gesture into that tab. A per-site
  `ask`/`always`/`never` override lives in the popup.

  Registration is stricter. `create()` wants a click in the very document that
  fired it; `always` never stands in for one (GitHub re-offers "add a passkey"
  on a timer, and a stand-in turned every offer into a prompt). The ledger
  stands in under one shape only — an *arrival page*: a document the user has
  not touched, within 5 s of load, with a fresh carried gesture. That is the
  shape of Microsoft's `login.microsoft.com/<tenant>/fido/create`, which fires
  `create()` on load; before this, every such registration fell through to the
  browser's QR dialog on Linux. The desktop app still asks before creating
  anything — the gate only decides who gets to ask.
- **What is handed back.** The relying party must receive something that behaves
  like a real `PublicKeyCredential` — `toJSON()` and working `instanceof` — not
  an object literal with the right fields. Get it wrong and the ceremony
  *succeeds*, Arca reports success, and the site fails on its own error.

One rule is not negotiable: **nothing the page says is trusted.** The shim runs
in the page's world, so anything it sends the relay the page could have sent
instead. The page supplies the request — challenge, rpId, which credentials —
and the isolated relay supplies every fact the signature or the approval rests
on:

- the **client data** (`type`, `challenge`, `origin`), built in the relay from
  its own `location.origin`; the app signs its hash and the page receives the
  exact bytes. Built in the page, it would carry whatever origin the page
  wrote, and a script on `sub.example.com` could sign in to `example.com` as
  `example.com`.
- **`picked`**, set only when content.js recorded a trusted click on that
  credential's row in Arca's picker (same isolated world, unreachable from the
  page), fresh and spent once. The row lives in the page's DOM, where the page
  can fade it or paint a click-through layer over it, so the click counts only
  if IntersectionObserver v2 reported the row painted unobscured and at full
  opacity for 500 ms before it. Otherwise — and always in Firefox, which cannot
  report that — the ceremony still runs and the desktop chooser asks.
- the **origin** the app checks against the rpId, and the **gate approval**,
  which is minted for one kind of ceremony so a sign-in approval cannot buy a
  registration.

`extension/test/passkey.test.mjs` covers all of this against the real files.

## Native Apple providers

The macOS and iOS targets implement password and passkey credential providers
through AuthenticationServices. The OS supplies the relying party and request
parameters; the Swift provider selects an account and calls `vault-ffi` for the
cryptographic operation. Both advertise passkey support.

The bridge uses ABI v16, checked against the linked Rust library by the Swift
tests. The cryptographic core creates ES256/P-256 credentials, encodes COSE
public keys and attestation objects, and signs assertions. Credential private
keys remain in the encrypted vault.

On macOS, registration commits an encrypted snapshot to the durable passkey
inbox before returning success. The desktop merges it into the canonical vault.
On iOS, the provider writes the canonical shared vault directly. See
[macOS persistence and account selection](MACOS-PASSKEYS.md).

The local macOS installer embeds `ArcaAutoFill.appex` into the Tauri app and
signs both bundles with matching local provisioning profiles. The containing
app and extension both need AutoFill, App Group and shared-keychain
capabilities. Setup and verification are in [apps/macos/README.md](../apps/macos/README.md).
The distribution release script is a separate path; do not infer its embedded
capabilities from a successful local development install.

Windows and Linux use the browser-extension WebAuthn path. Native Apple
provider support does not imply a native provider on those platforms.

## User verification: what a sign-in asks of you

A passkey assertion carries two flags the relying party trusts: **UP** (a
person was present) and **UV** (that person was verified). Arca's stance:

- The **open vault is the verification.** Opening it took the master password,
  Touch ID, Windows Hello or the USB key the user enrolled for exactly that,
  and the idle lock bounds how long that holds. This is the model 1Password
  and Apple Passwords use; it is what lets a sign-in be one step.
- **Presence is one deliberate click in Arca's own UI that names the site and
  the account.** Picking a passkey row in the in-page picker is that click, so
  the desktop asks nothing further. The extension's isolated world records the
  click and sets `picked: true` itself; a page cannot claim one, and a click
  on a row the browser did not report as plainly visible does not count.
  A ceremony the page started itself gets the desktop chooser instead — one
  button per matching account, one account = one button — and choosing *is*
  approving. Registration gets a single "Create passkey" button.
- **macOS keeps Touch ID** per ceremony: one touch, genuinely biometric.
- **"Ask for the master password on every passkey use"** (Settings, off by
  default) restores the per-use password prompt. The bridge decides which
  prompt a ceremony gets and records it with the pending request; the
  click-only command is refused for a password-required one, so the UI cannot
  downgrade the check.

The double prompt this replaced — pick the account, then type the master
password — was not a second factor. It was the same secret that had already
opened the vault, asked again.

## Security notes (feeds THREAT_MODEL.md)

- The credential private key is a P-256 scalar stored inside the encrypted vault
  and zeroized in memory; it never leaves the device.
- The extension unlocks via the OS-keychain device key gated by Touch ID (the OS
  performs the biometric as part of the AutoFill flow), so the master password is
  not needed per assertion. Same residual as T10 (device-key theft by same-user
  code) applies.
- `attestationObject` uses `fmt: "none"` — no attestation CA, no device
  identifier leaked to relying parties (privacy-preserving, and what most
  software authenticators do).
- Independent review of `passkey.rs` against the WebAuthn spec is required before
  this is used for real credentials (tracked with the overall audit).

## Known gaps

Neither is a bug today. Both are places where a future change — a stricter
relying party, a different Windows machine — would surface first, so they are
written down rather than rediscovered.

### The signature counter is always zero

`passkey::assert` passes `0` as `signCount` on every assertion, and the
`sign_count` field stored on a `VaultItem::Passkey` is written once as `0` and
never incremented or read back.

This is legal: WebAuthn treats a constant `0` as "this authenticator does not
support a signature counter", which is the honest answer for a credential that
is *designed* to sync across a user's devices — a per-device counter on synced
material would go backwards on every device switch and look exactly like the
cloning it exists to detect. Apple and Google's synced passkeys report `0` for
the same reason.

The consequence to know: a relying party that treats a counter as mandatory, or
that stores the value and rejects a non-increment, will refuse our assertions.
Nothing to fix pre-emptively — but if a specific site starts rejecting sign-ins
that the origin and UV checks should have allowed, look here early.

### Windows Hello is called from a thread with no COM apartment

`vault_winhello::verify` is invoked through `authenticate_off_main`, which hands
it to `tauri::async_runtime::spawn_blocking` — deliberately, so the blocking
prompt cannot freeze the UI thread's message pump (the original bug: a PIN box
that could not be typed into). See `biometric.rs`.

That worker thread is never `CoInitializeEx`'d, and nothing in the tree calls
`CoIncrementMTAUsage`. The WinRT calls inside `verify` — the activation factory
and the blocking `operation.get()` — therefore run on whatever apartment state
the thread happens to have, in practice the process-wide implicit MTA.

It has worked on the machine it was tested on, which is why this is a note and
not a defect. But UI-invoking interop, parented to a window owned by a different
thread, called from a thread that never declared its apartment, is the shape of
thing that fails on someone else's machine rather than yours — as
`CO_E_NOTINITIALIZED` / `RPC_E_*`, or as focus not returning cleanly after the
prompt dismisses. If that turns up, the fix is to declare the apartment on that
worker (or give the prompt its own thread), not to move the call back onto the
UI thread — that is where this started.
