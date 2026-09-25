# Changelog

## Unreleased

- macOS: select matching local signing profiles before replacing the app,
  verify the installed AutoFill capabilities, and restore the previous app,
  helpers and browser registrations if installation fails. Keep the native
  host at a stable path outside the build cache.
- Browser extension: retry a failed read-only login lookup once and offer a
  manual retry. After an extension reload, ask the user to reload the page;
  never replay credential fills, saves or passkey ceremonies.

- Security: build a passkey sign-in's client data in the extension's isolated
  world. The page's own script wrote the `origin` the signature covered, so a
  script on a subdomain could produce a sign-in the parent site accepted as
  its own. Only a click the extension itself saw in Arca's picker now counts
  as picking a passkey; a page can no longer claim one to skip the desktop's
  approval. A gate approval for a sign-in no longer admits a registration.
- Security: a click in Arca's picker counts as picking a passkey only if the
  browser reports the row visible — unobscured and unfaded — for half a second
  before it (IntersectionObserver v2). A page that fades the picker or paints
  a click-through layer over it gets the desktop's chooser instead of a
  one-click sign-in. Firefox cannot report this and always shows the chooser.
- Passkey sign-in is one step. Picking the passkey in Arca's in-page picker
  is the approval; a ceremony the page starts itself gets one chooser where
  clicking the account signs in. The open vault counts as user verification
  (as in 1Password and Apple Passwords) instead of asking for the master
  password again; a new setting brings the per-use password back. macOS keeps
  Touch ID.
- Unlock with a USB key, on Linux, macOS and Windows. Settings puts a key
  file on a stick (or adopts the one another of your computers put there);
  while it is plugged in the vault opens without the master password — on
  focus, on start, and silently when the browser asks for a fill or a passkey.
  Pulling the stick locks the vault (opt-out). Each computer binds the stick
  with a local pepper and wrap that never sync or back up, so a lost stick
  opens nothing, and the vault header is untouched: Touch ID, Hello and the
  keychain keep working next to it. See docs/KEYFILE-UNLOCK.md.
- Let a passkey registration that a page fires on load — Microsoft's
  `login.microsoft.com/…/fido/create` — ride the gesture carried from the page
  that led there, when the arriving document is untouched and within 5 s of
  load. Previously every such registration fell through to the browser's QR
  dialog on Linux. A click that opens a new tab now carries its gesture into
  that tab. Timer-driven re-offers in an old or touched page are still refused.

## 0.6.1 — 2026-09-09

- Detect username-first sign-in fields with implicit input types, accessible labels and login context, even when another form has a password field. Follow dynamically focused next steps.
- Anchor suggestions to the latest focused field, ignore stale lookups after dismissal, and keep long lists outside the input. Isolate picker styles and follow nested scrolling and page layout shifts. Add an explicit close button.
- Let passkey accounts fill the username-only first step without requesting a password. Keep Arca available when native conditional autofill is unsupported or refused, respect cancellation and account restrictions, and dismiss the competing native request after success.
- Exercise these flows in Chromium, including passkey completion while the website's required password field remains empty.

## 0.6.0 — 2026-09-09

- Require fresh master-password confirmation for sensitive desktop actions on Linux, with authorization tied to the active vault session.
- Add sync-conflict comparison, per-field selection, explicit secret reveal, stale-revision rejection and recoverable resolution.
- Install matching desktop/native-host builds transactionally on Linux; verify Git identity, running executable, bridge and single instance. Keep the previous installation for rollback without reverting vault data.
- Store the Linux native host outside Cargo caches and record installation checksums and the verified source commit automatically.
- Keep V5/ABI v16 compatibility; older conflict copies can be paired manually.

## 0.5.0 — 2026-09-08

- Fix local macOS AutoFill installation: embed the extension’s own provisioning profile, sign its application/team identifiers, and expand the shared keychain group in Info.plist so macOS can launch the provider.

- Resolve Cargo's configured output directory for desktop/native-host installs,
  Linux bundles and Apple FFI builds. A shared Cargo cache must not cause an
  installer to silently copy an older binary from the checkout's target folder.

- Reject late iOS unlock/sync completions after locking; invalidate unfinished
  unlocks on backgrounding and use a monotonic clock for background grace.
- Enforce a single desktop instance and focus its window on subsequent launches.
- Keep security controls at their durable values on save failures; write settings
  atomically. Show pending/running/error sync state and retry in the main window.
  Failed update checks no longer claim the installed version is current.
- Keep the last 20 login/Wi-Fi passwords encrypted per item, including through
  sync. Desktop/iOS offer copying and restoring one previous password. C ABI v16.
- Add opt-in rotating external encrypted backups, last-success/error status,
  read-back verification, and password verification without restoration.
- Use shared native modal dialogs with Escape, focus containment/return and
  accessible names; show consistent Arca naming, version and build information.
- Coordinate package versions at 0.5.0; run Apple/Windows checks on main pushes
  and require successful checks for the exact commit before signed releases.
- Refresh platform/security documentation and record the independent audit as
  an outstanding release requirement. V5 files need compatible clients on all
  devices; updating source does not install the iOS app on a phone.


## Unreleased

- Prevent duplicate Touch ID prompts from overlapping window/browser unlocks
  and from a manual unlock regaining focus before its first prompt completes.

- Add verified migration to OS-protected macOS device keys, with a Settings
  upgrade/repair action, protected new enrollments, and no silent legacy fallback.
  Authenticate off the main thread, reject late results after session changes,
  and preserve previous key references when persistence fails.

- Update backup settings and the main status bar immediately after configuration
  changes; discard older in-flight status replies and refresh on window focus.

- Prepare frontend dependencies and the supported test browser before local macOS
  installs; verify the launched app and native-host versions before accepting an update.
- Show disabled, missing and overdue automatic backups in the main status bar,
  with a direct link to settings and the last successful backup time when healthy.

- Authenticate the complete vault container (`SYBRVLT5`) so synced deletion
  records, password wrapping and empty vaults cannot bypass integrity checks.
  Legacy files remain readable and upgrade on an unlocked save; update every
  device before syncing the new format.
- Preserve simultaneous cloud uploads as separate revisions until merged,
  rather than overwriting a peer between the checksum check and upload.
- Roll back desktop edits, deletions and imports when persistence fails.
- Sync iOS note, Wi-Fi and deletion changes; run the first cycle after Google
  sign-in and preserve error messages and last-sync timestamps across the FFI.

### Data safety

- **The Apple app and its AutoFill extension take a shared lock on the vault.**
  Two processes wrote one file, and each write being atomic is not the same as
  safe: every writer reads, merges and writes, and nothing stopped the extension
  from committing a passkey in the gap between the app's read and its write. The
  app's next write had never seen that passkey and erased it — permanently, the
  extension process being long gone. `flock` on a sibling of the vault now makes
  the whole read-modify-write one step, the same guarantee the desktop already
  had.
- The iOS sync write-back no longer overwrites what another process committed
  during the cycle. It wrote bytes serialized *before* the network round-trip;
  it now re-folds the file under the lock and serializes that, via a new
  `vault_ffi_merge_and_serialize` (**C ABI v15**) that does both halves in one
  call so nothing can split them.
- Restoring an earlier version is refused while Google Drive sync is connected,
  matching encrypted-backup restore. Rolling the local file back did not roll
  the remote back: the engine still held the checksum of its last upload, saw
  nothing to download, and the next edit pushed the older vault over the newer
  remote — losing anything a second device had synced in between.
- Both restore paths now delete this machine's keychain device key along with
  the restored vault's device slot. Left behind, quick unlock reported itself
  available while it could never succeed, so every launch opened a Touch ID
  prompt and answered it with "Incorrect password, or the vault data is
  corrupt" — with no way back except toggling the setting.
- A passkey registration whose save fails is rolled back out of the in-memory
  vault. The orphan it used to leave was never registered by the site, yet the
  exclude-list check answered "excluded" on every retry, locking the user out
  of registering that passkey at all.
- **A bridge write that never reached the disk is undone in memory.** Every
  write changed the in-memory vault and then saved it, and a failed save
  returned an error while keeping the change. That turned a visible failure
  into a silent loss: the browser said the password was not saved, but the next
  probe answered "known" — no save bar, nothing left to click — and the next
  save answered "saved", so the password the user actually typed existed
  nowhere once the app quit. Saves, creates, deletes and bookmark imports now
  roll back the way a failed passkey registration already did, so memory and
  the file never disagree and a retry is a real retry.
- Bookmarks imported through the browser bridge are marked dirty for sync, like
  every other bridge write. They used to stay local-only until an unrelated
  edit happened to push them.

### Security

- **The bridge handshake authenticates both ways (bridge protocol v2).** Only
  the client proved itself; the app proved nothing, so a client believed
  anything that answered `{"type":"ok"}` on the port. Arca's port is released
  the instant it exits and the file naming that port outlived it — so whatever
  bound the port next was handed the next submitted password, and could answer
  a fill with credentials of its own choosing. The app now returns
  `HMAC-SHA256(token, client nonce)`, which the native host and the CLI verify
  in constant time before sending anything, and the connection-info file is
  deleted when the app exits.
- **A credential saved over TLS is never offered on a page served in the
  clear**, and a different port is a different site. Matching was on host alone,
  so an `https://bank.example` login was filled on `http://bank.example` — the
  shape of evil-twin Wi-Fi, a captive portal or spoofed DNS — and every service
  behind one hostname was merged, including each `localhost:<port>` a developer
  runs. Upgrading `http` to `https` is still allowed, and a hand-typed bare
  hostname still matches either.
- The idle timer resets only when a bridge request actually succeeds. It used
  to reset before validation, so a site retrying passkeys against an origin the
  user had silenced — or fills refused on origin mismatch — kept the vault
  unlocked with nobody at the desk.
- **Only a real click can release a credential from the picker.** The picker
  is rendered in the page's own DOM and opens automatically when a password
  field is focused, and its rows had no trust check — so a script on the page
  (an XSS, a compromised third-party tag) could focus the field, dispatch a
  click at a row, and read the filled password straight back out of the input,
  with no human involved and nothing on screen. The unlock row already refused
  synthetic clicks; every row does now, and so does the save bar's button,
  which decides what Arca writes to the vault for that site.
- A fill re-checks that the vault is still unlocked after the consent prompt.
  With lock-on-blur, glancing back at the browser locked the vault mid-prompt
  and the credential was still returned.
- A passkey assertion re-checks that the vault is still unlocked after the
  approval prompt, as a fill already did. The private key is read before the
  prompt, and lock-on-blur or the idle timer can fire while the user is looking
  at the dialog — so a locked vault could still sign a sign-in, which the
  relying party takes as proof the user was present just then.
- A credential in the Trash is no longer filled or read by id. The picker never
  offers one, but the bridge would still hand it over to anything holding an id
  from an earlier session, so retiring a credential did not retire it. Deleting
  an already-trashed item now reports that it was not there, instead of
  claiming a retraction that never happened.
- The bridge token is compared in constant time, one wrong token ends the
  connection instead of allowing unlimited retries on an open socket, and a
  connection that goes silent is dropped after 5 minutes rather than holding
  its thread forever.

### Autofill

- A password Arca generates is now offered for saving on submit. Generation is
  offered on sign-up and password-reset forms — two password boxes, often no
  username field (a token-based reset has none) — which the save-on-submit
  capture was built to reject. So the generated value became the live account
  password and was stored nowhere. Generate now records exactly what it filled
  and submit falls back to it, so the "Arca offers to save it when you submit"
  promise is finally kept.
- A password reset with no username field updates the existing login for the
  site in place instead of creating a blank-username duplicate — when the site
  has exactly one stored login. Two or more is ambiguous with no username to
  tell them apart, so Arca declines to guess and files a new entry the user can
  merge, rather than risk overwriting the wrong account's password.
- The generator now shows the password it created, with a copy button, instead
  of dropping a random string into a masked box the user can't read. It reveals
  nothing new — the value was just filled into the page's own field — and gives
  a way to verify or stash it before submitting.
- A generated password survives the redirect that follows a sign-up or reset.
  Those land on a login page, often on another host, and the "form gone, same
  site" gates that decide a normal sign-in succeeded threw the value away in
  exactly the case the feature exists for.
- Save-on-submit waits for the form to disappear by polling for up to 15
  seconds instead of sampling once at 1.5 s, so SPA logins slower than that are
  offered at all. The submit rate-limit keys on the candidate, so generating a
  second password and submitting immediately can no longer save the first one.
- Generating on an unlabelled change-password form fills the new-password box
  rather than the current one. It used to take the first field in document
  order, which on `[current, new, confirm]` is the box the form needs intact —
  the change then failed on "current password incorrect".
- The username field is resolved by ranked tiers rather than document order, so
  an explicit `autocomplete=username` beats a bare text input that happens to
  sit closer to the password. "Email / Company code / Password" used to fill
  the company code, and sign-ups saved the user's surname as their username.
- Identifier-first sign-ins (Google, Microsoft, Okta) are captured: the value
  typed at the identifier step is remembered for the password step, where the
  username box is hidden or static text and no username could be resolved.
- A "show password" toggle no longer offers to save before the form is
  submitted, nor blinds the real submit — password fields are tracked by
  element rather than by `type`.
- An update prompt names the account it would overwrite. With no username on
  the page the app resolves the target itself, and the user has to see which
  login that is before agreeing.
- Clicks on Arca's own picker, generated-password panel and save bar no longer
  count as submitting the page.
- A password box is no longer mistaken for its own username field. The tiers
  that find a username match on name, id and type, and several of those match
  the password itself: `name="user_password"` hits the "user" tier, and a "show
  password" toggle turns the box into `type=text`, which hits the last one.
  Filling then wrote the username into the password box and left the real login
  box empty, and capture read the password back out as the account name — so
  the save bar offered to store the password *as* the username. Only text,
  email, tel, url and search inputs are considered now, never the password
  field and never a checkbox called `remember_user`.
- On a page with no `<form>` — an ordinary React sign-in — an identifier binds
  to the password box that follows it, in its own tree. It used to take the
  first `current-password` box anywhere on the page, so on a page showing sign
  up above sign in, picking an account on the sign-in row filled a different
  widget entirely and left the box the user was typing in empty. A field inside
  a component's shadow root is never claimed by a light-DOM identifier.
- A pending save survives the service worker being evicted. Chromium stops an
  idle MV3 worker after about 30 seconds, and a sign-in that waits on a push
  approval before navigating is idle by that measure: the worker died holding
  the only copy of the captured password and no prompt ever appeared. It is now
  kept in `storage.session`, which is memory-only and never written to disk,
  exactly as the passkey gesture ledger already was.
- A captured password is no longer destroyed by the first page that cannot
  offer it. Reading it consumes it, and the checks that decide whether this
  document is the right place to prompt run afterwards — so a login landing on
  an interstitial that redirects again lost the password to the interstitial.
  It is put back, with its original age so the 90-second limit still expires on
  time, unless it has actually been offered.
- A manually typed password change is offered for saving. Capture used to
  require exactly one password field, so a current/new/confirm form (Portainer's
  account page, with no autocomplete hints and no username field) was invisible
  to save-on-submit and the changed password was stored nowhere. The new value is
  picked by field hints, falling back to the repeated new+confirm pair, and never
  by taking the current-password box; a confirm mismatch is a failed change and
  is not offered. An SPA that keeps the form mounted and clears its boxes on
  success now counts as settled, and a change that redirects to the site's
  sign-in page is offered there — unless the landing page is the change form
  itself, re-rendered with an error.
- Saving matches the stored login by the same origin rule as filling — scheme
  and port included — instead of by host alone. A username-less password reset
  on `nas.local:9443` used to update the sole login stored for `nas.local:443`,
  another service entirely, and leave that other service's URL on it.
- The save bar reports a failed save instead of closing as if it had worked.
  The probe and the click are separate moments: if the vault locked in between,
  the app's "locked" reply was swallowed, the bar vanished and nothing was
  written. The bar now keeps the captured password, says what happened and
  turns the button into "Unlock & Retry". A double click can no longer send the
  save twice.
- An update discovered after "Unlock & Save" is shown before it happens. While
  locked the app cannot say which stored account a username-less reset would
  overwrite; once unlocked it can, and the bar now names that account and waits
  for a second click rather than writing on the first.

- Passkeys work on a `www.` site again. The host is normalized for password
  matching by dropping `www.`, because `www.example.com` and `example.com` are
  one login to a person — but a passkey's relying-party ID is a name the page
  and the site agree on exactly, and a page that omits it gets its full
  hostname. Comparing the stripped host against the unstripped ID called every
  such ceremony an origin mismatch, so Arca never answered a sign-in on a
  `www.` site and any passkey already stored under one could not be used at
  all.
- A fingerprint that does not open the vault no longer hides the lock screen or
  starts a prompt loop. The result of the quick unlock was discarded and
  "unlocked" was announced regardless, so when quick unlock was not enabled or
  its device key no longer fit the vault, the app dropped its lock screen over
  a locked vault and the browser asked again every few seconds — a biometric
  prompt each time, none of which could ever work. It now falls back to the
  master password in Arca's own window, which is the only thing that says why.

### Desktop app

- **An automatic lock no longer discards an open editor.** With "lock when
  window loses focus" on, the ordinary way to use the generator destroyed the
  work: open New Login, generate a password, switch to the browser to paste it
  into the site's change-password form, come back — the dialog was gone and the
  password now live on that site was stored nowhere. The same dead end as a
  generated password the extension never saved, reached from the other side.
  The draft is kept in memory and the editor is restored on unlock. Closing the
  dialog still discards it; only the lock is treated as "hold this for me".
  Discarding was never the security win it looked like: dropping a React
  reference erases nothing, JavaScript strings cannot be zeroized, and the value
  was in the same webview heap before the lock. Nothing is written to disk.
- Errors are shown as errors. Every failure routed to the same green check for
  1.6 seconds, so "Could not read or write the vault file." looked exactly like
  "Copied". Failures now get their own colour, icon and a longer read, and the
  lock screen renders toasts at all — restore results were emitted after the
  vault locked and were never displayed.
- Locking from the sidebar emits the same lock event as the tray and the
  automatic locks. It used to stay silent, so decrypted items stayed in webview
  state and the lock screen immediately asked for Touch ID to reopen the vault
  the user had just deliberately locked.
- Idle auto-lock is no longer held off by background refreshes. Listing items,
  the security report and loading a detail ran on every `sync-merged` event, so
  a phone quietly editing entries kept a desktop unlocked indefinitely — the
  one situation idle-lock exists for.
- A revealed password is hidden again when the item changes, not just when the
  selection does. After an edit or a sync merge the old plaintext stayed on
  screen beside the new password's strength pill.
- Enter respects the same guards as the buttons it triggers: holding it in the
  SSH key dialog no longer generates a key per keypress, and a second Enter
  cannot start a concurrent backup restore or master-password change.
- Delete, restore, delete-forever and copy report their failures instead of
  failing silently and leaving the list disagreeing with what is on disk.

## 0.4.0 — 2026-09-01

### Data safety and security

- The vault format is now `SYBRVLT4`. Encrypted per-item revision ancestry
  distinguishes later edits from true concurrent sync edits; a real conflict
  preserves both values instead of silently discarding one. V1–V3 vaults remain
  readable, while older Arca builds refuse V4 rather than stripping metadata.
- Vault/KDF sizes and native bridge messages are bounded before expensive work
  or allocation. Independent writers share a file lock, lock failures no longer
  replace live items with an empty sealed state, and settings write failures are
  reported instead of ignored.
- Editors are type-safe: a login or bookmark editor cannot replace a passkey or
  another item kind. Autofill matches exact normalized hosts, and the desktop
  webview now rejects inline styles with a stricter CSP.
- Encrypted backups can be restored in-app. Arca verifies and decrypts the whole
  candidate first, refuses restore while Drive sync is connected, snapshots the
  current vault, replaces it atomically, and finishes locked.

### Bookmarks and autofill

- Bookmarks have structured, collapsible folders in Arca, with folders sorted
  first, folder suggestions, bulk move, edit support and note-aware search.
- The browser mirror serializes rebuild/cleanup operations and records every
  owned folder. Locking or disabling the mirror removes all proven Arca-owned
  copies, including a guarded one-time repair for folders orphaned by the old
  single-id race.
- The autofill picker stays inside the visual viewport near screen edges and
  zoomed layouts, works with Shadow DOM forms, and only offers password
  generation in appropriate new-password fields.

### Bridge

- **The local bridge protocol is versioned.** It was a private arrangement
  between the app and its own native-messaging host, so an unversioned,
  undocumented wire format cost nothing. It stops being private as soon as
  something else opens the socket — a passkey client inside an Electron app
  cannot use native messaging, so it connects directly — and then a change here
  breaks something over there with no signal but "passkeys stopped working". The
  handshake now states a version in both directions and refuses a peer it was not
  written against. Both sides treat an absent version as v1, so an old host and a
  new app, or the reverse, still work.

### Passkeys

- **Signing in to Microsoft 365 works.** Two separate bugs stacked on top of
  each other, and both were invisible from inside Arca, which reported success
  either way.

  The first was the gesture check. Entra does not run the ceremony on the page
  you click: it navigates to `login.microsoft.com/common/bridge/fido`, and *that*
  page fires `get()` on load. The gesture was tracked inside the page, so it died
  with the page and every M365 sign-in fell through to the browser — on Linux
  into the QR / security-key dialog, because there is no platform authenticator
  to catch it quietly. The gesture now lives in a per-tab ledger that outlives
  the navigation, and is still spent once per ceremony.

  The second was the credential itself. Arca handed the site an object literal
  with the right fields but no `toJSON()` and the wrong prototype, so
  `instanceof PublicKeyCredential` was false. The ceremony completed, Arca said
  it had signed you in, and the site's own code threw while handling the answer.
  It is now a conforming credential.
- **Per-site control over passkeys**, in the extension popup: ask (the default),
  always, or never. `never` is the way to keep Arca out of a site whose page
  fires passkey probes you do not want. This only decides who answers a
  ceremony — the vault must still be unlocked and the app must still approve.
- **A refused registration says so.** When a site tried to register a passkey
  Arca already held for that account, Arca refused silently and the page said
  "you already have a passkey" — which is wrong whenever the *site* is the one
  that lost it, and left no hint that the way out is to delete Arca's copy
  first. Arca now tells you.
- Every ceremony Arca declines to answer logs why, at `console.debug`. A missing
  gesture, a locked vault, no passkey for the site and a per-site "never" were
  previously all the same silence.
- **Firefox gets passkeys at all.** The Firefox manifest shipped without the
  passkey content scripts, so the feature had never worked there. Adding them
  needs `world: "MAIN"`, which raises the minimum Firefox to 128.

## 0.3.0 — 2026-07-28

The first published release. Earlier versions existed only as builds on the
author's own machine, so there is nothing to upgrade *from* yet; auto-update
starts working from here.

### Data safety

- **A permanently deleted credential no longer comes back.** Emptying the Trash
  removed the item and left nothing behind, so the next sync with a device that
  still held it put it straight back — worst for exactly the password someone
  destroys on purpose. A hard delete now leaves a record (an id and a timestamp,
  nothing derived from the secret) that travels with the vault. An edit made
  *after* the deletion still wins, the same rule a soft delete already followed.
- **A vault written by a newer Arca is refused instead of overwritten.** An
  unreadable remote copy is treated as a half-finished upload and replaced,
  which is right for a torn file and catastrophic for one written by a version
  that knows more than this build does. Unknown-but-ours containers are now
  refused; genuinely foreign bytes are still replaced.
- The vault file format is now `SYBRVLT3`. Older files open unchanged and are
  upgraded on the next save. **Older builds cannot read the new file**, so this
  is one-way — the automatic snapshot taken before every save is the way back.

### Passkeys

- **The GitHub passkey prompt loop is fixed.** Declining used to silence a site
  for a flat 90 seconds and then ask again, forever. It now escalates — 90
  seconds, 15 minutes, an hour, then silent for that site for the rest of the
  session — and Arca says so rather than going quiet unexplained. A successful
  sign-in clears it; quitting Arca resets it.
- The browser extension no longer treats "the user clicked something in the last
  five seconds" as "the user asked for this passkey". It watches for real input
  itself, on a tighter window, and uses the gesture up: one click, one ceremony.

### iOS

- The iOS app can now **add, edit and delete logins**, not just read them
  (C ABI v6), and **syncs with Google Drive** using its own OAuth client. It
  runs in the simulator. No device has run it and no sign-in has completed from
  a phone yet — see [`docs/IOS.md`](./docs/IOS.md).

### Under the hood

- Auto-update is wired: this build can be replaced by the next one without
  reinstalling by hand.
- `vault-sync` is its own crate, so the phone and the desktop share one sync
  engine instead of the desktop hiding it.
- The Google OAuth client secret is no longer in the source. It is supplied at
  build time; a build without it works completely except that Drive sync
  refuses to connect, and says so. See [`docs/SYNC.md`](./docs/SYNC.md).

### Still true, and worth repeating

Arca has **not been independently audited**. Read [`SECURITY.md`](./SECURITY.md)
and [`THREAT_MODEL.md`](./THREAT_MODEL.md) before trusting it with real secrets.
