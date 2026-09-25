# macOS passkeys and unlock — 0.6.2

The installed Arca app embeds the native credential provider. Browser WebAuthn
and native macOS AutoFill are separate entry points backed by the same vault.

## Unlock

The desktop authentication gate serializes competing unlock requests. Protected
quick unlock uses one keychain access-control read; it does not precede that read
with another LocalAuthentication prompt. Legacy quick unlock copies the key it
already authenticated to AutoFill. Publishing identities never reads that key
again. In the native picker, selecting an item reuses the session authenticated
when the picker opened; cancellation releases it.

## Native registration and account selection

`prepareInterface(forPasskeyRegistration:)` validates ES256 support and request
shape, authenticates once, and stores the new credential before completing the
system request. The exclusion list is checked against the latest shared state
while holding the shared file lock. Registration preserves existing credentials,
including another key for the same account. A later server rejection therefore
cannot invalidate an older working key.

Direct assertions bind the selected record to its relying party and credential
ID. The native passkey picker filters by RP and allowed credential IDs, then
requires an explicit account choice. Neither path selects an arbitrary first
account when multiple accounts are available.

## Persistence

The desktop's canonical file remains in application data. The AutoFill copy in
the App Group is a mirror, so the provider must not use that file alone as its
registration commit. On macOS, registration writes an immutable encrypted
snapshot to `passkey-inbox/<UUID>.vault`, flushes it and the containing directory,
and only then returns its attestation. No private key is stored outside the
encrypted vault format.

Native sessions merge pending snapshots under `default.vault.lock`, so a new key
can be used while the desktop is closed or locked. Every three seconds, an
unlocked desktop imports pending snapshots into a staged vault using the normal
authenticated merge. It acknowledges them only after saving the canonical file
and refreshing the AutoFill mirror. Failure retains the inbox for retry. The
import marks cloud sync dirty and refreshes desktop and native identities.

iOS continues to write its canonical shared vault directly.

## Verification and remaining manual acceptance

Automated coverage includes inbox survival across mirror overwrite and restart,
foreign-vault refusal, atomic Swift commit failures, file permissions, preservation
of old credentials, attestation/signature verification, and duplicate desktop
unlock requests. Mac/iOS builds and the full repository smoke suite are local
release gates; installed signing, provisioning and the live bridge are verified.

Manual acceptance still requires the owner to authenticate: unlock Arca and count
Touch ID prompts; create and use a passkey with the intended Google account;
select each UniFi account; cancel a ceremony; repeat after app restart. Build and
unit-test success alone do not demonstrate those real account ceremonies.
