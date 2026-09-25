/* vault-ffi — C ABI over vault-core for native platform integrations.
 *
 * Hand-maintained to match crates/vault-ffi/src/lib.rs (ABI version 16). All
 * out-buffers are heap-allocated by the library and must be released with
 * vault_ffi_free(ptr, len), which also zeroes them.
 *
 * ABI_VERSION in lib.rs is the authority, and vault_ffi_abi_version() reports
 * it at runtime; clients should refuse to run against a number they were not
 * written for. Tests in lib.rs check that this file names the same version and
 * declares every exported symbol, because "hand-maintained" is otherwise a
 * promise nothing enforces — this comment claimed v2 for a v3 library.
 *
 * Return codes:
 *    0  OK
 *   -1  null argument
 *   -2  invalid UTF-8 in a C string argument
 *   -3  operation failed (unrecognized format / generic)
 *   -4  vault is locked
 *   -5  item not found
 *   -6  a panic was caught at the boundary
 *   -7  decryption failed (wrong key / not a device-unlock vault / tampered)
 *   -8  device key was not 32 bytes
 *   -9  a sync cycle failed; the reason is in the status JSON's lastError
 */
#ifndef VAULT_FFI_H
#define VAULT_FFI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t vault_ffi_abi_version(void);

void vault_ffi_free(uint8_t *ptr, size_t len);

/* ---- Passwords surface (ABI v2) ----------------------------------------
 *
 * Opaque handle to an unlocked vault. Vault open/unlock is done here because
 * Swift can't run Argon2id/XChaCha20; Swift supplies the encrypted file bytes
 * (read from the shared App Group container) and the 32-byte device key (from
 * the shared keychain).
 *
 * OWNERSHIP / THREADING (relaxed in ABI v5): the vault behind a VaultHandle is
 * internally synchronized, so calls on one handle from different threads no
 * longer need external locking — which is what makes it safe to sync on a
 * background thread while the UI reads. vault_ffi_vault_free must still NOT
 * overlap any other call on the same handle, and must be called exactly once.
 *
 * Note that from v5 a handle's CONTENTS can change underneath you: a sync
 * merges a peer's items into the very vault the handle exposes, so a list taken
 * before a sync may be stale afterwards. A read that lands during the merge
 * BLOCKS until it finishes (milliseconds, and no network happens inside that
 * window) — one more reason not to call this from a UI thread.
 *
 * While the handle is open the decrypted vault (passwords included) is resident
 * in memory, so open, fetch the one password you need, and free the handle
 * promptly. */
typedef struct VaultHandle VaultHandle;

/* Open + unlock a vault from its raw file bytes with a 32-byte device key.
 * On OK, *out_handle is a handle to release with vault_ffi_vault_free. */
int32_t vault_ffi_vault_open(const uint8_t *vault_bytes, size_t vault_len,
                             const uint8_t *device_key, size_t device_key_len,
                             VaultHandle **out_handle);

/* ADDED IN ABI v3, purely additive.
 * Open + unlock from the MASTER PASSWORD (NUL-terminated UTF-8). Needed by any
 * client that has no device key yet - a phone on first launch, a recovery tool.
 * Runs Argon2id with the header's parameters, so it takes hundreds of ms: call
 * it off the UI thread. On OK, *out_handle is a handle to release with
 * vault_ffi_vault_free. */
int32_t vault_ffi_vault_open_password(const uint8_t *vault_bytes, size_t vault_len,
                                      const char *password,
                                      VaultHandle **out_handle);

/* Lock + free a handle (zeroizes the vault key and all decrypted items).
 * Null-safe. */
void vault_ffi_vault_free(VaultHandle *handle);

/* All login identities as UTF-8 JSON, METADATA ONLY (never a secret):
 *   [ {"id":"<uuid>","user":"<username>","domain":"<host>","label":"<title>"} ]
 * Out-buffer freed by the caller with vault_ffi_free. */
int32_t vault_ffi_identities(VaultHandle *handle, uint8_t **out_json,
                             size_t *out_json_len);

/* Every active item, of EVERY kind, as JSON. Metadata only, never a secret:
 * [{ id, kind, title, subtitle, url, has_totp }] where kind is one of
 * "login" | "passkey" | "ssh_key" | "wifi" | "secure_note".
 *
 * Distinct from vault_ffi_identities, which stays logins-only because it feeds
 * the platform credential store. This is what an app's own list should call.
 * Free with vault_ffi_free. */
int32_t vault_ffi_items(VaultHandle *handle, uint8_t **out_json,
                        size_t *out_json_len);

/* The full payload of one item, tagged by kind, as JSON.
 *
 * SECRET: carries the Wi-Fi password and note body in the clear. An SSH item's
 * PRIVATE key deliberately does NOT cross — a phone has no ssh-agent to spend
 * it with. Free with vault_ffi_free. */
int32_t vault_ffi_item_detail(VaultHandle *handle, const char *id_utf8,
                              uint8_t **out_json, size_t *out_json_len);

/* The live TOTP code for a login: { code, period, remaining }. The TOTP SECRET
 * never crosses; only the derived code, which expires. ERR_NOT_FOUND when the
 * id is unknown, is not a login, or has no TOTP. Free with vault_ffi_free. */
int32_t vault_ffi_totp(VaultHandle *handle, const char *id_utf8,
                       uint8_t **out_json, size_t *out_json_len);

/* The password for one identity id (the "id" from vault_ffi_identities).
 * SECRET: the buffer is zeroed by vault_ffi_free; copy it into the platform
 * credential and do not retain it. -5 (not found) for an unknown id. */
int32_t vault_ffi_password_for_id(VaultHandle *handle, const char *id_utf8,
                                  uint8_t **out_password,
                                  size_t *out_password_len);

/* ---- Password generation (ABI v8) ---------------------------------------
 *
 * No vault handle: you want a generated password while creating the account,
 * which is before there is anywhere to save it. Flags are 0/1. Returns
 * ERR_INVALID for length 0 or all four classes off. SECRET — free with
 * vault_ffi_free, which zeroes.
 */
int32_t vault_ffi_generate_password(size_t length, int32_t lowercase,
                                    int32_t uppercase, int32_t digits,
                                    int32_t symbols, uint8_t **out_password,
                                    size_t *out_password_len);

/* ---- Generation against a site's rules (ABI v9) -------------------------
 *
 * `rules_utf8` is Apple's Password Rules format, the same string iOS passes to
 * an AutoFill extension and HTML fields carry in `passwordrules`. Empty or
 * unparseable yields a strong default, never an error. SECRET — free with
 * vault_ffi_free.
 */
int32_t vault_ffi_generate_password_for_rules(const char *rules_utf8,
                                              size_t default_length,
                                              uint8_t **out_password,
                                              size_t *out_password_len);

/* ---- Passkeys by handle (ABI v10) ----------------------------------------
 *
 * What lets a phone SIGN IN with a stored passkey. The v1 passkey surface
 * takes the private key as an argument, because the macOS extension receives
 * it from the app process; on iOS the extension owns the vault handle, and the
 * key must never cross into Swift.
 *
 * vault_ffi_passkey_identities: every passkey's metadata as JSON —
 *   [{ id, rp_id, user_name, user_handle, credential_id }], binary fields
 *   base64. Not secret; feeds ASCredentialIdentityStore.
 *
 * vault_ffi_passkey_assert_for_id: a WebAuthn assertion by item id. On OK the
 *   JSON is { credential_id, user_handle, authenticator_data, signature },
 *   base64. -5 if the id is unknown or not a passkey. user_verified is 0/1.
 * Free both with vault_ffi_free. */
int32_t vault_ffi_passkey_identities(VaultHandle *handle, uint8_t **out_json,
                                     size_t *out_json_len);

/* TOTP semantics of vault_ffi_upsert_login, CHANGED in ABI v11:
 *   totp_secret == NULL  keeps the existing secret (the edit did not touch it)
 *   totp_secret == ""    clears it
 *   otpauth:// URIs      are normalized to their Base32 secret; a malformed
 *                        URI is refused with -3 rather than stored broken.
 * Before v11 NULL cleared the secret, so any client that did not round-trip
 * it destroyed the code on every edit — and the detail surface deliberately
 * never hands the secret out, so round-tripping was impossible. */

int32_t vault_ffi_passkey_assert_for_id(VaultHandle *handle,
                                        const char *id_utf8,
                                        const uint8_t *client_data_hash,
                                        size_t client_data_hash_len,
                                        int32_t user_verified,
                                        uint8_t **out_json,
                                        size_t *out_json_len);

/* ---- Device-unlock surface (ABI v4) -------------------------------------
 *
 * Lets a client that opened with the MASTER PASSWORD mint its own quick-unlock
 * key, instead of waiting for some other process to put one in the keychain.
 * On a phone there is no other process, so without this every AutoFill costs
 * the user their master password and an Argon2id derivation.
 *
 * Still no I/O here: the new vault file bytes come back for the CALLER to
 * persist. The caller owns the atomic write and the ordering. Write the vault
 * file BEFORE storing the key: a vault carrying a wrapping whose key was never
 * saved is harmless (the master password still opens it), whereas a stored key
 * for a vault that was never written opens nothing. */

/* Turn on quick unlock. Mints a fresh 32-byte device key, wraps the vault key
 * with it, and returns BOTH the key and the new vault file bytes. Both are
 * freed with vault_ffi_free.
 *
 * The master password keeps working — this adds a second wrapping of the same
 * vault key, it does not replace the first.
 *
 * SECRET: *out_device_key opens the vault without the master password. Put it
 * straight into the platform keychain behind a biometric access control.
 *
 * The returned bytes are verified to reopen with the returned key before they
 * are handed back, so a caller can never be given a vault it cannot unlock. */
int32_t vault_ffi_enable_device_unlock(VaultHandle *handle,
                                       uint8_t **out_device_key,
                                       size_t *out_device_key_len,
                                       uint8_t **out_vault_bytes,
                                       size_t *out_vault_bytes_len);

/* Turn quick unlock off: drop the device-wrapped key from the header and return
 * the new vault file bytes. Deleting the keychain item alone is NOT enough —
 * the wrapping would stay in the file and travel to every device the vault
 * syncs to. The master password is unaffected. */
int32_t vault_ffi_disable_device_unlock(VaultHandle *handle,
                                        uint8_t **out_vault_bytes,
                                        size_t *out_vault_bytes_len);

/* 1 if the vault carries a device-wrapped key, 0 if not, negative on error.
 * Ask this rather than trusting the keychain: a key can outlive the vault that
 * accepted it (restored from a backup), and a client that trusts the keychain
 * alone prompts for a biometric and then fails. */
int32_t vault_ffi_has_device_unlock(VaultHandle *handle);

/* ---- Sync surface (ABI v5) -----------------------------------------------
 *
 * The pull -> merge -> push cycle against the user's own Google Drive. This is
 * the only surface that performs I/O, and only NETWORK I/O: it talks to Google,
 * never to the filesystem. Drive holds CIPHERTEXT ONLY — the vault is sealed
 * before it leaves the device, and the scope is drive.appdata, so Arca sees its
 * own hidden folder and nothing else in the account.
 *
 * Everything network-shaped stays below this line: the REST calls, the TLS, the
 * token refresh, the retry policy. Two things do not, because they have no
 * portable form:
 *
 *   - the interactive sign-in. vault_ffi_sync_auth_begin hands back a URL and
 *     keeps the PKCE verifier; open it however the platform does
 *     (ASWebAuthenticationSession on iOS, a loopback listener on desktop) and
 *     return the code to vault_ffi_sync_auth_finish. The verifier never crosses
 *     this boundary.
 *   - storage. The refresh token comes back for your keychain, merged vault
 *     bytes come back for your file.
 *
 * THREADING: vault_ffi_sync_now and vault_ffi_sync_auth_finish block on the
 * network. Call them off the UI thread — on iOS an AutoFill extension that
 * blocks its main thread is killed by the watchdog, not merely slow. */

/* Opaque sync engine bound to one open vault. */
typedef struct SyncHandle SyncHandle;

/* An interactive sign-in in progress (holds the PKCE verifier). */
typedef struct SyncAuth SyncAuth;

/* Create a sync engine over an already-open vault. Starts DISCONNECTED: call
 * vault_ffi_sync_set_credential before vault_ffi_sync_now will do anything.
 *
 * The engine shares the handle's vault rather than copying it, so a merge is
 * visible to vault_ffi_identities on that handle with no reload — and the vault
 * handle may be freed while this one lives. */
int32_t vault_ffi_sync_new(VaultHandle *vault, SyncHandle **out_handle);

/* Free a sync handle. Null-safe, call exactly once, and never while
 * vault_ffi_sync_now is running on another thread. */
void vault_ffi_sync_free(SyncHandle *handle);

/* Set (or clear) the credential. refresh_token NULL DISCONNECTS: the cached
 * access token is dropped and the account forgotten. account is a display label
 * and may be NULL. Connecting resets the engine's bookkeeping — a remote
 * checksum recorded against one Google account means nothing under another. */
int32_t vault_ffi_sync_set_credential(SyncHandle *handle,
                                      const char *refresh_token,
                                      const char *account);

/* Local vault state changed and should be pushed on the next cycle. */
void vault_ffi_sync_mark_dirty(SyncHandle *handle);

/* Status as UTF-8 JSON, no network:
 *   {"connected":bool,"account":string|null,"lastSyncUnix":number|null,
 *    "lastError":string|null,"merged":false}
 * merged is always false here; only vault_ffi_sync_now can merge. */
int32_t vault_ffi_sync_status(SyncHandle *handle, uint8_t **out_json,
                              size_t *out_json_len);

/* Run one pull -> merge -> push cycle. BLOCKING, network I/O.
 *
 * *out_status_json is always produced, so a failed cycle still reports why.
 *
 * *out_vault_bytes is non-NULL ONLY when remote changes were merged, and is
 * then the new vault file to persist. Write it: the merge is already live in
 * the shared vault, so skipping the write leaves memory ahead of disk. Bytes
 * come back on failure too when a merge happened before the failure did.
 *
 * Returns 0, or -9 with the reason in the status JSON. */
int32_t vault_ffi_sync_now(SyncHandle *handle, uint8_t **out_vault_bytes,
                           size_t *out_vault_bytes_len,
                           uint8_t **out_status_json,
                           size_t *out_status_json_len);

/* Begin a sign-in: returns the authorization URL to open, and a handle holding
 * the PKCE verifier. redirect_uri is whatever the platform can catch (a custom
 * URL scheme on iOS, http://127.0.0.1:<port> on desktop); it is remembered, so
 * finish cannot disagree with begin about it. */
int32_t vault_ffi_sync_auth_begin(const char *redirect_uri, uint8_t **out_url,
                                  size_t *out_url_len, SyncAuth **out_auth);

/* Finish a sign-in: redeem code, return the refresh token and the account's
 * email. BLOCKING, network I/O.
 *
 * SECRET: *out_refresh_token grants access to the synced ciphertext until the
 * user revokes it. Put it straight into the platform keychain and free it with
 * vault_ffi_free, which zeroes it. It is the value to hand to
 * vault_ffi_sync_set_credential.
 *
 * *out_account is a display label and may come back NULL — the lookup is a
 * second request, and losing it must not fail a sign-in that succeeded.
 *
 * The verifier is single-use; a second call is rejected by the server. */
int32_t vault_ffi_sync_auth_finish(SyncAuth *auth, const char *code,
                                   uint8_t **out_refresh_token,
                                   size_t *out_refresh_token_len,
                                   uint8_t **out_account,
                                   size_t *out_account_len);

/* Free a sign-in handle, zeroizing the PKCE verifier. Null-safe. */
void vault_ffi_sync_auth_free(SyncAuth *auth);

/* Create a passkey for rp_id. Out-pairs (freed by the caller):
 *   credential_id, private_key (SEC1 P-256, 32 bytes — store encrypted!),
 *   attestation_object (CBOR, fmt "none"). */
int32_t vault_ffi_passkey_create(const char *rp_id, bool user_verified,
                                 uint8_t **out_credential_id,
                                 size_t *out_credential_id_len,
                                 uint8_t **out_private_key,
                                 size_t *out_private_key_len,
                                 uint8_t **out_attestation_object,
                                 size_t *out_attestation_object_len);

/* ---- Passkey registration into the vault (ABI v13) ----------------------
 *
 * vault_ffi_passkey_register: create a passkey for rp_id AND store it in the
 * vault in one call, returning the new vault bytes to persist plus the
 * credential id and CBOR attestation object for the relying party. Used by the
 * iOS AutoFill extension, which writes the shared App Group vault file itself;
 * splitting create from store would risk handing a site a credential whose key
 * never reached the vault. user_handle is opaque bytes (may be null/empty).
 * Existing credentials are retained, including keys for the same account.
 * The caller checks excludeCredentials before invoking this function. */
/* ---- Cross-process lost-update guard (ABI v14) --------------------------
 *
 * vault_ffi_merge_remote: fold another copy of THIS vault (read from the shared
 * file) into the in-memory handle before a write, so the app and the AutoFill
 * extension — separate processes over one file — stop clobbering each other's
 * committed writes. Same union/newest-wins merge as sync. ERR_DECRYPT if the
 * bytes are a different vault; OK no-op for null/empty. */
int32_t vault_ffi_merge_remote(VaultHandle *handle, const uint8_t *remote_bytes,
                               size_t remote_len);

/* ABI v16: history metadata, a single secret, and a prepared restore.
 * Restore returns ciphertext without changing the handle: persist first, then
 * merge it into the handle. Output buffers must be freed with vault_ffi_free. */
int32_t vault_ffi_password_history(VaultHandle *handle, const char *id_utf8,
    uint8_t **out, size_t *out_len);
int32_t vault_ffi_history_password(VaultHandle *handle, const char *id_utf8,
    const char *revision_utf8, uint8_t **out, size_t *out_len);
int32_t vault_ffi_restore_password_history(VaultHandle *handle, const char *id_utf8,
    const char *revision_utf8, int64_t now_millis, uint8_t **out, size_t *out_len);

/* ---- Merge-then-serialize in one step (ABI v15) -------------------------
 *
 * vault_ffi_merge_and_serialize: fold the on-disk copy in AND return the bytes
 * to write, so a caller holding the vault lock has no gap between the two.
 * vault_ffi_merge_remote returns nothing, so callers took their bytes from an
 * earlier call — and on the sync path those were serialized before a network
 * round-trip, silently overwriting whatever another process wrote during it.
 * remote_bytes may be null/empty (nothing on disk yet). The returned buffer is
 * verified re-openable and must be freed with vault_ffi_free. */
int32_t vault_ffi_merge_and_serialize(VaultHandle *handle,
                                      const uint8_t *remote_bytes,
                                      size_t remote_len,
                                      uint8_t **out_vault_bytes,
                                      size_t *out_vault_bytes_len);

int32_t vault_ffi_passkey_register(VaultHandle *handle, const char *rp_id,
                                   const char *user_name,
                                   const uint8_t *user_handle,
                                   size_t user_handle_len, bool user_verified,
                                   int64_t now_unix_millis,
                                   uint8_t **out_vault_bytes,
                                   size_t *out_vault_bytes_len,
                                   uint8_t **out_credential_id,
                                   size_t *out_credential_id_len,
                                   uint8_t **out_attestation_object,
                                   size_t *out_attestation_object_len);

/* Produce an assertion. Signature is DER ES256 over
 * (authenticatorData || client_data_hash). The signature counter is always 0
 * (synced credential), so there is nothing to persist. */
int32_t vault_ffi_passkey_assert(const uint8_t *private_key,
                                 size_t private_key_len, const char *rp_id,
                                 bool user_verified,
                                 const uint8_t *client_data_hash,
                                 size_t client_data_hash_len,
                                 uint8_t **out_authenticator_data,
                                 size_t *out_authenticator_data_len,
                                 uint8_t **out_signature,
                                 size_t *out_signature_len);

/* ---- Write surface (ABI v6) ---------------------------------------------
 *
 * Everything else reads. A client that can only read is a viewer, not a
 * password manager: it cannot save the login you just created on your phone.
 *
 * Same contract as the device-unlock surface: the in-memory vault is mutated
 * and NEW VAULT FILE BYTES come back for the caller to persist. Nothing is
 * written here — vault-core is I/O-free. On failure the handle is rolled back,
 * so it never drifts from the last state you persisted.
 *
 * Timestamps are the caller's (milliseconds since the Unix epoch); this library
 * has no clock. */

/* Insert or update a login.
 *
 * id            NULL or "" creates a new item; otherwise the UUID to overwrite
 *               (ERR_NOT_FOUND if it is unknown or is not a login).
 * totp_secret   NULL or "" stores no secret (never Some("")).
 * notes         NULL is treated as "".
 * out_id        The item's UUID as ASCII text, for a create or an edit.
 *
 * Both out-buffers must be released with vault_ffi_free(). */
int32_t vault_ffi_upsert_login(VaultHandle *handle, const char *id,
                               const char *title, const char *username,
                               const char *password, const char *url,
                               const char *totp_secret, const char *notes,
                               int64_t now_unix_millis,
                               uint8_t **out_vault_bytes,
                               size_t *out_vault_bytes_len, uint8_t **out_id,
                               size_t *out_id_len);

/* ---- Single-kind upserts (ABI v12) ---------------------------------------
 *
 * Create (id NULL/"") or edit in place (id set; wrong/missing kind -> -5) a
 * Wi-Fi entry or secure note, with the same returned-bytes persistence
 * contract as vault_ffi_upsert_login. `security` is the join-QR token: "WPA",
 * "WEP" or "nopass"; empty means WPA. `hidden` is 0/1. */
int32_t vault_ffi_upsert_wifi(VaultHandle *handle, const char *id,
                              const char *title, const char *ssid,
                              const char *password, const char *security,
                              int32_t hidden, const char *notes,
                              int64_t now_unix_millis,
                              uint8_t **out_vault_bytes,
                              size_t *out_vault_bytes_len, uint8_t **out_id,
                              size_t *out_id_len);

int32_t vault_ffi_upsert_secure_note(VaultHandle *handle, const char *id,
                                     const char *title, const char *body,
                                     int64_t now_unix_millis,
                                     uint8_t **out_vault_bytes,
                                     size_t *out_vault_bytes_len,
                                     uint8_t **out_id, size_t *out_id_len);

/* Soft-delete an item: it moves to the Trash and stays restorable. */
int32_t vault_ffi_delete_item(VaultHandle *handle, const char *id,
                              int64_t now_unix_millis,
                              uint8_t **out_vault_bytes,
                              size_t *out_vault_bytes_len);

#ifdef __cplusplus
}
#endif

#endif /* VAULT_FFI_H */
