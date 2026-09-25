// Swift side of the sync surface (vault-ffi ABI v5, `vault_ffi_sync_*`).
//
// The whole cycle — the Drive REST calls, TLS, token refresh, retry policy —
// runs in Rust. Swift supplies only the two things that have no portable form:
// the interactive sign-in (iOS cannot bind a loopback socket, so it needs
// ASWebAuthenticationSession) and storage (the refresh token goes in the
// keychain, merged vault bytes go in the app group container).
//
// Everything here is `async` and runs on `VaultSession`'s serial queue. Two
// reasons, the same two as the rest of the bridge: a sync cycle blocks on the
// network, and the C ABI forbids overlapping calls on one handle.

import Foundation
import os

#if canImport(AuthenticationServices)
import AuthenticationServices
#endif

private let syncLog = Logger(subsystem: "no.sybr.vault", category: "sync")

enum SyncError: Error {
    case ffi(code: Int32, operation: String)
    case decode
    /// The sign-in was dismissed by the user. Not a failure worth shouting about.
    case cancelled
    case noRedirect
}

/// A sync engine bound to one open vault.
///
/// Freed on deinit. The engine shares the session's vault rather than copying
/// it, so a merge is immediately visible through the same session — no reload,
/// but also no way to have two engines disagree.
final class VaultSync: @unchecked Sendable {
    private let handle: OpaquePointer
    /// The session whose vault this engine shares.
    ///
    /// Held strongly for two reasons: the write-back below needs the VAULT
    /// handle (not the sync handle) to re-serialize under the lock, and keeping
    /// the session alive is what stops that handle from being freed underneath
    /// the engine. No cycle — a session never holds its engine.
    private let session: VaultSession

    fileprivate init(handle: OpaquePointer, session: VaultSession) {
        self.handle = handle
        self.session = session
    }

    deinit { vault_ffi_sync_free(handle) }

    // MARK: Credential

    /// Point the engine at a Google account. Persisting the token is the
    /// caller's job (see `SyncCredentialStore`) — this only hands it to Rust.
    func connect(refreshToken: String, account: String?) async throws {
        try await VaultSession.runSync {
            let code = refreshToken.withCString { token in
                if let account {
                    return account.withCString { vault_ffi_sync_set_credential(self.handle, token, $0) }
                }
                return vault_ffi_sync_set_credential(self.handle, token, nil)
            }
            guard code == VaultFFICode.ok else {
                throw SyncError.ffi(code: code, operation: "sync_set_credential")
            }
        }
    }

    /// Forget the account: the cached access token is dropped Rust-side. The
    /// caller must delete the keychain item too, or the next launch reconnects.
    func disconnect() async throws {
        try await VaultSession.runSync {
            let code = vault_ffi_sync_set_credential(self.handle, nil, nil)
            guard code == VaultFFICode.ok else {
                throw SyncError.ffi(code: code, operation: "sync_disconnect")
            }
        }
    }

    /// Local changes exist and should be pushed on the next cycle.
    func markDirty() async {
        try? await VaultSession.runSync { vault_ffi_sync_mark_dirty(self.handle) }
    }

    // MARK: Cycle

    func status() async throws -> SyncStatus {
        try await VaultSession.runSync {
            var json: UnsafeMutablePointer<UInt8>?
            var length = 0
            let code = vault_ffi_sync_status(self.handle, &json, &length)
            guard code == VaultFFICode.ok, let json else {
                throw SyncError.ffi(code: code, operation: "sync_status")
            }
            defer { vault_ffi_free(json, length) }
            return try Self.decode(json, length)
        }
    }

    /// One pull → merge → push cycle. Blocking and network-bound.
    ///
    /// Writes the vault file when the merge produced new bytes. That write is
    /// not optional: the merge is already live in the shared vault, so skipping
    /// it would leave memory ahead of disk — and the next launch would silently
    /// lose whatever a peer had just sent.
    @discardableResult
    func syncNow() async throws -> SyncStatus {
        try await VaultSession.runSync {
            var vault: UnsafeMutablePointer<UInt8>?
            var vaultLength = 0
            var json: UnsafeMutablePointer<UInt8>?
            var jsonLength = 0
            let code = vault_ffi_sync_now(self.handle, &vault, &vaultLength, &json, &jsonLength)
            defer {
                if let vault { vault_ffi_free(vault, vaultLength) }
                if let json { vault_ffi_free(json, jsonLength) }
            }
            // Bytes come back on failure too, when a merge happened before the
            // failure did — so persist before deciding whether to throw.
            //
            // These bytes are NOT what gets written. They were serialized from
            // the handle at the end of a cycle that began seconds earlier, and
            // anything another process committed to the shared file in between
            // — an AutoFill passkey registration, most concretely — is absent
            // from them. Writing them verbatim erased it, permanently, because
            // the extension process was long gone. Instead: take the vault
            // lock, fold whatever is on disk NOW into the handle, and serialize
            // that. Merge and write become one step no other process can split.
            if vaultLength > 0, vault != nil {
                try VaultShared.withVaultLock {
                    let disk = (try? VaultShared.loadVault()) ?? Data()
                    var merged: UnsafeMutablePointer<UInt8>?
                    var mergedLength = 0
                    let mergeCode = disk.withUnsafeBytes { buf in
                        vault_ffi_merge_and_serialize(
                            self.session.rawHandle,
                            buf.bindMemory(to: UInt8.self).baseAddress,
                            buf.count,
                            &merged,
                            &mergedLength)
                    }
                    guard mergeCode == VaultFFICode.ok, let merged, mergedLength > 0 else {
                        throw SyncError.ffi(code: mergeCode, operation: "merge_and_serialize")
                    }
                    defer { vault_ffi_free(merged, mergedLength) }
                    try VaultShared.writeVault(Data(bytes: merged, count: mergedLength))
                }
            }
            guard let json else {
                throw SyncError.ffi(code: code, operation: "sync_now")
            }
            // A failed cycle still reports why, so the status is worth decoding
            // even when the call failed.
            return try Self.decode(json, jsonLength)
        }
    }

    private static func decode(_ bytes: UnsafeMutablePointer<UInt8>, _ length: Int) throws
        -> SyncStatus
    {
        guard let status = try? JSONDecoder().decode(
            SyncStatus.self, from: Data(bytes: bytes, count: length))
        else { throw SyncError.decode }
        return status
    }
}

extension VaultSession {
    /// A sync engine over this session's vault.
    func makeSync() async throws -> VaultSync {
        try await Self.runSync {
            var out: OpaquePointer?
            let code = vault_ffi_sync_new(self.rawHandle, &out)
            guard code == VaultFFICode.ok, let out else {
                throw SyncError.ffi(code: code, operation: "sync_new")
            }
            return VaultSync(handle: out, session: self)
        }
    }
}

// MARK: - The refresh token's home

/// The refresh token in the keychain.
///
/// Deliberately NOT behind a biometric ACL, unlike the device key: the
/// background sync loop needs it without a face in front of the phone, and it
/// unlocks only the *ciphertext* on Google's servers — useless without the
/// master password. `afterFirstUnlockThisDeviceOnly` so a sync can run in the
/// background but the token never leaves this device in a backup.
enum SyncCredentialStore {
    private static let service = "no.sybr.vault.sync"
    private static let account = "google-refresh-token"

    private static func query() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    static func save(_ token: String) throws {
        SecItemDelete(query() as CFDictionary)
        var add = query()
        add[kSecValueData as String] = Data(token.utf8)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw SyncError.ffi(code: Int32(status), operation: "keychain_add")
        }
    }

    static func load() -> String? {
        var q = query()
        q[kSecReturnData as String] = true
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess,
              let data = out as? Data
        else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    static func delete() { SecItemDelete(query() as CFDictionary) }

    /// Whether a token exists, without reading it.
    static var exists: Bool {
        var q = query()
        q[kSecReturnAttributes as String] = true
        return SecItemCopyMatching(q as CFDictionary, nil) == errSecSuccess
    }
}

// MARK: - Interactive sign-in

#if canImport(AuthenticationServices) && !os(macOS)

/// The one step that cannot live in Rust: opening Google's consent page and
/// catching the redirect.
///
/// `vault_ffi_sync_auth_begin` builds the URL and keeps the PKCE verifier —
/// which never crosses the boundary — and `_finish` redeems the code. Only the
/// middle is ours.
/// Owns a `SyncAuth*` so it can cross onto the vault queue: an OpaquePointer is
/// not Sendable, but a class that vouches for it is. Frees on deinit, which also
/// zeroizes the PKCE verifier — single-use, and a leak keeps a secret alive for
/// the process lifetime.
private final class SyncAuthBox: @unchecked Sendable {
    let pointer: OpaquePointer
    init(_ pointer: OpaquePointer) { self.pointer = pointer }
    deinit { vault_ffi_sync_auth_free(pointer) }
}

@MainActor
final class SyncSignIn: NSObject, ASWebAuthenticationPresentationContextProviding {
    /// Google accepts exactly one redirect for an iOS OAuth client: its own
    /// reversed client id. Not a scheme we chose — the client id decides it, so
    /// this string, `CFBundleURLSchemes` in Info.plist, and `REDIRECT_URI` in
    /// vault-sync's drive.rs all have to carry the same value.
    ///
    /// Getting it wrong is not subtle: Google answers `400
    /// redirect_uri_mismatch` on the consent page, which is exactly what the
    /// desktop client's loopback redirect did here before this client existed.
    nonisolated static let redirectURI = "com.googleusercontent.apps.269591410733-ltlkje5t7p8gajnp8vvk3gp9223nheu7:/oauth2redirect"
    nonisolated private static let scheme = "com.googleusercontent.apps.269591410733-ltlkje5t7p8gajnp8vvk3gp9223nheu7"

    private var session: ASWebAuthenticationSession?

    func presentationAnchor(for _: ASWebAuthenticationSession) -> ASPresentationAnchor {
        // The active foreground window; an extension has none, which is why
        // signing in is an app-only affordance.
        let scene = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .first { $0.activationState == .foregroundActive }
        return scene?.keyWindow ?? ASPresentationAnchor()
    }

    /// Run the whole sign-in and hand back the refresh token + display label.
    func run() async throws -> (refreshToken: String, account: String?) {
        // SyncAuthBox owns the verifier and frees it when this scope ends,
        // however it ends.
        let (url, auth) = try await Self.begin()
        let code = try await present(url)
        return try await Self.finish(auth, code: code)
    }

    nonisolated private static func begin() async throws -> (URL, SyncAuthBox) {
        try await VaultSession.runSync {
            var urlBytes: UnsafeMutablePointer<UInt8>?
            var urlLength = 0
            var auth: OpaquePointer?
            let code = redirectURI.withCString {
                vault_ffi_sync_auth_begin($0, &urlBytes, &urlLength, &auth)
            }
            guard code == VaultFFICode.ok, let urlBytes, let auth else {
                throw SyncError.ffi(code: code, operation: "sync_auth_begin")
            }
            defer { vault_ffi_free(urlBytes, urlLength) }
            // Box it first, so an unparseable URL still frees the verifier.
            let box = SyncAuthBox(auth)
            guard let url = URL(string: String(
                decoding: Data(bytes: urlBytes, count: urlLength), as: UTF8.self))
            else { throw SyncError.decode }
            return (url, box)
        }
    }

    private func present(_ url: URL) async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(
                url: url, callbackURLScheme: Self.scheme
            ) { callback, error in
                if let error {
                    let cancelled = (error as? ASWebAuthenticationSessionError)?.code
                        == .canceledLogin
                    continuation.resume(throwing: cancelled ? SyncError.cancelled : error)
                    return
                }
                guard let callback,
                      let code = URLComponents(url: callback, resolvingAgainstBaseURL: false)?
                          .queryItems?.first(where: { $0.name == "code" })?.value
                else {
                    continuation.resume(throwing: SyncError.noRedirect)
                    return
                }
                continuation.resume(returning: code)
            }
            session.presentationContextProvider = self
            // A private session would make the user sign in to Google every
            // time; this is their own account on their own phone.
            session.prefersEphemeralWebBrowserSession = false
            self.session = session
            if !session.start() {
                continuation.resume(throwing: SyncError.noRedirect)
            }
        }
    }

    nonisolated private static func finish(_ auth: SyncAuthBox, code: String) async throws
        -> (refreshToken: String, account: String?)
    {
        try await VaultSession.runSync {
            var token: UnsafeMutablePointer<UInt8>?
            var tokenLength = 0
            var account: UnsafeMutablePointer<UInt8>?
            var accountLength = 0
            let rc = code.withCString {
                vault_ffi_sync_auth_finish(auth.pointer, $0, &token, &tokenLength,
                                           &account, &accountLength)
            }
            guard rc == VaultFFICode.ok, let token else {
                throw SyncError.ffi(code: rc, operation: "sync_auth_finish")
            }
            // vault_ffi_free zeroes the token buffer.
            defer {
                vault_ffi_free(token, tokenLength)
                if let account { vault_ffi_free(account, accountLength) }
            }
            let refresh = String(decoding: Data(bytes: token, count: tokenLength), as: UTF8.self)
            // The label is a second request Rust makes; losing it must not fail
            // a sign-in that otherwise succeeded.
            let label = account.map {
                String(decoding: Data(bytes: $0, count: accountLength), as: UTF8.self)
            }
            return (refresh, label)
        }
    }
}

#endif
