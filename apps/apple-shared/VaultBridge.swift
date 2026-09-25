// Swift ↔ Rust bridge over vault-ffi (see crates/vault-ffi/include/vault_ffi.h).
//
// The Rust side owns all crypto; Swift only supplies the encrypted vault bytes
// (from the shared App Group container) and a key — either the device key from
// the shared keychain or the master password — then reads back login identities
// (metadata) and, on selection, one password. Shared by the host (populates the
// credential store) and the extension (fills). Secrets are copied straight into
// the platform credential and never retained.
//
// PORTABILITY: nothing here is macOS-only. An iOS app and its AutoFill
// extension link this file unchanged; the single platform difference (the
// data-protection keychain flag, which only macOS needs) is behind
// `#if os(macOS)`. See docs/IOS.md.
//
// CONCURRENCY: opening a vault blocks in three different ways — a keychain read
// that puts a Touch ID / Face ID prompt on screen and waits for the user, a file
// read, and (on the master-password path) Argon2id, which is *designed* to cost
// hundreds of milliseconds. None of it may run on the main actor: an AutoFill
// extension that wedges its main thread is killed by the watchdog rather than
// merely looking slow. So the handle lives behind a private serial queue and
// every entry point is `async`; callers stay on the main actor and `await`.
//
// A serial DispatchQueue rather than an `actor`, deliberately: actors run on the
// cooperative thread pool, which must not be blocked, and every call here blocks
// by nature. The queue also supplies the guarantee vault_ffi.h asks for —
// `vault_ffi_vault_free` never overlaps another call on the same handle.

import Foundation
import LocalAuthentication
import Security
import os

let vaultLog = Logger(subsystem: "no.sybr.vault.autofill", category: "vault")

/// App Group + keychain identifiers, shared with the Tauri Arca app.
enum VaultShared {
    static let appGroup = "group.no.sybr.vault"
    static let vaultFileName = "default.vault"
    static let keychainService = "no.sybr.vault"
    static let keychainAccount = "default-vault"

    /// The account name of the device key THIS process reads.
    ///
    /// On macOS it is deliberately not `keychainAccount`. The Tauri app keeps
    /// its own device key as a plain item in the login keychain under
    /// service+account `no.sybr.vault`/`default-vault`; one build gave the
    /// extension's data-protection copy the same pair, and the app's own
    /// lookup started resolving to an access-controlled item it was never
    /// built to read — Touch ID fired four times over a single unlock and the
    /// unlock still fell back to the master password.
    ///
    /// iOS has only the data-protection keychain and no second writer, so
    /// there is nothing to collide with and the name stays as it was — a
    /// change there would strand every phone's existing enrolment.
    static var deviceKeyAccount: String {
        #if os(macOS)
        "default-vault-autofill"
        #else
        keychainAccount
        #endif
    }

    /// The `ABI_VERSION` in crates/vault-ffi/src/lib.rs that this file was
    /// written against, enforced at open time. A static library from a different
    /// ABI would otherwise be called through the wrong signatures and fail
    /// quietly — and "quietly wrong" in a credential provider means filling the
    /// wrong bytes into someone's login form.
    /// v6 added the write surface (`vault_ffi_upsert_login`,
    /// `vault_ffi_delete_item`); v7 added `vault_ffi_items`,
    /// `vault_ffi_item_detail` and `vault_ffi_totp`, which is what finally lets
    /// a phone see more than logins; v8 added `vault_ffi_generate_password`;
    /// v9 added `vault_ffi_generate_password_for_rules`, which is what lets the
    /// AutoFill extension answer a system generate request without producing
    /// something the site will reject; v10 added the by-handle passkey surface
    /// (`vault_ffi_passkey_identities`, `vault_ffi_passkey_assert_for_id`), so
    /// a phone can sign in with a stored passkey without the private key ever
    /// crossing into Swift; v12 added `vault_ffi_upsert_wifi` and
    /// `vault_ffi_upsert_secure_note`, making every phone-relevant kind
    /// writable; v11 changed upsert's TOTP semantics — null keeps
    /// the existing secret, "" clears it — because the detail surface never
    /// hands the secret out, so a client editing a login could not round-trip
    /// it and every phone edit destroyed the code.
    /// Bump this in the SAME commit that bumps `ABI_VERSION`: nothing compiles
    /// against it, so a stale value is only ever caught at runtime, by this
    /// guard, on a device.
    static let requiredAbiVersion: Int32 = 16

    // MARK: Password generation

    /// What to generate. The defaults are what Arca offers first.
    struct PasswordRecipe: Equatable, Sendable {
        var length: Int = 20
        var lowercase = true
        var uppercase = true
        var digits = true
        var symbols = true

        /// Whether the FFI would accept this. The UI checks it so the control
        /// that would produce a refusal is disabled instead — turning off the
        /// last class should grey out Generate, not fail after you press it.
        var isUsable: Bool { length > 0 && (lowercase || uppercase || digits || symbols) }
    }

    /// Generate a password satisfying a site's Password Rules string.
    ///
    /// Empty or unparseable rules give a strong default. The library never
    /// errors on the rules themselves — they arrive from arbitrary websites,
    /// and a site that writes nonsense should cost the user nothing.
    static func generatePassword(rules: String, defaultLength: Int = 20) throws -> String {
        try requireMatchingAbi()
        var buffer: UnsafeMutablePointer<UInt8>?
        var length = 0
        let code = rules.withCString {
            vault_ffi_generate_password_for_rules($0, defaultLength, &buffer, &length)
        }
        guard code == VaultFFICode.ok, let buffer, length > 0 else {
            throw VaultError.ffi(code: code, operation: "generate_password_for_rules")
        }
        defer { vault_ffi_free(buffer, length) }
        return String(decoding: UnsafeBufferPointer(start: buffer, count: length), as: UTF8.self)
    }

    /// The ABI guard normally runs when a vault is opened. Generation never
    /// opens one, so without this it is the only surface that would call into a
    /// mismatched library unchecked — and a wrong signature here hands back
    /// whatever bytes happen to be at that address.
    private static func requireMatchingAbi() throws {
        let linked = vault_ffi_abi_version()
        guard linked == requiredAbiVersion else {
            throw VaultError.abiMismatch(linked: linked, expected: requiredAbiVersion)
        }
    }

    static func generatePassword(_ recipe: PasswordRecipe) throws -> String {
        try requireMatchingAbi()
        var buffer: UnsafeMutablePointer<UInt8>?
        var length = 0
        let code = vault_ffi_generate_password(
            recipe.length,
            recipe.lowercase ? 1 : 0,
            recipe.uppercase ? 1 : 0,
            recipe.digits ? 1 : 0,
            recipe.symbols ? 1 : 0,
            &buffer,
            &length)
        guard code == VaultFFICode.ok else {
            throw VaultError.ffi(code: code, operation: "generate_password")
        }
        // Unlike a password read from an entry, empty here is never legitimate:
        // a zero-length result means the library returned success and nothing.
        guard let buffer, length > 0 else {
            throw VaultError.ffi(code: VaultFFICode.ok, operation: "generate_password returned nothing")
        }
        defer { vault_ffi_free(buffer, length) }
        return String(decoding: UnsafeBufferPointer(start: buffer, count: length), as: UTF8.self)
    }

    /// Info.plist key carrying the shared keychain access group. Both targets
    /// set it to `$(AppIdentifierPrefix)no.sybr.vault.shared`, which Xcode
    /// expands from the provisioning profile — so the team prefix is not pinned
    /// in source and building under a different team just works.
    private static let accessGroupInfoKey = "ArcaKeychainAccessGroup"

    /// Group name without the team prefix, as written in the entitlements.
    private static let accessGroupSuffix = "no.sybr.vault.shared"

    /// Prefix used only when the build had no profile to expand
    /// `$(AppIdentifierPrefix)` from (e.g. `CODE_SIGNING_ALLOWED=NO` in CI).
    /// Such a build cannot reach the shared keychain at all; this just keeps the
    /// query well-formed instead of silently searching the wrong group.
    private static let fallbackTeamPrefix = "LY6LJ395B8."

    /// Shared keychain access group holding the device (quick-unlock) key.
    /// Matches the `keychain-access-groups` entitlement on both targets.
    static let keychainAccessGroup: String = {
        let declared = Bundle.main
            .object(forInfoDictionaryKey: VaultShared.accessGroupInfoKey) as? String
        // An unexpanded "$(AppIdentifierPrefix)…", an empty string, or a bare
        // prefix-less group all mean the variable never got substituted.
        if let declared,
           !declared.isEmpty,
           !declared.contains("$("),
           declared != VaultShared.accessGroupSuffix {
            return declared
        }
        vaultLog.notice("keychain access group not resolved from Info.plist; using the built-in prefix")
        return VaultShared.fallbackTeamPrefix + VaultShared.accessGroupSuffix
    }()

    /// The encrypted vault file in the shared container, or `nil` if the App
    /// Group entitlement isn't provisioned.
    static var vaultURL: URL? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroup)?
            .appending(path: vaultFileName)
    }

    /// The encrypted vault file's bytes.
    static func loadVault() throws -> Data {
        guard let url = vaultURL else { throw VaultError.noContainer }
        let bytes: Data
        do {
            // Read and handle the failure, rather than `fileExists` then read:
            // the app rewrites this file atomically, so a stat-then-read races it.
            bytes = try Data(contentsOf: url)
        } catch let error as NSError {
            switch error.code {
            case NSFileReadNoSuchFileError, NSFileNoSuchFileError:
                throw VaultError.noVaultFile
            case NSFileReadNoPermissionError:
                throw VaultError.containerNotPermitted
            default:
                throw VaultError.unreadableVaultFile(code: error.code)
            }
        }
        // An empty `Data` has no base address, so this would reach the FFI as a
        // null pointer and come back as "null argument" — which reads like a
        // programming error rather than the broken vault file it actually is.
        guard !bytes.isEmpty else { throw VaultError.emptyVaultFile }
        return bytes
    }

    /// The advisory lock guarding read-modify-write of the vault file.
    ///
    /// A sibling of the vault, so it lives in the same App Group container both
    /// processes already share. It is never read or written — only `flock`ed.
    static var vaultLockURL: URL? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroup)?
            .appending(path: vaultFileName + ".lock")
    }

    /// An exclusive cross-process lock on the vault, held until `release()`.
    ///
    /// The app and the AutoFill extension are separate processes writing one
    /// file. Each write was atomic on its own, which is not the same as safe:
    /// every writer does read-disk → merge → write, and nothing stopped the
    /// extension from committing a passkey in the gap between the app's read
    /// and its write. The app's next write had then never seen that passkey and
    /// erased it — permanently, since the extension process was already gone.
    /// `flock` is what makes the whole read-modify-write one step. The desktop
    /// side takes the same kind of lock on its own vault.
    ///
    /// Advisory, so it binds only code that asks for it — which is every writer
    /// here, because they all go through it. NOT reentrant: `flock` on a second
    /// descriptor blocks even within one process, so never nest these.
    struct VaultLock {
        fileprivate let fd: Int32
        func release() {
            flock(fd, LOCK_UN)
            close(fd)
        }
    }

    /// Take the vault lock, blocking until it is ours. Pair with `release()`,
    /// normally via `defer`.
    static func acquireVaultLock() throws -> VaultLock {
        guard let url = vaultLockURL else { throw VaultError.noContainer }
        // O_CREAT: the lock file may not exist yet, and creating it is not a
        // write to the vault.
        let fd = open(url.path, O_RDONLY | O_CREAT, 0o600)
        guard fd >= 0 else { throw VaultError.vaultLockUnavailable(code: errno) }
        // Retry across signal interruptions; anything else is a real failure,
        // and proceeding unlocked is the thing this exists to prevent.
        while flock(fd, LOCK_EX) != 0 {
            if errno == EINTR { continue }
            let failure = errno
            close(fd)
            throw VaultError.vaultLockUnavailable(code: failure)
        }
        return VaultLock(fd: fd)
    }

    /// Run `body` holding the vault lock.
    static func withVaultLock<T>(_ body: () throws -> T) throws -> T {
        let lock = try acquireVaultLock()
        defer { lock.release() }
        return try body()
    }

    #if os(macOS)
    /// Immutable ciphertext commits: desktop mirror refreshes cannot erase a
    /// registration before the desktop has durably imported it.
    static var passkeyInboxURL: URL? {
        vaultURL?.deletingLastPathComponent().appendingPathComponent("passkey-inbox", isDirectory: true)
    }

    static func pendingPasskeySnapshots(in directory: URL? = nil) throws -> [Data] {
        guard let inbox = directory ?? passkeyInboxURL else { throw VaultError.noContainer }
        guard FileManager.default.fileExists(atPath: inbox.path) else { return [] }
        return try FileManager.default.contentsOfDirectory(at: inbox, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "vault" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
            .map { try Data(contentsOf: $0) }
    }

    static func commitPasskeyRegistration(_ bytes: Data, in directory: URL? = nil) throws {
        guard let inbox = directory ?? passkeyInboxURL else { throw VaultError.noContainer }
        try FileManager.default.createDirectory(at: inbox, withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
        let destination = inbox.appendingPathComponent(UUID().uuidString + ".vault")
        try bytes.write(to: destination, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
        // Flush the commit before handing a credential to the relying party.
        let file = try FileHandle(forWritingTo: destination)
        defer { try? file.close() }
        try file.synchronize()
        let descriptor = open(inbox.path, O_RDONLY)
        guard descriptor >= 0 else { throw VaultError.vaultWriteFailed(code: Int(errno)) }
        defer { close(descriptor) }
        guard fsync(descriptor) == 0 else { throw VaultError.vaultWriteFailed(code: Int(errno)) }
    }
    #endif

    /// Replace the vault file.
    ///
    /// The one place that knows how this file gets written, because this is the
    /// user's only copy: atomically, so a failure mid-write leaves the previous
    /// vault intact rather than a truncated one, and — on iOS — unreadable while
    /// the device is locked. Everything that writes the container goes through
    /// here, so the options cannot drift between callers.
    ///
    /// Callers must hold `withVaultLock`; writing is only half of the operation
    /// that needs to be atomic.
    static func writeVault(_ bytes: Data) throws {
        guard let url = vaultURL else { throw VaultError.noContainer }
        #if os(iOS)
        let options: Data.WritingOptions = [.atomic, .completeFileProtection]
        #else
        // completeFileProtection is iOS-only; macOS has no equivalent flag here.
        let options: Data.WritingOptions = [.atomic]
        #endif
        do {
            try bytes.write(to: url, options: options)
        } catch let error as NSError {
            throw error.code == NSFileWriteNoPermissionError
                ? VaultError.containerNotPermitted
                : VaultError.vaultWriteFailed(code: error.code)
        }
    }
}

/// Return codes from vault_ffi.h, named so nothing here carries a bare -7.
/// Mirrors the table at the top of that header; keep the two in step.
enum VaultFFICode {
    static let ok: Int32 = 0
    static let nullArgument: Int32 = -1
    static let invalidUTF8: Int32 = -2
    static let operationFailed: Int32 = -3
    static let locked: Int32 = -4
    static let notFound: Int32 = -5
    static let panicked: Int32 = -6
    static let decryptionFailed: Int32 = -7
    static let badKeyLength: Int32 = -8
}

/// Everything that can go wrong reaching or opening the shared vault.
///
/// Every case carries nothing but codes and OS status values — never key
/// material, the master password, or any decrypted item — so the whole type is
/// safe to log at `.public` privacy.
enum VaultError: Error, Equatable {
    /// A `vault-ffi` call returned a non-zero code; see the table in vault_ffi.h.
    case ffi(code: Int32, operation: String)
    /// The linked static library speaks a different ABI than this source.
    case abiMismatch(linked: Int32, expected: Int32)
    /// The App Group container could not be resolved (entitlement missing or
    /// not provisioned).
    case noContainer
    /// The container is there but the OS refused the read — the classic sign of
    /// an App Group entitlement that was never actually granted.
    case containerNotPermitted
    case noVaultFile
    /// A zero-byte vault file: present, but nothing to open.
    case emptyVaultFile
    case unreadableVaultFile(code: Int)
    /// The re-sealed vault could not be written back to the container.
    case vaultWriteFailed(code: Int)
    /// The cross-process vault lock could not be taken (`errno`). Writing
    /// without it risks erasing what the other process just committed, so the
    /// operation is refused instead.
    case vaultLockUnavailable(code: Int32)
    case noDeviceKey(status: OSStatus)
    /// The minted device key could not be put in the keychain. The vault file
    /// is already re-sealed by then, which is harmless — the master password
    /// still opens it and retrying replaces the wrapping.
    case deviceKeyNotStored(status: OSStatus)
    /// `vault_ffi_identities` returned something that wasn't the documented JSON.
    case malformedIdentities
}

extension VaultError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .ffi(let code, _) where code == VaultFFICode.decryptionFailed:
            return "That key doesn't open this vault. If you changed your master password, unlock Arca once on this device."
        case .ffi(let code, _) where code == VaultFFICode.notFound:
            return "That login is no longer in your vault."
        case .ffi, .malformedIdentities:
            return "Couldn't read your vault."
        case .abiMismatch:
            return "This build of Arca is mismatched with its vault library. Reinstall Arca."
        case .noContainer, .containerNotPermitted:
            return "Arca can't reach its shared container. Check that the App Group entitlement is provisioned."
        case .noVaultFile, .emptyVaultFile:
            return "No vault found. Set one up in Arca first."
        case .unreadableVaultFile:
            return "Couldn't read the vault file."
        case .vaultWriteFailed:
            return "Couldn't save the vault. Check available storage and try again."
        case .vaultLockUnavailable:
            return "Another part of Arca is saving right now. Try again in a moment."
        case .deviceKeyNotStored(let status) where status == errSecUserCanceled:
            return "Quick unlock was cancelled."
        case .deviceKeyNotStored:
            return "Couldn't store the quick-unlock key. Is Face ID or a passcode set up?"
        case .noDeviceKey(let status) where status == errSecUserCanceled:
            return "Unlock was cancelled."
        case .noDeviceKey(let status) where status == errSecItemNotFound:
            return "No quick-unlock key yet. Unlock Arca once on this device to create one."
        case .noDeviceKey:
            return "Couldn't unlock with device authentication. Try your master password."
        }
    }

    /// Short, stable, guaranteed secret-free — for `Logger`, not for people.
    var logMessage: String {
        switch self {
        case .ffi(let code, let operation): return "ffi(\(operation)=\(code))"
        case .abiMismatch(let linked, let expected): return "abiMismatch(\(linked)!=\(expected))"
        case .noContainer: return "noContainer"
        case .containerNotPermitted: return "containerNotPermitted"
        case .noVaultFile: return "noVaultFile"
        case .emptyVaultFile: return "emptyVaultFile"
        case .unreadableVaultFile(let code): return "unreadableVaultFile(\(code))"
        case .vaultWriteFailed(let code): return "vaultWriteFailed(\(code))"
        case .vaultLockUnavailable(let code): return "vaultLockUnavailable(\(code))"
        case .deviceKeyNotStored(let status): return "deviceKeyNotStored(\(status))"
        case .noDeviceKey(let status): return "noDeviceKey(\(status))"
        case .malformedIdentities: return "malformedIdentities"
        }
    }
}

/// Secret-free log text for any error crossing this bridge.
///
/// Deliberately not `String(describing:)`: an arbitrary error's description is
/// not something we control, and these lines are logged at `.public` privacy so
/// they survive into sysdiagnose.
func vaultLogMessage(for error: Error) -> String {
    if let error = error as? VaultError { return error.logMessage }
    let ns = error as NSError
    return "unexpected(\(ns.domain):\(ns.code))"
}

/// One item of any kind, as produced by `vault_ffi_items`. Metadata only.
struct VaultItemMeta: Decodable, Identifiable, Hashable {
    enum Kind: String, Decodable {
        case login, passkey, wifi, bookmark
        case sshKey = "ssh_key"
        case secureNote = "secure_note"

        /// A kind this build has never heard of.
        ///
        /// `items()` decodes the WHOLE list in one go, so without this a single
        /// entry of a kind added after this app shipped would fail the decode
        /// and the phone would show an EMPTY VAULT. The desktop and the phone
        /// ship on completely different cadences — one is a script away, the
        /// other waits on review — so that is not a hypothetical.
        ///
        /// Degrading to "an entry this version cannot render" is the only
        /// honest outcome: the user still sees that something is there.
        case unknown

        init(from decoder: Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = Kind(rawValue: raw) ?? .unknown
        }

        /// The SF Symbol for this kind. Here rather than in a view because two
        /// screens draw the same list and must not disagree about what a Wi-Fi
        /// entry looks like.
        var symbol: String {
            switch self {
            case .login: return "key.fill"
            case .passkey: return "person.badge.key.fill"
            case .sshKey: return "terminal.fill"
            case .wifi: return "wifi"
            case .secureNote: return "note.text"
            case .bookmark: return "bookmark.fill"
            case .unknown: return "questionmark.square.dashed"
            }
        }

        var label: String {
            switch self {
            case .login: return "Login"
            case .passkey: return "Passkey"
            case .sshKey: return "SSH key"
            case .wifi: return "Wi-Fi"
            case .secureNote: return "Note"
            case .bookmark: return "Bookmark"
            case .unknown: return "Unsupported"
            }
        }
    }

    let id: String
    let kind: Kind
    let title: String
    let subtitle: String
    let url: String
    let hasTotp: Bool

    enum CodingKeys: String, CodingKey {
        case id, kind, title, subtitle, url
        case hasTotp = "has_totp"
    }
}

/// The full payload of one item. SECRET.
enum VaultItemDetail: Decodable {
    case login(title: String, username: String, password: String, url: String, hasTotp: Bool, notes: String)
    case passkey(title: String, rpID: String, userName: String)
    case sshKey(title: String, comment: String, keyType: String, publicKey: String, fingerprint: String)
    case wifi(title: String, ssid: String, password: String, security: String, hidden: Bool, notes: String)
    case secureNote(title: String, body: String)

    private enum CodingKeys: String, CodingKey {
        case kind, title, username, password, url, notes, body
        case ssid, security, hidden, comment, fingerprint
        case hasTotp = "has_totp"
        case rpID = "rp_id"
        case userName = "user_name"
        case keyType = "key_type"
        case publicKey = "public_key"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try c.decode(String.self, forKey: .kind)
        let title = try c.decode(String.self, forKey: .title)
        switch kind {
        case "login":
            self = .login(
                title: title,
                username: try c.decode(String.self, forKey: .username),
                password: try c.decode(String.self, forKey: .password),
                url: try c.decode(String.self, forKey: .url),
                hasTotp: try c.decode(Bool.self, forKey: .hasTotp),
                notes: try c.decode(String.self, forKey: .notes))
        case "passkey":
            self = .passkey(
                title: title,
                rpID: try c.decode(String.self, forKey: .rpID),
                userName: try c.decode(String.self, forKey: .userName))
        case "ssh_key":
            self = .sshKey(
                title: title,
                comment: try c.decode(String.self, forKey: .comment),
                keyType: try c.decode(String.self, forKey: .keyType),
                publicKey: try c.decode(String.self, forKey: .publicKey),
                fingerprint: try c.decode(String.self, forKey: .fingerprint))
        case "wifi":
            self = .wifi(
                title: title,
                ssid: try c.decode(String.self, forKey: .ssid),
                password: try c.decode(String.self, forKey: .password),
                security: try c.decode(String.self, forKey: .security),
                hidden: try c.decode(Bool.self, forKey: .hidden),
                notes: try c.decode(String.self, forKey: .notes))
        case "secure_note":
            self = .secureNote(title: title, body: try c.decode(String.self, forKey: .body))
        default:
            // A kind this build has not learned. Refusing beats rendering a
            // blank card that looks like an empty item.
            throw DecodingError.dataCorruptedError(
                forKey: .kind, in: c, debugDescription: "unknown item kind \(kind)")
        }
    }
}

/// A live TOTP code and the seconds it has left.
struct VaultTotp: Decodable {
    let code: String
    let period: UInt64
    let remaining: UInt64
}

/// One login identity (metadata only) as produced by `vault_ffi_identities`.
struct VaultIdentity: Decodable, Sendable, Identifiable {
    let id: String
    let user: String
    let domain: String
    let label: String
}

/// An unlocked vault.
///
/// `@unchecked Sendable` because `OpaquePointer` isn't: the invariant that makes
/// it safe is that the handle is only ever touched inside `run`, which executes
/// on one shared serial queue — so no two FFI calls on a handle overlap, and the
/// free is ordered behind everything already queued for it.
final class VaultSession: @unchecked Sendable {

    /// Shared and serial. Shared so two simultaneous opens can't put two
    /// biometric prompts on screen; serial so the C ABI's non-overlap rule holds.
    private static let queue = DispatchQueue(label: "no.sybr.vault.session", qos: .userInitiated)

    private let handle: OpaquePointer

    private init(handle: OpaquePointer) { self.handle = handle }

    deinit {
        // Hand the raw pointer to the queue rather than `self`: `deinit` runs on
        // whichever thread dropped the last reference, and the free has to be
        // ordered behind any work already queued for this handle. Enqueuing it
        // does both, and lets `self` finish dying immediately.
        let box = HandleBox(handle: handle)
        Self.queue.async { vault_ffi_vault_free(box.handle) }
    }

    /// Carries a handle across to the queue. `@unchecked` because
    /// `OpaquePointer` isn't `Sendable`; sound here because exactly one enqueued
    /// block ever receives a given box, and it frees the handle and drops it.
    private struct HandleBox: @unchecked Sendable {
        let handle: OpaquePointer
    }

    // MARK: Opening

    /// Open the shared vault with the device (quick-unlock) key.
    ///
    /// Puts a Touch ID / Face ID prompt on screen and waits for the user, so it
    /// must not be called from a context that also has to draw.
    static func openWithDeviceKey(reason: String) async throws -> VaultSession {
        try await Self.run {
            try Self.checkAbi()
            let vaultBytes = try VaultShared.loadVault()
            return try Self.withDeviceKey(reason: reason) { key in
                var handle: OpaquePointer?
                let code = vaultBytes.withUnsafeBytes { vault in
                    key.withUnsafeBytes { deviceKey in
                        vault_ffi_vault_open(
                            vault.bindMemory(to: UInt8.self).baseAddress, vault.count,
                            deviceKey.bindMemory(to: UInt8.self).baseAddress, deviceKey.count,
                            &handle)
                    }
                }
                guard code == VaultFFICode.ok, let handle else {
                    throw VaultError.ffi(code: code, operation: "vault_open")
                }
                #if os(macOS)
                do {
                    try VaultShared.withVaultLock { try Self.foldInDiskState(handle) }
                } catch {
                    vault_ffi_vault_free(handle)
                    throw error
                }
                #endif
                return VaultSession(handle: handle)
            }
        }
    }

    /// Open the shared vault with the **master password**.
    ///
    /// The path a client with no device key has to take — a phone on first
    /// launch, a recovery tool. Derives the key with Argon2id using the
    /// parameters in the vault's own header, so it is expensive by design; that
    /// cost is the reason this whole type is `async` rather than a convenience.
    static func openWithMasterPassword(_ password: String) async throws -> VaultSession {
        try await Self.run {
            try Self.checkAbi()
            let vaultBytes = try VaultShared.loadVault()
            var handle: OpaquePointer?
            let code = vaultBytes.withUnsafeBytes { vault in
                password.withCString { password in
                    vault_ffi_vault_open_password(
                        vault.bindMemory(to: UInt8.self).baseAddress, vault.count,
                        password, &handle)
                }
            }
            guard code == VaultFFICode.ok, let handle else {
                throw VaultError.ffi(code: code, operation: "vault_open_password")
            }
            return VaultSession(handle: handle)
        }
    }

    // MARK: Reading

    /// Login identities — metadata only, never a secret.
    /// Every item, of every kind. Metadata only.
    ///
    /// `identities()` stays logins-only because it feeds the platform
    /// credential store. This is what a LIST should call: until ABI v7 four of
    /// the five kinds simply had no way to be asked for, so a phone showed a
    /// fifth of the vault and gave no sign the rest existed.
    func items() async throws -> [VaultItemMeta] {
        try await Self.run {
            var json: UnsafeMutablePointer<UInt8>?
            var length = 0
            let code = vault_ffi_items(self.handle, &json, &length)
            guard code == VaultFFICode.ok else {
                throw VaultError.ffi(code: code, operation: "items")
            }
            guard let json else { return [] }
            defer { vault_ffi_free(json, length) }
            do {
                return try JSONDecoder()
                    .decode([VaultItemMeta].self, from: Data(bytes: json, count: length))
            } catch {
                throw VaultError.malformedIdentities
            }
        }
    }

    /// The full payload of one item, tagged by kind.
    ///
    /// SECRET: carries the Wi-Fi password and note body. Hold it no longer than
    /// the screen that shows it.
    func detail(forID id: String) async throws -> VaultItemDetail {
        try await Self.run {
            var json: UnsafeMutablePointer<UInt8>?
            var length = 0
            let code = id.withCString { vault_ffi_item_detail(self.handle, $0, &json, &length) }
            guard code == VaultFFICode.ok else {
                throw VaultError.ffi(code: code, operation: "item detail")
            }
            guard let json else { throw VaultError.malformedIdentities }
            defer { vault_ffi_free(json, length) }
            do {
                return try JSONDecoder()
                    .decode(VaultItemDetail.self, from: Data(bytes: json, count: length))
            } catch {
                throw VaultError.malformedIdentities
            }
        }
    }

    func passwordHistory(forID id: String) async throws -> [VaultPasswordHistory] {
        try await Self.run {
            var buffer: UnsafeMutablePointer<UInt8>?
            var length = 0
            let code = id.withCString { vault_ffi_password_history(self.handle, $0, &buffer, &length) }
            guard code == VaultFFICode.ok, let buffer else {
                throw VaultError.ffi(code: code, operation: "password history")
            }
            defer { vault_ffi_free(buffer, length) }
            return try JSONDecoder().decode([VaultPasswordHistory].self, from: Data(bytes: buffer, count: length))
        }
    }

    func historyPassword(forID id: String, revision: String) async throws -> String {
        try await Self.run {
            var buffer: UnsafeMutablePointer<UInt8>?
            var length = 0
            let code = id.withCString { idPtr in revision.withCString {
                vault_ffi_history_password(self.handle, idPtr, $0, &buffer, &length)
            } }
            guard code == VaultFFICode.ok else {
                throw VaultError.ffi(code: code, operation: "previous password")
            }
            guard let buffer else { return "" }
            defer { vault_ffi_free(buffer, length) }
            return String(decoding: UnsafeBufferPointer(start: buffer, count: length), as: UTF8.self)
        }
    }

    func restorePasswordHistory(forID id: String, revision: String) async throws {
        try await Self.run {
            let lock = try VaultShared.acquireVaultLock()
            defer { lock.release() }
            try Self.foldInDiskState(self.handle)
            var buffer: UnsafeMutablePointer<UInt8>?
            var length = 0
            let now = Int64(Date().timeIntervalSince1970 * 1000)
            let code = id.withCString { idPtr in revision.withCString {
                vault_ffi_restore_password_history(self.handle, idPtr, $0, now, &buffer, &length)
            } }
            guard code == VaultFFICode.ok, let buffer else {
                throw VaultError.ffi(code: code, operation: "restore previous password")
            }
            defer { vault_ffi_free(buffer, length) }
            try VaultShared.writeVault(Data(bytes: buffer, count: length))
            try Self.foldInDiskState(self.handle)
        }
    }

    /// The live TOTP code for a login, and how long it has left.
    ///
    /// Returns nil when the item has no TOTP — which the ABI reports as
    /// `notFound` rather than an empty code, so the UI can hide the row instead
    /// of showing six blanks.
    func totp(forID id: String) async throws -> VaultTotp? {
        try await Self.run {
            var json: UnsafeMutablePointer<UInt8>?
            var length = 0
            let code = id.withCString { vault_ffi_totp(self.handle, $0, &json, &length) }
            if code == VaultFFICode.notFound { return nil }
            guard code == VaultFFICode.ok, let json else {
                throw VaultError.ffi(code: code, operation: "totp")
            }
            defer { vault_ffi_free(json, length) }
            return try? JSONDecoder()
                .decode(VaultTotp.self, from: Data(bytes: json, count: length))
        }
    }

    func identities() async throws -> [VaultIdentity] {
        try await Self.run {
            var json: UnsafeMutablePointer<UInt8>?
            var length = 0
            let code = vault_ffi_identities(self.handle, &json, &length)
            guard code == VaultFFICode.ok else {
                throw VaultError.ffi(code: code, operation: "identities")
            }
            // (null, 0) is how the ABI represents an empty result.
            guard let json else { return [] }
            defer { vault_ffi_free(json, length) }
            do {
                return try JSONDecoder()
                    .decode([VaultIdentity].self, from: Data(bytes: json, count: length))
            } catch {
                // The decode error itself could quote the payload, so it is
                // swallowed rather than logged or wrapped.
                throw VaultError.malformedIdentities
            }
        }
    }

    /// One stored passkey's metadata — what the credential store and the
    /// assertion response need, and nothing secret.
    struct VaultPasskeyIdentity: Decodable, Identifiable, Sendable {
        let id: String
        let rpID: String
        let userName: String
        let userHandle: Data
        let credentialID: Data

        enum CodingKeys: String, CodingKey {
            case id, rpID = "rp_id", userName = "user_name"
            case userHandle = "user_handle", credentialID = "credential_id"
        }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            id = try c.decode(String.self, forKey: .id)
            rpID = try c.decode(String.self, forKey: .rpID)
            userName = try c.decode(String.self, forKey: .userName)
            userHandle = try Self.base64(c, .userHandle)
            credentialID = try Self.base64(c, .credentialID)
        }

        private static func base64(
            _ c: KeyedDecodingContainer<CodingKeys>, _ key: CodingKeys
        ) throws -> Data {
            let raw = try c.decode(String.self, forKey: key)
            guard let data = Data(base64Encoded: raw) else {
                throw DecodingError.dataCorruptedError(
                    forKey: key, in: c, debugDescription: "not base64")
            }
            return data
        }
    }

    /// A WebAuthn assertion, ready for `ASPasskeyAssertionCredential`.
    /// What a registration hands back to the relying party.
    struct VaultPasskeyRegistration: Sendable {
        let credentialID: Data
        let attestationObject: Data
    }

    struct VaultPasskeyAssertion: Decodable, Sendable {
        let credentialID: Data
        let userHandle: Data
        let authenticatorData: Data
        let signature: Data

        enum CodingKeys: String, CodingKey {
            case credentialID = "credential_id", userHandle = "user_handle"
            case authenticatorData = "authenticator_data", signature
        }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            func field(_ key: CodingKeys) throws -> Data {
                let raw = try c.decode(String.self, forKey: key)
                guard let data = Data(base64Encoded: raw) else {
                    throw DecodingError.dataCorruptedError(
                        forKey: key, in: c, debugDescription: "not base64")
                }
                return data
            }
            credentialID = try field(.credentialID)
            userHandle = try field(.userHandle)
            authenticatorData = try field(.authenticatorData)
            signature = try field(.signature)
        }
    }

    /// Every stored passkey's metadata, for the credential store.
    private static func readPasskeyIdentities(_ handle: OpaquePointer) throws -> [VaultPasskeyIdentity] {
        var buffer: UnsafeMutablePointer<UInt8>?
        var length = 0
        let code = vault_ffi_passkey_identities(handle, &buffer, &length)
        guard code == VaultFFICode.ok, let buffer else {
            throw VaultError.ffi(code: code, operation: "passkey_identities")
        }
        defer { vault_ffi_free(buffer, length) }
        return try JSONDecoder().decode([VaultPasskeyIdentity].self,
                                        from: Data(bytes: buffer, count: length))
    }

    func passkeyIdentities() async throws -> [VaultPasskeyIdentity] {
        try await Self.run { try Self.readPasskeyIdentities(self.handle) }
    }

    /// Sign a relying party's challenge with a stored passkey.
    ///
    /// `userVerified` must reflect what ACTUALLY gated this call — Face ID or
    /// the master password — because it is written into the authenticator
    /// data's flags, and the relying party trusts it. Claiming verification
    /// that did not happen is lying to the site about its own security.
    func assertPasskey(
        forID id: String, clientDataHash: Data, userVerified: Bool
    ) async throws -> VaultPasskeyAssertion {
        try await Self.run {
            var buffer: UnsafeMutablePointer<UInt8>?
            var length = 0
            let code = id.withCString { idPtr in
                clientDataHash.withUnsafeBytes { hash in
                    vault_ffi_passkey_assert_for_id(
                        self.handle, idPtr,
                        hash.bindMemory(to: UInt8.self).baseAddress, hash.count,
                        userVerified ? 1 : 0,
                        &buffer, &length)
                }
            }
            guard code == VaultFFICode.ok, let buffer else {
                throw VaultError.ffi(code: code, operation: "passkey_assert_for_id")
            }
            defer { vault_ffi_free(buffer, length) }
            return try JSONDecoder().decode(
                VaultPasskeyAssertion.self,
                from: Data(bytes: buffer, count: length))
        }
    }

    /// The password for one identity, as the `String` the platform credential
    /// APIs require.
    ///
    /// The Rust buffer is zeroed by `vault_ffi_free` as soon as it is copied.
    /// The `String` cannot be wiped — Swift strings are immutable and the runtime
    /// may copy them — so hand it straight to `ASPasswordCredential` and keep no
    /// other reference to it.
    func password(forID id: String) async throws -> String {
        try await Self.run {
            var buffer: UnsafeMutablePointer<UInt8>?
            var length = 0
            let code = id.withCString {
                vault_ffi_password_for_id(self.handle, $0, &buffer, &length)
            }
            guard code == VaultFFICode.ok else {
                throw VaultError.ffi(code: code, operation: "password_for_id")
            }
            // (null, 0) is an empty password, not a failure.
            guard let buffer else { return "" }
            defer { vault_ffi_free(buffer, length) }
            // Decoded straight from the Rust buffer: going via `Data` first would
            // leave a second heap copy of the password behind that nothing zeroes.
            return String(decoding: UnsafeBufferPointer(start: buffer, count: length),
                          as: UTF8.self)
        }
    }

    // MARK: Quick unlock
    /// Fold the current on-disk vault into this handle before a write.
    ///
    /// The Swift half of the cross-process lost-update guard (see
    /// vault_ffi_merge_remote). The app and the AutoFill extension each hold
    /// their own decrypted copy of the one shared file; without this, whichever
    /// writes second serializes its stale copy over the first's committed
    /// change and silently loses it — a login the app just saved, or a passkey
    /// the extension just registered. Reads the file and merges it in (union,
    /// newest-wins) so a write ADDS to the other side's work instead of erasing
    /// it. Called inside `run`, so it is already on the vault queue.
    ///
    /// A missing or empty file is the first write ever — nothing to fold.
    private static func foldInDiskState(_ handle: OpaquePointer) throws {
        let disk: Data
        do {
            disk = try VaultShared.loadVault()
        } catch VaultError.noVaultFile, VaultError.emptyVaultFile {
            return
        }
        let code = disk.withUnsafeBytes { buf in
            vault_ffi_merge_remote(
                handle, buf.bindMemory(to: UInt8.self).baseAddress, buf.count)
        }
        // A different vault on disk (ERR_DECRYPT) must ABORT the write, not be
        // written over: throwing here leaves the file exactly as the other
        // process wrote it.
        guard code == VaultFFICode.ok else {
            throw VaultError.ffi(code: code, operation: "merge_remote")
        }
        #if os(macOS)
        for snapshot in try VaultShared.pendingPasskeySnapshots() {
            let result = snapshot.withUnsafeBytes { bytes in
                vault_ffi_merge_remote(handle, bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count)
            }
            guard result == VaultFFICode.ok else {
                throw VaultError.ffi(code: result, operation: "merge_pending_registration")
            }
        }
        #endif
    }

    /// Public entry to the pre-write disk merge, for the ONE writer that does
    /// not go through the methods above: the sync engine. `syncNow` serializes
    /// and writes the vault, and its handle shares this session's vault, so
    /// folding disk in here — before a sync cycle — is what stops a sync
    /// write-back from clobbering a passkey the AutoFill extension just wrote.
    func foldDiskState() async throws {
        try await Self.run { try Self.foldInDiskState(self.handle) }
    }


    /// Turn on quick unlock: mint a device key, re-seal the vault with it, and
    /// put the key in the shared keychain behind Face ID / Touch ID.
    ///
    /// The order is not arbitrary. The vault file is written BEFORE the key is
    /// stored, because the two failure modes are not symmetric: a vault carrying
    /// a wrapping whose key was never saved is inert — the master password still
    /// opens it and running this again replaces the wrapping — whereas a stored
    /// key for a vault that was never written opens nothing, and every launch
    /// after it would prompt for a biometric and then fail.
    func enableDeviceUnlock() async throws {
        try await Self.run {
            let lock = try VaultShared.acquireVaultLock()
            defer { lock.release() }
            try Self.foldInDiskState(self.handle)
            var key: UnsafeMutablePointer<UInt8>?
            var keyLength = 0
            var vault: UnsafeMutablePointer<UInt8>?
            var vaultLength = 0
            let code = vault_ffi_enable_device_unlock(
                self.handle, &key, &keyLength, &vault, &vaultLength)
            guard code == VaultFFICode.ok, let key, let vault else {
                throw VaultError.ffi(code: code, operation: "enable_device_unlock")
            }
            // Rust zeroes both buffers; the device key half is a secret.
            defer {
                vault_ffi_free(key, keyLength)
                vault_ffi_free(vault, vaultLength)
            }

            try VaultShared.writeVault(Data(bytes: vault, count: vaultLength))

            var keyData = Data(bytes: key, count: keyLength)
            // Same best-effort wipe as the read path, and the same reason it is
            // only best-effort: `Data` is copy-on-write, so this clears the
            // buffer while nothing else holds it.
            defer { keyData.resetBytes(in: 0..<keyData.count) }
            try Self.storeDeviceKey(keyData)
        }
    }

    /// Insert or update a login, persisting the vault file.
    ///
    /// Pass `id` to edit an existing login, or nil to create one. The Rust side
    /// returns the whole new vault file; writing it is ours to do, and it lands
    /// atomically with file protection like every other write here.
    ///
    /// Returns the item's id, which is the caller's handle to it afterwards
    /// (the same id on an edit, a fresh one on a create).
    @discardableResult
    /// `withCString` for an optional: nil crosses as a NULL pointer.
    ///
    /// This distinction is load-bearing since ABI v11 — for the TOTP field,
    /// NULL means "keep the existing secret" and "" means "clear it". Folding
    /// nil to "" here is how the keep-on-null fix shipped in Rust while every
    /// phone edit went on clearing codes through this very file.
    private static func withOptionalCString<R>(
        _ string: String?, _ body: (UnsafePointer<CChar>?) throws -> R
    ) rethrows -> R {
        if let string {
            return try string.withCString { try body($0) }
        }
        return try body(nil)
    }

    func upsertLogin(
        id: String? = nil,
        title: String,
        username: String,
        password: String,
        url: String,
        totpSecret: String? = nil,
        notes: String = ""
    ) async throws -> String {
        try await Self.run {
            let lock = try VaultShared.acquireVaultLock()
            defer { lock.release() }
            try Self.foldInDiskState(self.handle)
            var vault: UnsafeMutablePointer<UInt8>?
            var vaultLength = 0
            var idOut: UnsafeMutablePointer<UInt8>?
            var idLength = 0
            // Milliseconds since the epoch: vault-core has no clock, so the
            // timestamp is ours to supply.
            let now = Int64(Date().timeIntervalSince1970 * 1000)

            // withCString nests rather than composes; the pointers are only
            // valid inside their closures, so the call happens innermost.
            // nil id -> NULL (create); nil totp -> NULL (KEEP the existing
            // secret, per v11). `?? ""` here would turn every phone edit into
            // an explicit clear — which is exactly what it used to do.
            let code: Int32 = Self.withOptionalCString(id) { idPtr in
                title.withCString { titlePtr in
                    username.withCString { userPtr in
                        password.withCString { passPtr in
                            url.withCString { urlPtr in
                                Self.withOptionalCString(totpSecret) { totpPtr in
                                    notes.withCString { notesPtr in
                                        vault_ffi_upsert_login(
                                            self.handle, idPtr, titlePtr, userPtr,
                                            passPtr, urlPtr, totpPtr, notesPtr, now,
                                            &vault, &vaultLength, &idOut, &idLength)
                                    }
                                }
                            }
                        }
                    }
                }
            }
            guard code == VaultFFICode.ok, let vault, let idOut else {
                throw VaultError.ffi(code: code, operation: "upsert_login")
            }
            defer {
                vault_ffi_free(vault, vaultLength)
                vault_ffi_free(idOut, idLength)
            }
            // Persist BEFORE reporting success: an id for an item that never
            // reached disk would be a lie the UI acts on.
            try VaultShared.writeVault(Data(bytes: vault, count: vaultLength))
            return String(decoding: Data(bytes: idOut, count: idLength), as: UTF8.self)
        }
    }

    /// Create or edit a Wi-Fi entry. Same persistence contract as
    /// `upsertLogin`: the file is written before the id is reported.
    func upsertWifi(
        id: String? = nil,
        title: String,
        ssid: String,
        password: String,
        security: String,
        hidden: Bool,
        notes: String = ""
    ) async throws -> String {
        try await Self.run {
            let lock = try VaultShared.acquireVaultLock()
            defer { lock.release() }
            try Self.foldInDiskState(self.handle)
            var vault: UnsafeMutablePointer<UInt8>?
            var vaultLength = 0
            var idOut: UnsafeMutablePointer<UInt8>?
            var idLength = 0
            let now = Int64(Date().timeIntervalSince1970 * 1000)
            let code: Int32 = Self.withOptionalCString(id) { idPtr in
                title.withCString { titlePtr in
                    ssid.withCString { ssidPtr in
                        password.withCString { passPtr in
                            security.withCString { secPtr in
                                notes.withCString { notesPtr in
                                    vault_ffi_upsert_wifi(
                                        self.handle, idPtr, titlePtr, ssidPtr,
                                        passPtr, secPtr, hidden ? 1 : 0, notesPtr,
                                        now, &vault, &vaultLength, &idOut, &idLength)
                                }
                            }
                        }
                    }
                }
            }
            guard code == VaultFFICode.ok, let vault, let idOut else {
                throw VaultError.ffi(code: code, operation: "upsert_wifi")
            }
            defer {
                vault_ffi_free(vault, vaultLength)
                vault_ffi_free(idOut, idLength)
            }
            try VaultShared.writeVault(Data(bytes: vault, count: vaultLength))
            return String(decoding: Data(bytes: idOut, count: idLength), as: UTF8.self)
        }
    }

    /// Create or edit a secure note. Same persistence contract as `upsertLogin`.
    func upsertNote(
        id: String? = nil,
        title: String,
        body: String
    ) async throws -> String {
        try await Self.run {
            let lock = try VaultShared.acquireVaultLock()
            defer { lock.release() }
            try Self.foldInDiskState(self.handle)
            var vault: UnsafeMutablePointer<UInt8>?
            var vaultLength = 0
            var idOut: UnsafeMutablePointer<UInt8>?
            var idLength = 0
            let now = Int64(Date().timeIntervalSince1970 * 1000)
            let code: Int32 = Self.withOptionalCString(id) { idPtr in
                title.withCString { titlePtr in
                    body.withCString { bodyPtr in
                        vault_ffi_upsert_secure_note(
                            self.handle, idPtr, titlePtr, bodyPtr, now,
                            &vault, &vaultLength, &idOut, &idLength)
                    }
                }
            }
            guard code == VaultFFICode.ok, let vault, let idOut else {
                throw VaultError.ffi(code: code, operation: "upsert_secure_note")
            }
            defer {
                vault_ffi_free(vault, vaultLength)
                vault_ffi_free(idOut, idLength)
            }
            try VaultShared.writeVault(Data(bytes: vault, count: vaultLength))
            return String(decoding: Data(bytes: idOut, count: idLength), as: UTF8.self)
        }
    }

    /// Register a NEW passkey and persist it, returning what the relying party
    /// needs back.
    ///
    /// One call, not create-then-store, and the reason is the same one that
    /// governs every write in this file: this is the user's only copy. The Rust
    /// side puts the private key into the returned vault bytes before it hands
    /// back the credential id, and we write those bytes BEFORE reporting
    /// success — so the site never receives a credential whose key never reached
    /// the vault, which would be a passkey that registers once and can never
    /// sign in again.
    ///
    /// `userVerified` must reflect what actually gated this — Face ID or the
    /// master password — because it is written into the attestation the site
    /// trusts.
    func registerPasskey(
        rpID: String, userName: String, userHandle: Data, userVerified: Bool,
        excludedCredentialIDs: [Data] = []
    ) async throws -> VaultPasskeyRegistration {
        try await Self.run {
            let lock = try VaultShared.acquireVaultLock()
            defer { lock.release() }
            try Self.foldInDiskState(self.handle)
            let known = try Self.readPasskeyIdentities(self.handle)
            if known.contains(where: { $0.rpID == rpID && excludedCredentialIDs.contains($0.credentialID) }) {
                throw VaultError.ffi(code: VaultFFICode.operationFailed, operation: "excluded_credential")
            }
            var vault: UnsafeMutablePointer<UInt8>?
            var vaultLength = 0
            var credID: UnsafeMutablePointer<UInt8>?
            var credLength = 0
            var attObj: UnsafeMutablePointer<UInt8>?
            var attLength = 0
            let now = Int64(Date().timeIntervalSince1970 * 1000)

            let code: Int32 = rpID.withCString { rpPtr in
                userName.withCString { userPtr in
                    userHandle.withUnsafeBytes { handleBuf in
                        vault_ffi_passkey_register(
                            self.handle, rpPtr, userPtr,
                            handleBuf.bindMemory(to: UInt8.self).baseAddress,
                            handleBuf.count, userVerified, now,
                            &vault, &vaultLength,
                            &credID, &credLength,
                            &attObj, &attLength)
                    }
                }
            }
            guard code == VaultFFICode.ok, let vault, let credID, let attObj else {
                throw VaultError.ffi(code: code, operation: "passkey_register")
            }
            defer {
                vault_ffi_free(vault, vaultLength)
                vault_ffi_free(credID, credLength)
                vault_ffi_free(attObj, attLength)
            }
            // Persist BEFORE returning the credential — see the doc comment.
            #if os(macOS)
            try VaultShared.commitPasskeyRegistration(Data(bytes: vault, count: vaultLength))
            #else
            try VaultShared.writeVault(Data(bytes: vault, count: vaultLength))
            #endif
            return VaultPasskeyRegistration(
                credentialID: Data(bytes: credID, count: credLength),
                attestationObject: Data(bytes: attObj, count: attLength))
        }
    }

    /// Soft-delete an item (it moves to the Trash, restorable on the desktop),
    /// persisting the vault file.
    func deleteItem(id: String) async throws {
        try await Self.run {
            let lock = try VaultShared.acquireVaultLock()
            defer { lock.release() }
            try Self.foldInDiskState(self.handle)
            var vault: UnsafeMutablePointer<UInt8>?
            var vaultLength = 0
            let now = Int64(Date().timeIntervalSince1970 * 1000)
            let code = id.withCString {
                vault_ffi_delete_item(self.handle, $0, now, &vault, &vaultLength)
            }
            guard code == VaultFFICode.ok, let vault else {
                throw VaultError.ffi(code: code, operation: "delete_item")
            }
            defer { vault_ffi_free(vault, vaultLength) }
            try VaultShared.writeVault(Data(bytes: vault, count: vaultLength))
        }
    }

    /// Turn quick unlock off.
    ///
    /// The keychain item goes first, so the key stops being usable the moment
    /// the user asks. Stripping the wrapping from the file matters too: deleting
    /// the key alone would leave the wrapping in the vault, where it travels to
    /// every device the vault syncs to.
    func disableDeviceUnlock() async throws {
        try await Self.run {
            let lock = try VaultShared.acquireVaultLock()
            defer { lock.release() }
            try Self.foldInDiskState(self.handle)
            Self.deleteDeviceKey()

            var vault: UnsafeMutablePointer<UInt8>?
            var vaultLength = 0
            let code = vault_ffi_disable_device_unlock(self.handle, &vault, &vaultLength)
            guard code == VaultFFICode.ok, let vault else {
                throw VaultError.ffi(code: code, operation: "disable_device_unlock")
            }
            defer { vault_ffi_free(vault, vaultLength) }
            try VaultShared.writeVault(Data(bytes: vault, count: vaultLength))
        }
    }

    /// Whether the VAULT carries a device-wrapped key.
    ///
    /// A different question from whether the keychain holds one, and worth
    /// asking separately: a key outlives the vault that accepted it if the file
    /// is replaced from a backup, and a client trusting only the keychain would
    /// prompt for a biometric and then fail to open anything.
    func hasDeviceUnlock() async -> Bool {
        let result = try? await Self.run {
            vault_ffi_has_device_unlock(self.handle) == 1
        }
        return result ?? false
    }

    // MARK: Plumbing

    /// Run blocking work on the vault queue and `await` it.
    ///
    /// Not cancellable: neither the biometric prompt nor Argon2id can be
    /// interrupted once started, so pretending otherwise would be a lie. They are
    /// bounded — the prompt by the user, the KDF by the header's parameters.
    /// The same queue, for the sync surface in VaultSync.swift. Sharing it is
    /// the point: `vault_ffi_sync_*` and `vault_ffi_*` touch the same vault, and
    /// the C ABI forbids overlapping calls on it.
    static func runSync<T: Sendable>(
        _ work: @escaping @Sendable () throws -> T
    ) async throws -> T {
        try await run(work)
    }

    /// The raw handle, for `vault_ffi_sync_new`. Not for general use: everything
    /// else goes through a method that keeps the call on the queue.
    var rawHandle: OpaquePointer { handle }

    private static func run<T: Sendable>(
        _ work: @escaping @Sendable () throws -> T
    ) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                continuation.resume(with: Result { try work() })
            }
        }
    }

    /// Fail closed if the linked static library is a different ABI than this
    /// source was written against.
    private static func checkAbi() throws {
        let linked = vault_ffi_abi_version()
        guard linked == VaultShared.requiredAbiVersion else {
            throw VaultError.abiMismatch(linked: linked, expected: VaultShared.requiredAbiVersion)
        }
    }

    /// Base keychain query identifying the one device-key item. Shared by every
    /// operation on it, so the four attributes that decide *which* item is
    /// touched cannot drift between read, write, delete and probe.
    private static func deviceKeyQuery() -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: VaultShared.keychainService,
            kSecAttrAccount as String: VaultShared.deviceKeyAccount,
            kSecAttrAccessGroup as String: VaultShared.keychainAccessGroup,
        ]
        #if os(macOS)
        // Arca writes the device key into the DATA-PROTECTION keychain, which is
        // the one that carries access groups and biometric access control.
        // Without this flag the query hits the file-based login keychain and
        // finds nothing. iOS has only the data-protection keychain.
        query[kSecUseDataProtectionKeychain as String] = true
        #endif
        return query
    }

    /// Store the device key, replacing whatever was there.
    private static func storeDeviceKey(_ key: Data) throws {
        // Replace rather than add: `SecItemAdd` over an existing item fails with
        // errSecDuplicateItem, and a leftover key from a previous enrolment
        // would unlock nothing.
        deleteDeviceKey()

        // `biometryCurrentSet` invalidates the key when a face or finger is
        // added, which is the defence against someone who has the passcode
        // enrolling their own biometrics. It cannot be satisfied on a device
        // with none enrolled, so fall back to `userPresence` there — the master
        // password is the backstop either way.
        let context = LAContext()
        let hasBiometrics = context.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics, error: nil)
        let flags: SecAccessControlCreateFlags =
            hasBiometrics ? .biometryCurrentSet : .userPresence

        // WhenUnlockedThisDeviceOnly: the key is for THIS device, so it must
        // never reach a backup or another device via iCloud Keychain.
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            nil)
        else {
            throw VaultError.deviceKeyNotStored(status: errSecParam)
        }

        var query = deviceKeyQuery()
        // kSecAttrAccessControl carries the accessibility itself; setting
        // kSecAttrAccessible alongside it is rejected.
        query[kSecAttrAccessControl as String] = access
        query[kSecValueData as String] = key

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw VaultError.deviceKeyNotStored(status: status)
        }
    }

    /// Remove the device key. Missing is success — the caller wants it gone.
    private static func deleteDeviceKey() {
        _ = SecItemDelete(deviceKeyQuery() as CFDictionary)
    }

    /// Forget the stored device key without an open vault to strip the wrapping
    /// from. For when the vault FILE is replaced: the key was minted for a file
    /// that no longer exists, and leaving it would offer a biometric unlock that
    /// cannot possibly work.
    static func forgetDeviceKey() { deleteDeviceKey() }

    /// Whether a device key is stored, WITHOUT prompting for it.
    ///
    /// Asking for the data would put a Face ID sheet on screen to answer what is
    /// only a question about which button to draw. So the probe must say "yes,
    /// but it is behind authentication" rather than actually authenticating.
    ///
    /// This used to pass `kSecUseAuthenticationUISkip`, which does the opposite
    /// of what the name suggests here: it *silently omits* every item that would
    /// need an authentication prompt, so the one item we are asking about was
    /// filtered out of the result set and the call returned `errSecItemNotFound`.
    /// The accepted statuses below are the ones `kSecUseAuthenticationUIFail`
    /// produces — the constant and the check disagreed.
    ///
    /// It looked fine for months because the simulator has no Secure Enclave and
    /// does not enforce the access control, so nothing was ever classified as
    /// needing UI and the item came straight back. On a real phone quick unlock
    /// therefore reported "not set up" forever, including immediately after
    /// being switched on.
    ///
    /// An `LAContext` with `interactionNotAllowed` is the documented way to ask:
    /// an ACL-protected item answers `errSecInteractionNotAllowed`, which is a
    /// yes.
    static var hasStoredDeviceKey: Bool {
        let context = LAContext()
        context.interactionNotAllowed = true
        defer { context.invalidate() }

        var query = deviceKeyQuery()
        // Ask for attributes, not data: an existence check with no return type
        // at all is not a contract SecItem defines.
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationContext as String] = context

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        let stored = status == errSecSuccess || status == errSecInteractionNotAllowed
        if !stored && status != errSecItemNotFound {
            // Anything else is a real surprise, and the last bug here was
            // invisible precisely because nothing was ever logged.
            vaultLog.error("device-key probe: unexpected OSStatus \(status, privacy: .public)")
        }
        return stored
    }

    /// Read the device key from the shared keychain group, gated by Touch ID /
    /// Face ID / the device passcode, and hand it to `body`.
    ///
    /// Scoped rather than returned so no copy of the key outlives the open it was
    /// read for. The wipe is best-effort: `Data` is copy-on-write, so it clears
    /// the buffer only while this is the last reference — which is precisely why
    /// the key never leaves this function.
    private static func withDeviceKey<T>(reason: String, _ body: (Data) throws -> T) throws -> T {
        let context = LAContext()
        context.localizedReason = reason
        // Never reuse an earlier authentication: every vault open is its own
        // deliberate act. Zero is the default; stated so it cannot drift.
        context.touchIDAuthenticationAllowableReuseDuration = 0
        defer { context.invalidate() }

        var query = deviceKeyQuery()
        query[kSecReturnData as String] = true
        query[kSecUseAuthenticationContext as String] = context

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, var key = result as? Data else {
            throw VaultError.noDeviceKey(status: status)
        }
        defer { key.resetBytes(in: 0..<key.count) }
        return try body(key)
    }
}

struct VaultPasswordHistory: Decodable, Identifiable, Sendable {
    let id: String
    let replacedAt: Int64
}
