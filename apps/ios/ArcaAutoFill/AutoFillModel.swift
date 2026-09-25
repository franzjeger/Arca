// State for the AutoFill extension: unlock, then either fill the credential the
// OS named or show the ones matching the site.
//
// The extension is a SEPARATE PROCESS from the app, so it cannot borrow the
// app's unlocked session. It opens the vault itself: with the device key from
// the shared keychain when the user has turned quick unlock on — a biometric and
// a symmetric unwrap — and otherwise with the master password, which costs a
// full Argon2id derivation on every single fill. That difference is why
// `vault_ffi_enable_device_unlock` exists.

import AuthenticationServices
import Observation
import os

private let log = Logger(subsystem: "no.sybr.vault.ios.autofill", category: "provider")

@MainActor
@Observable
final class AutoFillModel {

    enum Phase: Equatable {
        case locked
        case unlocking
        case picking
    }

    /// The OS asked for one specific credential rather than a list.
    enum DirectRequest {
        case password(recordID: String, user: String)
        /// A passkey assertion. The hash is of the clientDataJSON the OS built;
        /// signing it is the whole ceremony.
        case passkey(recordID: String, clientDataHash: Data, rpID: String)
        /// A passkey REGISTRATION: mint a new credential for the site, store it,
        /// and hand back the attestation. `clientDataHash` is over the
        /// clientDataJSON the OS built for this ceremony.
        case registerPasskey(
            rpID: String, userName: String, userHandle: Data, clientDataHash: Data,
            excludedCredentialIDs: [Data])
    }

    private(set) var phase: Phase = .locked
    private(set) var identities: [VaultIdentity] = []
    private(set) var failure: String?

    /// Whether the password field should offer a biometric retry.
    ///
    /// Cached, and resolved off the main actor. It used to call the keychain
    /// directly and is read from inside `UnlockForm.body`, so a blocking XPC to
    /// securityd ran on the main thread on every redraw — in the one process
    /// iOS kills outright for wedging its main thread. It answers `false` until
    /// the probe lands, which is the safe way round: the worst case is that the
    /// retry button appears a moment late.
    private(set) var canUseDeviceKey = false

    private let domains: Set<String>
    private let direct: DirectRequest?
    private let onFill: @MainActor (ASPasswordCredential) -> Void
    private let onFillPasskey: @MainActor (ASPasskeyAssertionCredential) -> Void
    private let onRegisterPasskey: @MainActor (ASPasskeyRegistrationCredential) -> Void
    /// The RP's excludeCredentials named a passkey we already hold: decline with
    /// the dedicated WebAuthn code rather than minting a duplicate.
    private let onDeclineExcluded: @MainActor () -> Void
    private let onCancel: @MainActor () -> Void

    private var session: VaultSession?

    init(
        domains: Set<String>,
        direct: DirectRequest?,
        onFill: @escaping @MainActor (ASPasswordCredential) -> Void,
        onFillPasskey: @escaping @MainActor (ASPasskeyAssertionCredential) -> Void = { _ in },
        onRegisterPasskey: @escaping @MainActor (ASPasskeyRegistrationCredential) -> Void = { _ in },
        onDeclineExcluded: @escaping @MainActor () -> Void = {},
        onCancel: @escaping @MainActor () -> Void
    ) {
        self.domains = domains
        self.direct = direct
        self.onFill = onFill
        self.onFillPasskey = onFillPasskey
        self.onRegisterPasskey = onRegisterPasskey
        self.onDeclineExcluded = onDeclineExcluded
        self.onCancel = onCancel
    }

    func cancel() { onCancel() }

    /// The keychain existence check, off the main actor.
    private static func probeDeviceKey() async -> Bool {
        await Task.detached(priority: .userInitiated) {
            VaultSession.hasStoredDeviceKey
        }.value
    }


    /// Try the device key straight away. Falls through to the password form when
    /// there is no key or the biometric is declined — never blocks on it.
    func start() async {
        // Probe here rather than trusting the cached value: this runs before the
        // first redraw, so nothing has populated it yet.
        let stored = await Self.probeDeviceKey()
        canUseDeviceKey = stored
        guard stored else { return }
        await open(fallback: "Couldn't unlock with Face ID.") {
            try await VaultSession.openWithDeviceKey(reason: "fill a password from Arca")
        }
    }

    func useDeviceKey() async {
        await open(fallback: "Couldn't unlock with Face ID.") {
            try await VaultSession.openWithDeviceKey(reason: "fill a password from Arca")
        }
    }

    /// Argon2id needs the vault header's memory cost in one block — 64 MiB at
    /// Arca's defaults — and an AutoFill extension has a hard memory ceiling it
    /// is KILLED for crossing, not slowed. `os_proc_available_memory` is
    /// Apple's documented way to ask whether an expensive operation will fit
    /// before starting it.
    ///
    /// The headroom is for everything the derivation does not account for: the
    /// decrypted vault, SwiftUI, and the allocator's own slack. Refusing with a
    /// sentence beats being terminated mid-fill, which the user sees as the
    /// keyboard simply forgetting Arca exists.
    private static let argon2Budget = 64 << 20
    private static let headroom = 24 << 20

    private static var canAffordPasswordUnlock: Bool {
        os_proc_available_memory() > argon2Budget + headroom
    }

    func unlock(password: String) async {
        guard Self.canAffordPasswordUnlock else {
            log.error("refusing password unlock: \(os_proc_available_memory(), privacy: .public) bytes available")
            failure = """
                Not enough memory here to derive the key. Open Arca and turn on \
                Face ID — filling then costs a fraction of this.
                """
            return
        }
        await open(fallback: "Couldn't unlock the vault.") {
            try await VaultSession.openWithMasterPassword(password)
        }
    }

    /// Both unlock paths converge here: get a handle, then either fill the one
    /// credential the OS named or show the ones matching the site.
    private func open(
        fallback: String,
        _ makeSession: @Sendable () async throws -> VaultSession
    ) async {
        guard phase != .unlocking else { return }
        phase = .unlocking
        failure = nil
        do {
            let session = try await makeSession()
            self.session = session

            // Asked for one credential: hand it back rather than showing a list
            // of one and making the user tap it.
            switch direct {
            case let .password(recordID, user):
                await fill(recordID: recordID, user: user)
                return
            case let .passkey(recordID, clientDataHash, rpID):
                await assertPasskey(
                    recordID: recordID, clientDataHash: clientDataHash, rpID: rpID)
                return
            case let .registerPasskey(rpID, userName, userHandle, clientDataHash, excluded):
                await registerPasskey(
                    rpID: rpID, userName: userName, userHandle: userHandle,
                    clientDataHash: clientDataHash, excludedCredentialIDs: excluded)
                return
            case nil:
                break
            }

            identities = try await session.identities()
                .filter { domains.isEmpty || domains.contains($0.domain) }
                .sorted {
                    ($0.domain.lowercased(), $0.user.lowercased())
                        < ($1.domain.lowercased(), $1.user.lowercased())
                }
            phase = .picking
        } catch {
            log.error("unlock failed: \(vaultLogMessage(for: error), privacy: .public)")
            // A declined biometric is a choice, not an error: the password field
            // is already on screen.
            failure = Self.cancelled(error) ? nil : Self.message(error, fallback: fallback)
            phase = .locked
        }
    }

    func pick(_ identity: VaultIdentity) async {
        await fill(recordID: identity.id, user: identity.user)
    }

    private func fill(recordID: String, user: String) async {
        guard let session else { return }
        do {
            let password = try await session.password(forID: recordID)
            onFill(ASPasswordCredential(user: user, password: password))
        } catch {
            log.error("fill failed: \(vaultLogMessage(for: error), privacy: .public)")
            failure = Self.message(error, fallback: "Couldn't read that password.")
            // Back to the list if there is one, otherwise to the password field.
            phase = identities.isEmpty ? .locked : .picking
        }
    }

    /// Sign the relying party's challenge with the stored passkey.
    ///
    /// `userVerified: true` is earned, not asserted: this line is only reached
    /// after `open` succeeded, and both unlock paths — Face ID for the device
    /// key, or the master password through Argon2id — are user verification in
    /// WebAuthn's sense. The flag goes into the authenticator data, and the
    /// relying party trusts it.
    private func assertPasskey(recordID: String, clientDataHash: Data, rpID: String) async {
        guard let session else { return }
        do {
            let assertion = try await session.assertPasskey(
                forID: recordID, clientDataHash: clientDataHash, userVerified: true)
            onFillPasskey(
                ASPasskeyAssertionCredential(
                    userHandle: assertion.userHandle,
                    relyingParty: rpID,
                    signature: assertion.signature,
                    clientDataHash: clientDataHash,
                    authenticatorData: assertion.authenticatorData,
                    credentialID: assertion.credentialID))
        } catch {
            log.error("passkey assert failed: \(vaultLogMessage(for: error), privacy: .public)")
            failure = Self.message(error, fallback: "Couldn't sign in with that passkey.")
            phase = .locked
        }
    }

    /// Mint a new passkey for the site, store it in the vault, and hand back the
    /// attestation.
    ///
    /// `userVerified: true` is earned the same way as the assertion above: this
    /// is only reached after `open` succeeded, which took Face ID or the master
    /// password. The persist happens inside `registerPasskey` BEFORE it returns,
    /// so the site never gets a credential whose private key is not on disk.
    private func registerPasskey(
        rpID: String, userName: String, userHandle: Data, clientDataHash: Data,
        excludedCredentialIDs: [Data]
    ) async {
        guard let session else { return }
        do {
            // Give the system its specific exclusion response. The session
            // repeats this check under the file lock before committing.
            if !excludedCredentialIDs.isEmpty {
                let excluded = Set(excludedCredentialIDs)
                let mine = try await session.passkeyIdentities()
                if mine.contains(where: { $0.rpID == rpID && excluded.contains($0.credentialID) }) {
                    log.info("excludeCredentials matched a stored passkey; declining")
                    onDeclineExcluded()
                    return
                }
            }
            let reg = try await session.registerPasskey(
                rpID: rpID, userName: userName,
                userHandle: userHandle, userVerified: true,
                excludedCredentialIDs: excludedCredentialIDs)

            // Publish the new passkey to the OS BEFORE completing, or it saves
            // to the vault but is never offered for sign-in until the main app
            // is next opened — iOS only routes an assertion to Arca for relying
            // parties the credential-identity store has been told about. Re-read
            // and republish the WHOLE set (logins + passkeys): the store does a
            // full replace, so passing only the new passkey would wipe the
            // logins. Failure here is not fatal — the credential is safely
            // stored; the next app unlock republishes — so it must not block
            // handing the attestation back to the site.
            // Publish ONLY when both reads succeed. replace() does a full-set
            // replaceCredentialIdentities, so publishing a partial or empty set
            // on a read failure would WIPE the store instead of leaving it for
            // the next app unlock to republish.
            if let logins = try? await session.identities(),
               let passkeys = try? await session.passkeyIdentities() {
                await CredentialIdentities.replace(with: logins, passkeys: passkeys)
            } else {
                log.error("could not read identities to publish the new passkey; next app unlock will")
            }

            onRegisterPasskey(
                ASPasskeyRegistrationCredential(
                    relyingParty: rpID,
                    clientDataHash: clientDataHash,
                    credentialID: reg.credentialID,
                    attestationObject: reg.attestationObject))
        } catch {
            if case VaultError.ffi(_, "excluded_credential") = error {
                onDeclineExcluded()
                return
            }
            log.error("passkey register failed: \(vaultLogMessage(for: error), privacy: .public)")
            failure = Self.message(error, fallback: "Couldn't create that passkey.")
            phase = .locked
        }
    }

    private static func message(_ error: Error, fallback: String) -> String {
        (error as? LocalizedError)?.errorDescription ?? fallback
    }

    private static func cancelled(_ error: Error) -> Bool {
        guard let vaultError = error as? VaultError else { return false }
        switch vaultError {
        case .noDeviceKey(let status), .deviceKeyNotStored(let status):
            return status == errSecUserCanceled
        default:
            return false
        }
    }
}
