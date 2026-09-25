// Publishing login identities to ASCredentialIdentityStore.
//
// This is what puts Arca in the QuickType bar. Without it the provider is
// installed but invisible: iOS only suggests Arca on a page it already knows
// Arca has a login for, and the store is how it knows.
//
// METADATA ONLY — domain, username, and the vault item's id. No password ever
// crosses this boundary; the extension fetches those itself, one per fill. That
// is exactly why the store can stay populated while the vault is shut.

import AuthenticationServices
import os

private let log = Logger(subsystem: "no.sybr.vault.ios", category: "identities")

enum CredentialIdentities {

    /// Republish the whole set.
    ///
    /// Returns whether AutoFill is switched on for Arca in Settings. The store
    /// quietly accepts nothing while it is off, so the answer is worth having:
    /// the app can say what to turn on instead of looking broken.
    @discardableResult
    static func replace(
        with identities: [VaultIdentity],
        passkeys: [VaultSession.VaultPasskeyIdentity] = []
    ) async -> Bool {
        guard await ASCredentialIdentityStore.shared.state().isEnabled else {
            log.info("AutoFill not enabled for Arca; skipping identity publish")
            return false
        }

        // An item with no URL has no domain to match on, so publishing it would
        // only ever clutter the QuickType bar.
        var entries: [ASCredentialIdentity] = identities
            .filter { !$0.domain.isEmpty }
            .map {
                ASPasswordCredentialIdentity(
                    serviceIdentifier: ASCredentialServiceIdentifier(
                        identifier: $0.domain, type: .domain),
                    user: $0.user,
                    recordIdentifier: $0.id)
            }
        // Passkeys ride in the same store. This is the line that makes a
        // stored passkey USABLE on the phone: iOS only routes an assertion to
        // Arca for relying parties it has been told about.
        entries += passkeys.map {
            ASPasskeyCredentialIdentity(
                relyingPartyIdentifier: $0.rpID,
                userName: $0.userName,
                credentialID: $0.credentialID,
                userHandle: $0.userHandle,
                recordIdentifier: $0.id)
        }

        do {
            try await ASCredentialIdentityStore.shared.replaceCredentialIdentities(entries)
            log.info("published \(entries.count, privacy: .public) identities")
        } catch {
            // Never fatal. The vault is open and usable; AutoFill just will not
            // suggest anything until the next unlock republishes.
            log.error("identity publish failed: \(vaultLogMessage(for: error), privacy: .public)")
        }
        return true
    }

    /// Drop everything, for when the vault file is replaced — the identities on
    /// file describe a vault that is gone.
    static func removeAll() async {
        do {
            try await ASCredentialIdentityStore.shared.removeAllCredentialIdentities()
        } catch {
            log.error("identity clear failed: \(vaultLogMessage(for: error), privacy: .public)")
        }
    }
}
