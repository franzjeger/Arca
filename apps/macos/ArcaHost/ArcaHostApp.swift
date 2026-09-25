// Arca AutoFill — host app (M2).
//
// Publishes the real vault's login identities (metadata only — domain +
// username, never passwords) to ASCredentialIdentityStore so they appear as
// AutoFill suggestions. Opening the vault to read identities takes one Touch ID;
// the passwords themselves are only ever read inside the extension, per fill.
// The shipping container will be the Tauri Arca.app; this host is the harness.

import AuthenticationServices
import SwiftUI

@main
struct ArcaHostApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .windowResizability(.contentSize)
    }
}

struct ContentView: View {
    @State private var status = "Checking…"
    @State private var isEnabled = false
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Arca AutoFill")
                .font(.title2).bold()

            Text(status)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Divider()

            VStack(alignment: .leading, spacing: 6) {
                Label("System Settings ▸ General ▸ AutoFill & Passwords ▸ enable Arca.", systemImage: "1.circle")
                Label("Press “Sync to AutoFill” (one Touch ID to read your logins).", systemImage: "2.circle")
                Label("In Safari / an app, pick an Arca suggestion — Touch ID fills it.", systemImage: "3.circle")
            }
            .font(.callout)

            HStack {
                Button("Open AutoFill Settings") { openAutoFillSettings() }
                Button("Sync to AutoFill") { Task { await sync() } }
                    .disabled(!isEnabled || busy)
                Spacer()
                Button("Refresh") { Task { await refresh() } }
                    .disabled(busy)
            }
            .padding(.top, 4)
        }
        .padding(28)
        .frame(width: 500)
        .task { await refresh() }
    }

    @MainActor
    private func refresh() async {
        let state = await ASCredentialIdentityStore.shared.state()
        isEnabled = state.isEnabled
        status = state.isEnabled
            ? "Arca is enabled. Press “Sync to AutoFill” to publish your logins."
            : "Arca is NOT enabled yet. Open AutoFill Settings, turn Arca on, then Refresh."
    }

    // Open the vault (Touch ID) and publish its login identities — metadata only.
    // Every step is awaited, so the window keeps drawing while the Touch ID
    // prompt is up and while the vault decrypts.
    @MainActor
    private func sync() async {
        busy = true
        defer { busy = false }
        do {
            let session = try await VaultSession.openWithDeviceKey(
                reason: "publish your Arca logins to AutoFill")
            var entries: [ASCredentialIdentity] = try await session.identities().map {
                ASPasswordCredentialIdentity(
                    serviceIdentifier: ASCredentialServiceIdentifier(identifier: $0.domain, type: .domain),
                    user: $0.user,
                    recordIdentifier: $0.id)
            }
            let logins = entries.count
            // Passkeys ride the same store. This registration is what makes the
            // OS route an assertion to Arca at all — without it the extension's
            // passkey code is never called.
            let passkeys = try await session.passkeyIdentities()
            entries += passkeys.map {
                ASPasskeyCredentialIdentity(
                    relyingPartyIdentifier: $0.rpID,
                    userName: $0.userName,
                    credentialID: $0.credentialID,
                    userHandle: $0.userHandle,
                    recordIdentifier: $0.id)
            }
            try await ASCredentialIdentityStore.shared.replaceCredentialIdentities(entries)
            status = "Synced \(logins) logins and \(passkeys.count) passkeys to AutoFill."
        } catch {
            // The bridge's own text says which of the several setup steps is
            // missing; a raw error dump did not.
            vaultLog.error("sync failed: \(vaultLogMessage(for: error), privacy: .public)")
            status = (error as? VaultError)?.errorDescription
                ?? "Sync failed. Is the vault set up in the shared container, and Touch ID available?"
        }
    }

    @MainActor
    private func openAutoFillSettings() {
        let candidates = [
            "x-apple.systempreferences:com.apple.Passwords-Settings.extension",
            "x-apple.systempreferences:com.apple.preferences.password",
        ]
        for s in candidates {
            if let url = URL(string: s), NSWorkspace.shared.open(url) { return }
        }
    }
}
