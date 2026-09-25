// The extension's picker UI: the real logins for the site, from the vault.
// Picking one fills it (after the Touch ID that opened the vault).
//
// Renders `VaultIdentity` straight from the bridge — a parallel row struct would
// just be four fields of the same thing, kept in sync by hand.

import SwiftUI

struct CredentialListView: View {
    let identities: [VaultIdentity]
    /// Why the vault couldn't be opened, if it couldn't. Already user-facing.
    let failure: String?
    let onPick: (VaultIdentity) -> Void
    let onCancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "key.fill").foregroundStyle(.tint)
                Text("Arca").font(.headline)
                Spacer()
                Button("Cancel", action: onCancel)
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
            }

            if let failure {
                Text(failure)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else if identities.isEmpty {
                Text("No matching logins.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                ScrollView {
                    VStack(spacing: 6) {
                        ForEach(identities) { identity in
                            Button { onPick(identity) } label: {
                                row(for: identity)
                            }
                            .buttonStyle(.plain)
                            .accessibilityLabel("\(title(for: identity)), \(identity.domain)")
                        }
                    }
                }
            }

            Spacer(minLength: 0)
        }
        .padding(16)
        .frame(minWidth: 340, minHeight: 240)
    }

    private func row(for identity: VaultIdentity) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "person.crop.circle")
                .font(.title3)
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text(title(for: identity)).font(.body)
                Text(identity.domain).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Image(systemName: "chevron.right")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .padding(10)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
        .contentShape(Rectangle())
    }

    /// The username, falling back to the item's title and then its domain — a
    /// login saved without a username shouldn't render as a blank row.
    private func title(for identity: VaultIdentity) -> String {
        [identity.user, identity.label].first { !$0.isEmpty } ?? identity.domain
    }
}
