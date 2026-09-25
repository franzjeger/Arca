// The extension's UI: a password field, then the logins matching the site.

import SwiftUI

struct UnlockPickerView: View {
    // Plain `let` is correct for an @Observable model — reading its properties
    // inside `body` is what registers the dependency.
    let model: AutoFillModel

    var body: some View {
        NavigationStack {
            Group {
                switch model.phase {
                case .locked, .unlocking:
                    UnlockForm(model: model)
                case .picking:
                    picker
                }
            }
            .navigationTitle("Arca")
            .navigationBarTitleDisplayMode(.inline)
            // Try the device key immediately. With quick unlock on, a fill is a
            // glance instead of typing a master password into a keyboard
            // accessory view.
            .task { await model.start() }
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Cancel") { model.cancel() }
                }
            }
        }
    }

    @ViewBuilder
    private var picker: some View {
        if model.identities.isEmpty {
            ContentUnavailableView(
                "No matching logins",
                systemImage: "key",
                description: Text("This vault has no login saved for this site."))
        } else {
            List(model.identities) { identity in
                Button {
                    Task { await model.pick(identity) }
                } label: {
                    HStack(spacing: 12) {
                        Image(systemName: "person.crop.circle")
                            .font(.title2)
                            .foregroundStyle(.secondary)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(title(for: identity))
                            Text(identity.domain)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
            .listStyle(.plain)
        }
    }

    private func title(for identity: VaultIdentity) -> String {
        [identity.user, identity.label].first { !$0.isEmpty } ?? identity.domain
    }
}

private struct UnlockForm: View {
    let model: AutoFillModel

    @State private var password = ""
    @FocusState private var focused: Bool

    private var isUnlocking: Bool { model.phase == .unlocking }

    var body: some View {
        VStack(spacing: 18) {
            Spacer()

            Image(systemName: "lock.fill")
                .font(.system(size: 36))
                .foregroundStyle(.tint)
            Text("Unlock to fill")
                .font(.headline)

            SecureField("Master password", text: $password)
                .textFieldStyle(.roundedBorder)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .submitLabel(.go)
                .focused($focused)
                .onSubmit(submit)
                .disabled(isUnlocking)

            if let failure = model.failure {
                Text(failure)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
            }

            Button(action: submit) {
                if isUnlocking {
                    ProgressView().frame(maxWidth: .infinity)
                } else {
                    Text("Unlock").frame(maxWidth: .infinity)
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(password.isEmpty || isUnlocking)

            if model.canUseDeviceKey {
                Button("Use Face ID", systemImage: "faceid") {
                    Task { await model.useDeviceKey() }
                }
                .disabled(isUnlocking)
            }

            Spacer()
        }
        .padding(24)
        .onAppear { focused = true }
    }

    private func submit() {
        guard !password.isEmpty, !isUnlocking else { return }
        Task {
            await model.unlock(password: password)
            password = ""
        }
    }
}
