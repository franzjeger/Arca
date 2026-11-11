// The extension's UI: a password field, then the site's passkeys and logins
// above every other login, under a search field.

import SwiftUI

struct UnlockPickerView: View {
    // Plain `let` is correct for an @Observable model — reading its properties
    // inside `body` is what registers the dependency.
    let model: AutoFillModel

    @State private var query = ""

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

    /// The site's passkeys and logins first, then every other login, all under
    /// a search field: a login saved under another address, or with none, is
    /// one search away instead of a dead end.
    @ViewBuilder
    private var picker: some View {
        let logins = model.logins(matching: query)
        let searching = !query.trimmingCharacters(in: .whitespaces).isEmpty
        List {
            if let failure = model.failure {
                Text(failure)
                    .font(.callout)
                    .foregroundStyle(.red)
            }
            if !searching && !model.passkeys.isEmpty {
                Section("Passkeys") {
                    ForEach(model.passkeys) { passkey in
                        row(
                            icon: "person.badge.key",
                            title: passkey.userName.isEmpty ? passkey.rpID : passkey.userName,
                            detail: passkey.rpID
                        ) { await model.pick(passkey) }
                    }
                }
            }
            if !logins.site.isEmpty {
                Section(model.site.map { "For \($0)" } ?? "For this site") {
                    ForEach(logins.site) { login in row(for: login) }
                }
            } else if !searching && model.passkeys.isEmpty {
                Text(model.site.map { "No login saved for \($0)." } ?? "No login saved for this site.")
                    .foregroundStyle(.secondary)
            }
            if !logins.others.isEmpty {
                Section(logins.site.isEmpty && searching ? "Logins" : "Other logins") {
                    ForEach(logins.others) { login in row(for: login) }
                }
            }
        }
        .listStyle(.insetGrouped)
        .searchable(
            text: $query,
            placement: .navigationBarDrawer(displayMode: .always),
            prompt: "Search all logins")
        .textInputAutocapitalization(.never)
        .autocorrectionDisabled()
        .overlay {
            if searching && logins.site.isEmpty && logins.others.isEmpty {
                ContentUnavailableView.search(text: query)
            }
        }
    }

    private func row(for login: VaultIdentity) -> some View {
        row(
            icon: "person.crop.circle",
            title: [login.user, login.label].first { !$0.isEmpty } ?? login.domain,
            detail: login.domain.isEmpty ? login.label : login.domain
        ) { await model.pick(login) }
    }

    private func row(
        icon: String, title: String, detail: String,
        action: @escaping @MainActor () async -> Void
    ) -> some View {
        Button {
            Task { await action() }
        } label: {
            HStack(spacing: 12) {
                Image(systemName: icon)
                    .font(.title2)
                    .foregroundStyle(.secondary)
                    .frame(width: 30)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                    Text(detail)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
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
