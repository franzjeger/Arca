// Add or edit a Wi-Fi network on the phone.
//
// The phone is where Wi-Fi passwords actually arrive — someone reads you the
// cabin's network over coffee — so writing them down should not require the
// Mac. Mirrors LoginEditView's shape: metadata from the list row, the secret
// fetched on appear for an edit, everything held in @State only while the
// sheet is up.

import SwiftUI

struct WifiEditView: View {
    /// nil creates; otherwise the Wi-Fi item being edited.
    let existing: VaultItemMeta?

    @Environment(VaultStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    @State private var title = ""
    @State private var ssid = ""
    @State private var password = ""
    @State private var security = "WPA"
    @State private var hidden = false
    @State private var revealed = false
    @State private var loading = false
    @State private var saving = false
    @State private var failure: String?

    /// The join-QR tokens vault-core stores, with labels a person recognises.
    private static let securities: [(token: String, label: String)] = [
        ("WPA", "WPA / WPA2 / WPA3"),
        ("WEP", "WEP"),
        ("nopass", "Open (no password)"),
    ]

    private var canSave: Bool {
        // An open network legitimately has no password; any other kind without
        // one is a typo waiting to be saved.
        !saving && !loading && !ssid.isEmpty
            && (security == "nopass" || !password.isEmpty)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Network name (SSID)", text: $ssid)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("Title (optional)", text: $title)
                }
                Section {
                    Picker("Security", selection: $security) {
                        ForEach(Self.securities, id: \.token) { entry in
                            Text(entry.label).tag(entry.token)
                        }
                    }
                    if security != "nopass" {
                        HStack {
                            Group {
                                if revealed {
                                    TextField("Password", text: $password)
                                } else {
                                    SecureField("Password", text: $password)
                                }
                            }
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()

                            Button {
                                revealed.toggle()
                            } label: {
                                Image(systemName: revealed ? "eye.slash" : "eye")
                            }
                            .buttonStyle(.borderless)
                            .accessibilityLabel(revealed ? "Hide password" : "Show password")
                        }
                    }
                    Toggle("Hidden network", isOn: $hidden)
                }
                if let failure {
                    Section {
                        Text(failure).font(.footnote).foregroundStyle(.red)
                    }
                }
            }
            .disabled(loading)
            .navigationTitle(existing == nil ? "New Wi-Fi" : "Edit Wi-Fi")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(saving ? "Saving…" : "Save") { Task { await save() } }
                        .disabled(!canSave)
                }
            }
            .task { await load() }
        }
    }

    private func load() async {
        guard let existing else { return }
        loading = true
        defer { loading = false }
        guard case let .wifi(t, s, p, sec, hid, _) = await store.detail(for: existing) else {
            failure = "Could not read that network. Close and try again."
            return
        }
        title = t
        ssid = s
        password = p
        security = sec.isEmpty ? "WPA" : sec
        hidden = hid
    }

    private func save() async {
        saving = true
        defer { saving = false }
        if let message = await store.saveWifi(
            id: existing?.id, title: title, ssid: ssid,
            // An open network stores no stale passphrase from a previous mode.
            password: security == "nopass" ? "" : password,
            security: security, hidden: hidden)
        {
            failure = message
            return
        }
        dismiss()
    }
}
