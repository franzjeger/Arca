// Add or edit a login on the phone.
//
// This is what turns the app from a viewer into a manager: until the FFI could
// write (ABI v6) you could read a password here but had to reach for the Mac to
// save one.
//
// Editing loads the existing password on appear, which costs one authenticated
// read — the identity list carries metadata only, never the secret. A create
// skips that entirely.

import SwiftUI

struct LoginEditView: View {
    /// nil creates a new login; otherwise the item being edited.
    let existing: VaultItemMeta?

    @Environment(VaultStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    @State private var title = ""
    @State private var username = ""
    @State private var password = ""
    @State private var url = ""
    @State private var revealed = false
    @State private var loading = false
    @State private var saving = false
    @State private var generating = false
    @State private var scanning = false
    /// What to do with the verification code on save. nil = leave untouched,
    /// which the ABI's v11 semantics make the safe default — the secret never
    /// crosses to Swift, so "put back what was there" is not an option.
    @State private var totpChange: String?
    /// Whether the login HAD a code when the sheet opened (metadata only).
    @State private var hadTotp = false
    @State private var failure: String?

    private var isEdit: Bool { existing != nil }
    /// A login with nothing to identify it and nothing to fill is not worth
    /// saving; anything else is the user's call, not ours.
    private var canSave: Bool {
        !saving && !loading
            && !(title.isEmpty && username.isEmpty && url.isEmpty)
            && !password.isEmpty
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Title", text: $title)
                        .textContentType(.organizationName)
                    TextField("Website", text: $url)
                        .textContentType(.URL)
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }
                Section {
                    TextField("Username", text: $username)
                        .textContentType(.username)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    HStack {
                        // A password field the user cannot read back is a good
                        // way to save a typo they can never diagnose.
                        Group {
                            if revealed {
                                TextField("Password", text: $password)
                            } else {
                                SecureField("Password", text: $password)
                            }
                        }
                        .textContentType(.password)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()

                        Button {
                            revealed.toggle()
                        } label: {
                            Image(systemName: revealed ? "eye.slash" : "eye")
                        }
                        .buttonStyle(.borderless)
                        .accessibilityLabel(revealed ? "Hide password" : "Show password")

                        Button {
                            generating = true
                        } label: {
                            Image(systemName: "wand.and.sparkles")
                        }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("Generate a password")
                    }
                }
                Section("Verification code") {
                    switch (hadTotp, totpChange) {
                    case (_, ""):
                        // Explicit removal, pending save.
                        Label("Code will be removed", systemImage: "clock.badge.xmark")
                            .foregroundStyle(.secondary)
                        Button("Undo") { totpChange = nil }
                    case (_, .some):
                        Label("New code scanned", systemImage: "clock.badge.checkmark")
                            .foregroundStyle(.green)
                        Button("Scan again", systemImage: "qrcode.viewfinder") { scanning = true }
                    case (true, nil):
                        Label("This login has a code", systemImage: "clock.badge.checkmark")
                            .foregroundStyle(.secondary)
                        Button("Replace by scanning", systemImage: "qrcode.viewfinder") {
                            scanning = true
                        }
                        Button("Remove code", role: .destructive) { totpChange = "" }
                    case (false, nil):
                        // The reason this exists: the site shows its QR to the
                        // phone, and the phone is where the camera is.
                        Button("Scan QR code", systemImage: "qrcode.viewfinder") {
                            scanning = true
                        }
                    }
                }

                if let failure {
                    Section {
                        Text(failure)
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                }
            }
            .disabled(loading)
            .navigationTitle(isEdit ? "Edit Login" : "New Login")
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
            .sheet(isPresented: $scanning) {
                QRScannerView { payload in
                    // The raw otpauth:// URI, verbatim. The Rust side parses and
                    // validates it at save — a second parser here would just be
                    // one more place for the two to disagree.
                    totpChange = payload
                }
            }
            .sheet(isPresented: $generating) {
                PasswordGeneratorView { generated in
                    password = generated
                    // Revealed on purpose: a password you just generated and
                    // cannot see is one you have no reason to trust arrived
                    // intact, and it is going to be saved in a moment anyway.
                    revealed = true
                }
            }
        }
    }

    /// Prefill from the item being edited.
    ///
    /// From the DETAIL, not the list row. The row carries the host — `host_of`
    /// applied to the URL — so prefilling from it silently rewrote
    /// "https://github.com/login" to "github.com" on every edit, quietly
    /// discarding the path the site actually needs.
    private func load() async {
        guard let existing else { return }
        loading = true
        defer { loading = false }
        guard case let .login(t, u, p, link, _, _) = await store.detail(for: existing) else {
            // Saving now would overwrite real fields with empty ones.
            failure = "Could not read that login. Close and try again."
            return
        }
        title = t
        username = u
        url = link
        password = p
        hadTotp = existing.hasTotp
    }

    private func save() async {
        saving = true
        defer { saving = false }
        if let message = await store.saveLogin(
            id: existing?.id, title: title, username: username,
            password: password, url: url, totpSecret: totpChange)
        {
            failure = message
            return
        }
        dismiss()
    }
}
