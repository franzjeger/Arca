// Add or edit a secure note on the phone.
//
// The shortest editor in the app, deliberately: a title and a body. Notes are
// what people reach for when standing somewhere — a door code, a licence key
// read over the phone — which is exactly when a Mac is not available.

import SwiftUI

struct NoteEditView: View {
    /// nil creates; otherwise the note being edited.
    let existing: VaultItemMeta?

    @Environment(VaultStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    @State private var title = ""
    @State private var body_ = ""
    @State private var loading = false
    @State private var saving = false
    @State private var failure: String?

    /// A note needs SOMETHING — but title-only is fine ("Safe code is my
    /// birthday backwards" can be an entire note in its title).
    private var canSave: Bool {
        !saving && !loading && !(title.isEmpty && body_.isEmpty)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Title", text: $title)
                }
                Section {
                    TextEditor(text: $body_)
                        .frame(minHeight: 180)
                        .privacySensitive()
                }
                if let failure {
                    Section {
                        Text(failure).font(.footnote).foregroundStyle(.red)
                    }
                }
            }
            .disabled(loading)
            .navigationTitle(existing == nil ? "New Note" : "Edit Note")
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
        guard case let .secureNote(t, b) = await store.detail(for: existing) else {
            failure = "Could not read that note. Close and try again."
            return
        }
        title = t
        body_ = b
    }

    private func save() async {
        saving = true
        defer { saving = false }
        if let message = await store.saveNote(id: existing?.id, title: title, body: body_) {
            failure = message
            return
        }
        dismiss()
    }
}
