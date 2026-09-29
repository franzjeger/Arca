import SwiftUI

/// Find & merge duplicate logins, after looking at them.
///
/// Nothing is merged until someone has seen what would be: each group shows
/// its logins and which one is kept, and any of them can be kept instead.
/// Logins for one site and username are turned on; the same username on
/// related sites (accounts.google.com and google.com) is only offered. The
/// merge applies only if every login shown is unchanged since.
struct DuplicatesView: View {
    /// A group and what was chosen for it, in one value so that neither is
    /// ever drawn without the other.
    private struct Choice: Identifiable {
        let id: Int
        let group: DuplicateGroup
        var merge: Bool
        var keep: String
    }

    @Environment(VaultStore.self) private var store
    @Environment(\.dismiss) private var dismiss
    @State private var choices: [Choice] = []
    @State private var loaded = false
    @State private var error: String?
    @State private var busy = false
    @State private var merged: Int?

    private var chosen: Int { choices.filter(\.merge).count }
    private var reviewing: Bool { merged == nil && !choices.isEmpty }

    var body: some View {
        NavigationStack {
            Group {
                if let merged {
                    ContentUnavailableView {
                        Label(
                            merged == 1 ? "Merged 1 login" : "Merged \(merged) logins",
                            systemImage: "checkmark.circle")
                    } description: {
                        Text("They are in the Trash, which Arca on a computer can restore, and their passwords are in the history of the logins kept.")
                    }
                } else if !loaded {
                    ProgressView()
                } else if choices.isEmpty, error == nil {
                    ContentUnavailableView(
                        "No duplicates", systemImage: "checkmark.circle",
                        description: Text("No login is saved more than once."))
                } else {
                    review
                }
            }
            .navigationTitle("Duplicate logins")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    if reviewing {
                        Button("Cancel") { dismiss() }
                            .disabled(busy)
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    if reviewing {
                        Button(chosen > 1 ? "Merge \(chosen)" : "Merge") {
                            Task { await merge() }
                        }
                        .disabled(busy || chosen == 0)
                    } else {
                        Button("Done") { dismiss() }
                    }
                }
            }
            .interactiveDismissDisabled(busy)
            .task { await look() }
        }
    }

    private var review: some View {
        List {
            if let error {
                Section {
                    Label(error, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                    Button("Look again") { Task { await look() } }
                }
            }
            Section {
                Text("Logins saved more than once. The one you keep stays as it is; the others go to the Trash, and their passwords into its password history.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            ForEach($choices) { $choice in
                section($choice)
            }
        }
        .disabled(busy)
    }

    private func section(_ choice: Binding<Choice>) -> some View {
        let group = choice.wrappedValue.group
        let keep = choice.wrappedValue.keep
        let kept = group.logins.first { $0.id == keep }
        let name = kept.map { $0.title.isEmpty ? $0.site : $0.title } ?? "These logins"
        return Section {
            Toggle("Merge \(group.logins.count) logins", isOn: choice.merge)
            ForEach(group.logins) { login in
                Button {
                    choice.wrappedValue.keep = login.id
                } label: {
                    row(login, kept: login.id == keep, differs: kept.map {
                        login.hasPassword && $0.password != login.password
                    } ?? false)
                }
                .foregroundStyle(.primary)
                .accessibilityAddTraits(login.id == keep ? .isSelected : [])
                .accessibilityHint("Keeps this login and merges the others into it")
            }
        } header: {
            Text(group.possible ? "Possibly one account: \(name)" : name)
        } footer: {
            if group.possible {
                Text("The same username on related sites. Turn this on only if they are one account.")
            }
        }
    }

    private func row(_ login: DuplicateLogin, kept: Bool, differs: Bool) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: kept ? "checkmark.circle.fill" : "circle")
                .foregroundStyle(kept ? Color.accentColor : .secondary)
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(login.title.isEmpty ? login.site : login.title)
                    if kept {
                        Text("Kept").font(.caption).foregroundStyle(Color.accentColor)
                    }
                }
                Text([login.site, login.username].filter { !$0.isEmpty }.joined(separator: " · "))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                HStack(spacing: 6) {
                    Text("Edited \(Self.edited(login.modifiedAt))")
                    if !login.hasPassword { Text("No password") }
                    if differs { Text("Different password").foregroundStyle(.orange) }
                    if login.hasTotp { Text("TOTP") }
                    if login.hasNotes { Text("Notes") }
                }
                .font(.caption2)
                .foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
    }

    private func look() async {
        error = nil
        do {
            let found = try await store.findDuplicates()
            choices = found.enumerated().map { index, group in
                Choice(id: index, group: group, merge: !group.possible, keep: group.keep)
            }
        } catch {
            self.error = Self.message(error, fallback: "Couldn't look for duplicates.")
        }
        loaded = true
    }

    private func merge() async {
        busy = true
        defer { busy = false }
        error = nil
        let chosen = choices.filter(\.merge).map { choice in
            DuplicateChoice(keep: choice.keep, ids: choice.group.logins.map(\.id))
        }
        do {
            merged = try await store.mergeDuplicates(
                chosen, shown: choices.flatMap(\.group.logins))
        } catch {
            self.error = Self.message(error, fallback: "Couldn't merge those logins.")
        }
    }

    private static func message(_ error: Error, fallback: String) -> String {
        (error as? LocalizedError)?.errorDescription ?? fallback
    }

    /// "12 Sep 2026". By the device's own clock, so only for reading.
    private static func edited(_ unixMillis: Int64) -> String {
        Date(timeIntervalSince1970: Double(unixMillis) / 1000)
            .formatted(date: .abbreviated, time: .omitted)
    }
}
