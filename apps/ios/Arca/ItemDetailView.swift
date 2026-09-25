// One item, of whatever kind. Metadata came with the list; the payload is
// fetched on demand and lives in `@State` only while this sheet is on screen.
//
// Every kind renders its OWN fields. A single "value" row reused across kinds
// would be less code and worse: a Wi-Fi entry has an SSID and a security mode,
// an SSH key has a fingerprint you check by eye, and a note is a paragraph. The
// point of ABI v7 was to stop pretending everything is a login.

import SwiftUI

struct ItemDetailView: View {
    let item: VaultItemMeta

    @Environment(VaultStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    @State private var detail: VaultItemDetail?
    @State private var revealed = false
    @State private var busy = false
    @State private var copiedNote: String?
    @State private var history: [VaultPasswordHistory] = []
    @State private var restoring: VaultPasswordHistory?

    var body: some View {
        NavigationStack {
            List {
                if let detail {
                    content(for: detail)
                } else {
                    Section { ProgressView().frame(maxWidth: .infinity) }
                }

                if item.hasTotp { TotpSection(item: item) }
                if item.kind == .login || item.kind == .wifi {
                    Section {
                        if history.isEmpty {
                            Text("No previous passwords yet.").foregroundStyle(.secondary)
                        }
                        ForEach(history) { entry in
                            VStack(alignment: .leading, spacing: 8) {
                                Text("Replaced \(Date(timeIntervalSince1970: Double(entry.replacedAt) / 1000).formatted())")
                                    .font(.caption).foregroundStyle(.secondary)
                                HStack {
                                    Button("Copy") {
                                        busy = true
                                        Task {
                                            if await store.copyHistoryPassword(for: item, revision: entry.id) {
                                                copiedNote = "Previous password copied."
                                            }
                                            busy = false
                                        }
                                    }.buttonStyle(.borderless)
                                    Spacer()
                                    Button("Restore…") { restoring = entry }.buttonStyle(.borderless)
                                }
                            }.disabled(busy)
                        }
                    } header: { Text("Password history") }
                    footer: { Text("Keeps the last 20 password changes made after updating Arca. Restoring changes only Arca, not the website or network.") }
                }

                if let copiedNote {
                    Section {
                        Label(copiedNote, systemImage: "clock")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
                if let failure = store.failure {
                    Section {
                        Text(failure).font(.callout).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle(item.title.isEmpty ? item.kind.label : item.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) { Button("Done") { dismiss() } }
            }
        }
        .task {
            detail = await store.detail(for: item)
            if item.kind == .login || item.kind == .wifi {
                history = await store.passwordHistory(for: item)
            }
        }
        .confirmationDialog("Restore this saved password? Your current password will be kept in history.", isPresented: Binding(
            get: { restoring != nil }, set: { if !$0 { restoring = nil } }
        ), titleVisibility: .visible) {
            if let entry = restoring {
                Button("Restore saved password") {
                    busy = true
                    Task {
                        if await store.restoreHistoryPassword(for: item, revision: entry.id) {
                            revealed = false
                            detail = await store.detail(for: item)
                            history = await store.passwordHistory(for: item)
                            copiedNote = "Previous password restored in Arca."
                        }
                        busy = false
                        restoring = nil
                    }
                }
            }
            Button("Cancel", role: .cancel) { restoring = nil }
        }
        // The payload leaves memory with the sheet. Nothing here is cached for
        // "next time" — the FFI hands out one secret at a time by design.
        .onDisappear { detail = nil; revealed = false }
    }

    @ViewBuilder
    private func content(for detail: VaultItemDetail) -> some View {
        switch detail {
        case let .login(_, username, password, url, _, notes):
            Section {
                row("Username", username, copyable: true)
                if !url.isEmpty { row("Site", url) }
            }
            secretSection("Password", value: password)
            notesSection(notes)

        case let .passkey(_, rpID, userName):
            Section {
                row("Site", rpID)
                row("Account", userName, copyable: true)
            }
            Section {
                Label(
                    "Passkeys sign in through the site's own prompt. There is nothing to copy.",
                    systemImage: "info.circle")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

        case let .sshKey(_, comment, keyType, publicKey, fingerprint):
            Section {
                row("Type", keyType)
                if !comment.isEmpty { row("Comment", comment) }
                row("Fingerprint", fingerprint, mono: true)
            }
            Section("Public key") {
                Text(publicKey)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                Button("Copy public key", systemImage: "doc.on.doc") {
                    copy(publicKey, note: "Public key copied.")
                }
            }
            Section {
                // Said plainly rather than left as an absence, so nobody hunts
                // for a reveal button that was never going to be there.
                Label(
                    "The private key stays on your computer. A phone has no ssh-agent to use it with.",
                    systemImage: "lock.laptopcomputer")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

        case let .wifi(_, ssid, password, security, hidden, notes):
            Section {
                row("Network", ssid, copyable: true)
                row("Security", security)
                if hidden { row("Hidden", "Yes") }
            }
            secretSection("Password", value: password)
            notesSection(notes)

        case let .secureNote(_, body):
            Section {
                Text(body)
                    .font(.body)
                    .textSelection(.enabled)
                    .privacySensitive()
                Button("Copy note", systemImage: "doc.on.doc") {
                    copy(body, note: "Note copied.")
                }
            }
        }
    }

    // MARK: - pieces

    @ViewBuilder
    private func row(_ label: String, _ value: String, copyable: Bool = false, mono: Bool = false)
        -> some View
    {
        LabeledContent(label) {
            Text(value.isEmpty ? "—" : value)
                .font(mono ? .caption.monospaced() : .body)
                .textSelection(.enabled)
        }
        .contextMenu(menuItems: {
            if copyable, !value.isEmpty {
                Button("Copy", systemImage: "doc.on.doc") { copy(value, note: "\(label) copied.") }
            }
        })
    }

    @ViewBuilder
    private func secretSection(_ label: String, value: String) -> some View {
        Section(label) {
            Text(revealed ? value : "••••••••••••")
                .font(.body.monospaced())
                .textSelection(.enabled)
                // Honoured wherever SwiftUI applies privacy redaction. The
                // app-switcher snapshot is covered separately, in ArcaApp.
                .privacySensitive()
            Button(
                revealed ? "Hide" : "Reveal",
                systemImage: revealed ? "eye.slash" : "eye"
            ) { revealed.toggle() }
            Button("Copy \(label.lowercased())", systemImage: "doc.on.doc") {
                copy(value, note: "Copied. iOS clears the pasteboard in \(Int(SecretPasteboard.lifetime)) seconds.")
            }
        }
        .disabled(busy)
    }

    @ViewBuilder
    private func notesSection(_ notes: String) -> some View {
        if !notes.isEmpty {
            Section("Notes") {
                Text(notes).font(.callout).textSelection(.enabled).privacySensitive()
            }
        }
    }

    private func copy(_ value: String, note: String) {
        guard !value.isEmpty else { return }
        SecretPasteboard.copy(value)
        copiedNote = note
    }
}

/// The live TOTP code, refreshed every second so the countdown is honest.
///
/// Its own view so the timer redraws six digits and a bar rather than the whole
/// sheet — including the secret rows, which would flicker once a second.
private struct TotpSection: View {
    let item: VaultItemMeta
    @Environment(VaultStore.self) private var store
    @Environment(TotpActivityController.self) private var island

    @State private var totp: VaultTotp?
    @State private var copied = false
    /// One attempt per appearance. `start` records why it failed, so retrying
    /// every second would only rewrite the same sentence sixty times a minute.
    @State private var triedIsland = false

    var body: some View {
        Section("Verification code") {
            if let totp {
                HStack {
                    Text(spaced(totp.code))
                        .font(.title2.monospaced().weight(.semibold))
                        .textSelection(.enabled)
                        .privacySensitive()
                    Spacer()
                    // Seconds, not a spinner: you need to know whether to use
                    // this code or wait two seconds for the next one.
                    Text("\(totp.remaining)s")
                        .font(.footnote.monospacedDigit())
                        .foregroundStyle(totp.remaining <= 5 ? .orange : .secondary)
                }
                ProgressView(value: Double(totp.remaining), total: Double(max(totp.period, 1)))
                    .tint(totp.remaining <= 5 ? .orange : .accentColor)
                Button("Copy code", systemImage: "doc.on.doc") {
                    SecretPasteboard.copy(totp.code)
                    copied = true
                }
                // Off, not on: it starts by itself the moment this section
                // appears (see `.task`), because needing a tap first defeats
                // the purpose — you press it, leave for the app you are
                // signing in to, and that is when it becomes visible.
                if island.isAvailable, island.showingItemID == item.id {
                    Button("Keep off the Dynamic Island", systemImage: "xmark.circle") {
                        island.stop()
                    }
                }
                if copied {
                    Text("Copied.").font(.footnote).foregroundStyle(.secondary)
                }
                // Said, not logged. "Nothing happens" is the one failure the
                // user cannot act on.
                if let failure = island.lastFailure {
                    Label(failure, systemImage: "exclamationmark.circle")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            } else {
                ProgressView()
            }
        }
        .task {
            // Re-derived rather than counted down locally: a code that keeps
            // ticking while the app was backgrounded would be confidently wrong.
            while !Task.isCancelled {
                let next = await store.totp(for: item)
                if let next {
                    if island.showingItemID == item.id {
                        // Push the new code only when it actually rotated,
                        // rather than once a second: an update is a system
                        // call, and 29 out of 30 would say nothing new.
                        if next.code != totp?.code {
                            await island.refresh(code: next)
                        }
                    } else if !triedIsland {
                        // Automatic, on opening the item. Opening a code you
                        // are about to type somewhere else IS the request; a
                        // separate button to say so again only means the
                        // people who need it most never find it.
                        //
                        // Attempted even when unavailable, so `start` can say
                        // why rather than the caller deciding to stay quiet.
                        triedIsland = true
                        island.start(
                            item: item,
                            code: next,
                            label: item.subtitle.isEmpty ? item.title : item.subtitle)
                    }
                }
                totp = next
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    /// "123456" reads as one number; "123 456" reads as two halves you can type.
    private func spaced(_ code: String) -> String {
        guard code.count == 6 else { return code }
        let mid = code.index(code.startIndex, offsetBy: 3)
        return "\(code[..<mid]) \(code[mid...])"
    }
}
