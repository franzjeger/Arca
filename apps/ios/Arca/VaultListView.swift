// The unlocked vault: search, pick, look at one item.
//
// EVERY kind, since ABI v7. For six ABI versions this list called
// `vault_ffi_identities`, which filters to logins — so passkeys, SSH keys,
// Wi-Fi networks and secure notes were not hidden here, they were unaskable.
// A phone showed a fifth of the vault and gave no sign the rest existed.
//
// `vault_ffi_identities` still exists and still filters, because it feeds the
// AutoFill credential store, where a Wi-Fi password would be nonsense.

import SwiftUI

struct VaultListView: View {
    @Environment(VaultStore.self) private var store
    @State private var selected: VaultItemMeta?
    @State private var editing: VaultItemMeta?
    @State private var creating: VaultCreateKind?
    @State private var generatingPassword = false
    @State private var showingDevices = false
    /// Asking for a master password changed on another device: once when sync
    /// finds the change, then from the banner after "Not now".
    @State private var askingNewPassword = false
    @State private var newPassword = ""
    @State private var newPasswordError: String?

    var body: some View {
        @Bindable var store = store

        NavigationStack {
            Group {
                if store.items.isEmpty {
                    ContentUnavailableView {
                        Label("Empty vault", systemImage: "tray")
                    } description: {
                        Text("Nothing in this vault yet.")
                    } actions: {
                        Button("Add a login") { creating = .login }
                    }
                } else if store.results.isEmpty, !store.query.isEmpty {
                    ContentUnavailableView.search(text: store.query)
                } else if store.results.isEmpty {
                    // An empty CATEGORY, not an empty vault. Said in the
                    // category's own words so it is obvious the filter is
                    // working rather than the data missing.
                    ContentUnavailableView {
                        Label(store.category.label, systemImage: store.category.symbol)
                    } description: {
                        Text(store.category.emptyMessage)
                    }
                } else {
                    List {
                        ForEach(store.sections, id: \.letter) { section in
                            Section(section.letter) {
                                ForEach(section.items) { item in
                                    Button { selected = item } label: { row(item) }
                                        .buttonStyle(.plain)
                                        .swipeActions(edge: .trailing) {
                                            Button("Delete", systemImage: "trash", role: .destructive) {
                                                Task { await store.deleteItem(item) }
                                            }
                                            // Only logins have an editor. Offering
                                            // Edit on a Wi-Fi entry and then showing
                                            // a login form is worse than not
                                            // offering it.
                                            if item.kind == .login {
                                                Button("Edit", systemImage: "pencil") { editing = item }
                                                    .tint(.accentColor)
                                            }
                                        }
                                }
                            }
                        }
                    }
                    .listStyle(.plain)
                    // The index bar is the whole point of sectioning: six
                    // hundred rows are reachable in one drag instead of thirty
                    // flicks. Hidden while searching, where the result set is
                    // short and the letters would be a column of stubs.
                    .modifier(SectionIndex(enabled: store.query.isEmpty))
                }
            }
            .navigationTitle(store.category.shortLabel)
            .searchable(text: $store.query, prompt: "Search the vault")
            .toolbar {
                // In the title position rather than buried in the "..." menu:
                // the category IS what the screen is showing, so it belongs
                // where the screen says what it is.
                ToolbarItem(placement: .principal) {
                    Menu {
                        Picker("Category", selection: $store.category) {
                            ForEach(VaultCategory.allCases) { cat in
                                Label(
                                    "\(cat.label)  (\(store.count(of: cat)))",
                                    systemImage: cat.symbol
                                ).tag(cat)
                            }
                        }
                    } label: {
                        HStack(spacing: 4) {
                            Text(store.category.shortLabel).font(.headline)
                            Image(systemName: "chevron.down").font(.caption2)
                        }
                        .foregroundStyle(.primary)
                    }
                    .accessibilityLabel("Category: \(store.category.label)")
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Lock", systemImage: "lock") { store.lock() }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Menu("Add", systemImage: "plus") {
                        Button("Login", systemImage: "key.fill") { creating = .login }
                        Button("Wi-Fi", systemImage: "wifi") { creating = .wifi }
                        Button("Note", systemImage: "note.text") { creating = .note }
                    }
                }
                ToolbarItem(placement: .topBarLeading) {
                    Menu("Options", systemImage: "ellipsis.circle") {
                        Text("Arca \(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?") (\(Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"))")
                        Divider()
                        if store.syncConnected {
                            Button("Sync now", systemImage: "arrow.triangle.2.circlepath") {
                                Task { await store.runSync() }
                            }
                            .disabled(store.syncing)
                            Button("Synced devices", systemImage: "laptopcomputer.and.iphone") {
                                showingDevices = true
                            }
                            Button("Stop syncing", systemImage: "icloud.slash", role: .destructive) {
                                Task { await store.disconnectSync() }
                            }
                        } else {
                            Button("Sync with Google Drive", systemImage: "icloud") {
                                Task { await store.connectSync() }
                            }
                            .disabled(store.syncing)
                        }
                        Divider()
                        Menu("Auto-lock", systemImage: "timer") {
                            Picker("Auto-lock", selection: Binding(
                                get: { store.lockAfter },
                                set: { store.lockAfter = $0 })
                            ) {
                                ForEach(AutoLockDelay.allCases) { delay in
                                    Text(delay.label).tag(delay)
                                }
                            }
                        }
                        Divider()
                        // Also reachable from the password field when editing,
                        // but that is no help when the account is being created
                        // in Safari and there is nothing to edit yet.
                        Button("Generate a password", systemImage: "wand.and.sparkles") {
                            generatingPassword = true
                        }
                        Divider()
                        if store.quickUnlockEnabled {
                            Button("Turn off quick unlock", systemImage: "faceid") {
                                Task { await store.disableQuickUnlock() }
                            }
                        } else {
                            Button("Unlock with Face ID next time", systemImage: "faceid") {
                                Task { await store.enableQuickUnlock() }
                            }
                        }
                    }
                }
            }
            .sheet(item: $selected) { ItemDetailView(item: $0) }
            // One sheet per destination; the item's kind picks the editor. A
            // wrong pairing here is what the "Edit" swipe used to guard against
            // by not existing for these kinds at all.
            .sheet(item: $editing) { item in
                switch item.kind {
                case .wifi: WifiEditView(existing: item)
                case .secureNote: NoteEditView(existing: item)
                default: LoginEditView(existing: item)
                }
            }
            .sheet(item: $creating) { kind in
                switch kind {
                case .login: LoginEditView(existing: nil)
                case .wifi: WifiEditView(existing: nil)
                case .note: NoteEditView(existing: nil)
                }
            }
            // No `onUse`: opened on its own there is no field to fill, so
            // Copy is the only thing that would make sense.
            .sheet(isPresented: $generatingPassword) { PasswordGeneratorView() }
            .sheet(isPresented: $showingDevices) { SyncDevicesView() }
            .onChange(of: store.needsNewPassword, initial: true) { _, needed in
                askingNewPassword = needed
            }
            .alert("Master password changed", isPresented: $askingNewPassword) {
                SecureField("New master password", text: $newPassword)
                Button("Continue") { Task { await adoptNewPassword() } }
                Button("Not now", role: .cancel) {
                    newPassword = ""
                    newPasswordError = nil
                }
            } message: {
                Text(newPasswordError
                    ?? "It was changed on another device. Enter the new one to keep this iPhone in sync.")
            }
            // Only after an unlock has actually asked the store — `nil` means
            // we don't know yet, and guessing would nag people who are set up.
            .safeAreaInset(edge: .bottom) {
                VStack(spacing: 0) {
                    // A menu action that fails leaves no trace otherwise: the
                    // sheet is gone and the toggle simply did not move.
                    if store.syncing {
                        Banner(text: "Syncing with Google Drive…", bad: false)
                    }
                    if let failure = store.failure { Banner(text: failure, bad: true) }
                    if store.needsNewPassword, !askingNewPassword {
                        Button { askingNewPassword = true } label: {
                            Banner(text: "Master password changed on another device. Tap to enter it.", bad: true)
                        }
                        .buttonStyle(.plain)
                    }
                    // Nothing is lost by the time this shows: the cycle that
                    // noticed put the changes back. It stays until dismissed,
                    // because a second time is worth a look at who else can
                    // get into the Google account.
                    if !store.driveLostChanges.isEmpty {
                        Button { Task { await store.acknowledgeLostChanges() } } label: {
                            Banner(text: """
                                Google Drive had lost the latest changes from \
                                \(Self.listed(store.driveLostChanges)). Arca has put them \
                                back. If this happens again, someone else may have access \
                                to your Google account. Tap to dismiss.
                                """, bad: true)
                        }
                        .buttonStyle(.plain)
                    }
                    if store.autoFillEnabled == false { AutoFillHint() }
                    // The toggle also lives in the Options menu, but that menu
                    // is a "..." in the top-LEFT corner above a full-screen
                    // list, and the first person to use this on a phone simply
                    // never found it. Offer it where the eye already is.
                    if !store.quickUnlockEnabled {
                        QuickUnlockOffer { Task { await store.enableQuickUnlock() } }
                    }
                }
            }
        }
    }

    /// The alert closes on its own when a button is pressed, so a wrong
    /// password reopens it with the reason.
    private func adoptNewPassword() async {
        let password = newPassword
        newPassword = ""
        newPasswordError = await store.adoptNewPassword(password)
        if newPasswordError != nil { askingNewPassword = true }
    }

    /// "A", "A and B", "A, B and C".
    private static func listed(_ names: [String]) -> String {
        guard let last = names.last else { return "" }
        guard names.count > 1 else { return last }
        return names.dropLast().joined(separator: ", ") + " and " + last
    }

    private func row(_ item: VaultItemMeta) -> some View {
        HStack(spacing: 12) {
            // The icon is the kind. Five types in one list are unreadable
            // otherwise — you cannot tell an SSH key from a note by its name.
            Image(systemName: item.kind.symbol)
                .font(.title3)
                .foregroundStyle(.tint)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(Self.title(for: item))
                Text(item.subtitle.isEmpty ? item.kind.label : item.subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if item.hasTotp {
                Image(systemName: "clock.badge.checkmark")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Image(systemName: "chevron.right")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .contentShape(Rectangle())
    }

    /// Title first, then whatever the kind puts in the subtitle — an item saved
    /// without a title shouldn't render as a blank row.
    static func title(for item: VaultItemMeta) -> String {
        [item.title, item.subtitle].first { !$0.isEmpty } ?? item.kind.label
    }
}

/// Shown when the identity store refused the publish because AutoFill is off.
/// No button: iOS has no public deep link to the AutoFill settings pane, and a
/// button that opened the wrong page would be worse than saying where to go.
private struct AutoFillHint: View {
    var body: some View {
        Banner(
            text: "Turn Arca on in Settings ▸ General ▸ AutoFill & Passwords to fill from the keyboard.",
            bad: false)
    }
}

/// An offer, not a warning: quick unlock is optional, and someone who has
/// decided against it should not be shown an orange triangle forever. It
/// disappears the moment it is accepted, because `quickUnlockEnabled` flips.
private struct QuickUnlockOffer: View {
    let enable: () -> Void

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: "faceid").foregroundStyle(.tint)
            Text("Unlock with Face ID instead of typing your master password.")
                .font(.footnote)
                .foregroundStyle(.secondary)
            Spacer(minLength: 0)
            Button("Turn on", action: enable)
                .font(.footnote.weight(.semibold))
                .buttonStyle(.borderless)
        }
        .padding(12)
        .frame(maxWidth: .infinity)
        .background(.thinMaterial)
    }
}

/// Every device that syncs this vault and when it last did. Drive can hold a
/// device's changes back without anything failing; this is where that shows,
/// as a laptop that "synced 3 days ago" when it was used this morning.
private struct SyncDevicesView: View {
    @Environment(VaultStore.self) private var store
    @Environment(\.dismiss) private var dismiss
    @State private var devices: [SyncedDevice]?

    var body: some View {
        NavigationStack {
            Group {
                if let devices, devices.isEmpty {
                    ContentUnavailableView(
                        "No devices yet", systemImage: "laptopcomputer.and.iphone",
                        description: Text("A device shows here once it has synced this vault."))
                } else if let devices {
                    List(devices) { entry in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(entry.isThisDevice ? "\(entry.device.name) (this device)" : entry.device.name)
                            Text("Synced \(Self.when(entry.device.lastUpload))")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .accessibilityElement(children: .combine)
                    }
                } else {
                    ProgressView()
                }
            }
            .navigationTitle("Synced devices")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .task { devices = await store.syncDevices() }
        }
    }

    /// "5 minutes ago", "yesterday". By the device's own clock, so only for
    /// reading.
    private static func when(_ unixMillis: Int64) -> String {
        Date(timeIntervalSince1970: Double(unixMillis) / 1000)
            .formatted(.relative(presentation: .named))
    }
}

private struct Banner: View {
    let text: String
    let bad: Bool

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: bad ? "exclamationmark.circle" : "exclamationmark.triangle")
                .foregroundStyle(bad ? .red : .orange)
            Text(text)
                .font(.footnote)
                .foregroundStyle(.secondary)
            Spacer(minLength: 0)
        }
        .padding(12)
        .frame(maxWidth: .infinity)
        .background(.thinMaterial)
    }
}


/// `.listSectionIndex` where the OS has it, nothing where it does not.
///
/// Its own modifier so the availability check sits in one place instead of
/// splitting the whole list body into two nearly identical branches.
private struct SectionIndex: ViewModifier {
    let enabled: Bool

    func body(content: Content) -> some View {
        if #available(iOS 26.0, *) {
            content.listSectionIndexVisibility(enabled ? .visible : .hidden)
        } else {
            content
        }
    }
}


/// What the "+" menu can create. Identifiable so it can drive a sheet.
enum VaultCreateKind: String, Identifiable {
    case login, wifi, note
    var id: String { rawValue }
}
