// The app's whole state: shut, opening, or open.
//
// There is no half-open state on purpose — a failed unlock leaves no handle
// behind, and `session` is the only thing that distinguishes locked from
// unlocked. Dropping it frees the Rust handle, which locks and zeroizes the
// vault, so `lock()` is one assignment rather than a teardown sequence.
//
// Nothing here caches a password. The store holds a handle and fetches one
// secret at a time through it, which is the point of the FFI's shape.

import Foundation
import Observation
import os

private let log = Logger(subsystem: "no.sybr.vault.ios", category: "store")

@MainActor
@Observable
final class VaultStore {

    enum Phase: Equatable {
        /// Nothing in the shared container to open — import one first.
        case needsVault
        case locked
        case unlocking
        case unlocked
    }

    private(set) var phase: Phase = .locked
    /// Everything in the vault, of every kind — what the list shows.
    private(set) var items: [VaultItemMeta] = []
    /// Stored passkeys' metadata, held only to republish to the credential
    /// store. Never a private key — that stays behind the Rust handle.
    private var passkeyIdentities: [VaultSession.VaultPasskeyIdentity] = []
    /// Logins only, and only for the AutoFill credential store.
    ///
    /// Two calls rather than deriving one from the other, on purpose: the
    /// credential store needs the login's HOST, and `host_of` lives in Rust
    /// precisely because a second implementation of it drifted once already.
    /// Both are cheap metadata reads.
    private(set) var identities: [VaultIdentity] = []
    /// The last failure, already phrased for a person.
    private(set) var failure: String?
    /// Whether AutoFill is switched on for Arca in Settings. `nil` until an
    /// unlock has actually asked, so the UI can stay quiet rather than guess.
    private(set) var autoFillEnabled: Bool?
    /// Whether the OPEN vault carries a device wrapping. Only meaningful while
    /// unlocked; `quickUnlockAvailable` is the question to ask before that.
    private(set) var quickUnlockEnabled = false
    var query = ""
    /// Which slice of the vault the list is showing.
    var category: VaultCategory = .all

    /// Whether a quick-unlock key is stored on this device.
    ///
    /// Cached, not computed. It used to call straight into the keychain, and it
    /// is read from inside `UnlockView.body` — so on a device, where every probe
    /// is a synchronous XPC to securityd that also has to consult a biometric
    /// access control, it ran again on every keystroke in the password field.
    /// Three things change the answer, and all three refresh it themselves.
    private(set) var quickUnlockAvailable = false

    /// Held only while unlocked.
    private var session: VaultSession?
    private var lifetime = SessionLifetime()
    /// The sync engine, alive for as long as the session it wraps.
    private var sync: VaultSync?
    /// Last known sync state, for the UI. `nil` until asked.
    private(set) var syncStatus: SyncStatus?
    private(set) var syncing = false

    nonisolated init() {}

    /// Items matching the current search AND category, in a stable order.
    var results: [VaultItemMeta] {
        let inCategory = items.filter(category.contains)
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return inCategory }
        return inCategory.filter {
            $0.title.lowercased().contains(needle)
                || $0.subtitle.lowercased().contains(needle)
                || $0.url.lowercased().contains(needle)
                || $0.kind.label.lowercased().contains(needle)
        }
    }

    /// How many items a category holds, ignoring the search.
    ///
    /// Shown next to each category so the ones that are empty say so before you
    /// tap them. In a vault of six hundred logins, six passkeys are otherwise
    /// indistinguishable from none.
    func count(of category: VaultCategory) -> Int {
        items.reduce(into: 0) { $0 += category.contains($1) ? 1 : 0 }
    }

    /// `results` cut into alphabetical sections, with the index letters.
    ///
    /// A phone cannot show six hundred rows usefully as one strip. Sections give
    /// the list an index bar, which is the difference between scrolling to "S"
    /// and scrolling past everything before it.
    var sections: [(letter: String, items: [VaultItemMeta])] {
        Dictionary(grouping: results, by: Self.indexLetter)
            .sorted { lhs, rhs in
                // "#" last: a bucket of numbers and symbols at the top pushes
                // the alphabet down and is never what anyone is looking for.
                if (lhs.key == "#") != (rhs.key == "#") { return rhs.key == "#" }
                return lhs.key < rhs.key
            }
            .map { (letter: $0.key, items: $0.value) }
    }

    /// The section an item belongs in — its first letter, or "#".
    private static func indexLetter(for item: VaultItemMeta) -> String {
        let name = VaultListView.title(for: item)
        guard let first = name.first(where: { !$0.isWhitespace }) else { return "#" }
        // Folded so "Ørsted" files under Ø rather than by its underlying scalar,
        // and "élan" under E. Norwegian vaults are full of both.
        let folded = String(first).folding(
            options: [.diacriticInsensitive, .caseInsensitive], locale: .current)
        guard let letter = folded.first, letter.isLetter else { return "#" }
        return String(letter).uppercased()
    }

    /// The full payload of one item. SECRET — hold it no longer than the sheet.
    func detail(for item: VaultItemMeta) async -> VaultItemDetail? {
        guard let session else { return nil }
        do {
            let detail = try await session.detail(forID: item.id)
            guard self.session === session else { return nil }
            return detail
        } catch {
            guard self.session === session else { return nil }
            log.error("detail fetch failed: \(vaultLogMessage(for: error), privacy: .public)")
            failure = Self.message(error, fallback: "Couldn't read that item.")
            return nil
        }
    }

    /// The live TOTP code, or nil when the item has none.
    func totp(for item: VaultItemMeta) async -> VaultTotp? {
        guard let session, item.hasTotp else { return nil }
        let code = try? await session.totp(forID: item.id)
        return self.session === session ? code : nil
    }

    /// Re-check whether there is a vault to open. Cheap; call it on appear.
    func refresh() {
        guard phase != .unlocked, phase != .unlocking else { return }
        phase = VaultFile.exists ? .locked : .needsVault
        refreshQuickUnlockAvailability()
    }

    /// Resolve whether a device key is stored, and publish it.
    ///
    /// Off the main actor because it is a blocking XPC round-trip: cheap in the
    /// simulator, not on a phone. `await` it before *deciding* anything — the
    /// cached property is for drawing, and it is false until the first probe
    /// lands. Reading it too early is what briefly turned the automatic Face ID
    /// attempt into a button nobody asked for.
    @discardableResult
    func resolveQuickUnlockAvailability() async -> Bool {
        let stored = await Task.detached(priority: .userInitiated) {
            VaultSession.hasStoredDeviceKey
        }.value
        quickUnlockAvailable = stored
        return stored
    }

    /// Fire-and-forget refresh, for the places that only need the UI to catch up.
    private func refreshQuickUnlockAvailability() {
        Task { await resolveQuickUnlockAvailability() }
    }

    func unlock(password: String) async {
        // Argon2id with the vault header's parameters — hundreds of
        // milliseconds, off the main actor inside VaultSession.
        await open(fallback: "Couldn't unlock the vault.") {
            try await VaultSession.openWithMasterPassword(password)
        }
    }

    /// Unlock with the stored device key, behind Face ID / Touch ID.
    func unlockWithDeviceKey() async {
        await open(fallback: "Couldn't unlock with Face ID.") {
            try await VaultSession.openWithDeviceKey(reason: "unlock your Arca vault")
        }
    }

    /// The two unlock paths differ only in how the handle is obtained.
    private func open(
        fallback: String,
        _ makeSession: @Sendable () async throws -> VaultSession
    ) async {
        guard phase != .unlocking, phase != .unlocked, let token = lifetime.begin() else { return }
        phase = .unlocking
        failure = nil
        do {
            let session = try await makeSession()
            guard lifetime.accepts(token) else { return }
            self.session = session
            try await load(session)
            let quickUnlock = await session.hasDeviceUnlock()
            guard lifetime.accepts(token) else { return }
            quickUnlockEnabled = quickUnlock
            phase = .unlocked
            // After the phase flip on purpose: this is what puts Arca in the
            // QuickType bar, and it is metadata only, so nobody should be made
            // to wait behind it to see their own vault.
            let enabled = await CredentialIdentities.replace(
                with: self.identities, passkeys: passkeyIdentities)
            guard lifetime.accepts(token) else { return }
            autoFillEnabled = enabled
            // Sync last: it is network-bound and nobody should wait behind it to
            // see their own vault.
            await startSync(session)
        } catch {
            guard lifetime.accepts(token) else { return }
            lock()
            log.error("unlock failed: \(vaultLogMessage(for: error), privacy: .public)")
            failure = Self.cancelled(error) ? nil : Self.message(error, fallback: fallback)
            phase = VaultFile.exists ? .locked : .needsVault
        }
    }

    /// Read both lists and sort them the one way the whole app agrees on.
    ///
    /// One function so a save cannot reshuffle the list under the user by
    /// sorting differently from the unlock that drew it.
    private func load(_ session: VaultSession) async throws {
        let items = try await session.items()
        let identities = try await session.identities()
        let passkeys = try await session.passkeyIdentities()
        guard self.session === session else { throw CancellationError() }
        passkeyIdentities = passkeys
        // Kind first, then title: a vault with logins, keys and notes mixed by
        // name is a list you have to read rather than scan.
        self.items = items.sorted {
            ($0.kind.label, $0.title.lowercased(), $0.subtitle.lowercased())
                < ($1.kind.label, $1.title.lowercased(), $1.subtitle.lowercased())
        }
        self.identities = identities.sorted {
            ($0.domain.lowercased(), $0.user.lowercased())
                < ($1.domain.lowercased(), $1.user.lowercased())
        }
    }

    /// Turn quick unlock on for this device. Needs an open vault: the key wraps
    /// the vault key, which only exists while unlocked.
    func enableQuickUnlock() async {
        guard let session else { return }
        do {
            try await session.enableDeviceUnlock()
            guard self.session === session else { return }
            quickUnlockEnabled = true
            refreshQuickUnlockAvailability()
            failure = nil
        } catch {
            guard self.session === session else { return }
            log.error("enable quick unlock failed: \(vaultLogMessage(for: error), privacy: .public)")
            failure = Self.cancelled(error) ? nil : Self.message(
                error, fallback: "Couldn't turn on quick unlock.")
        }
    }

    func disableQuickUnlock() async {
        guard let session else { return }
        do {
            try await session.disableDeviceUnlock()
            guard self.session === session else { return }
            quickUnlockEnabled = false
            refreshQuickUnlockAvailability()
            failure = nil
        } catch {
            guard self.session === session else { return }
            log.error("disable quick unlock failed: \(vaultLogMessage(for: error), privacy: .public)")
            failure = Self.message(error, fallback: "Couldn't turn off quick unlock.")
        }
    }

    // MARK: Auto-lock

    /// How long the vault may stay open while Arca is not in front.
    ///
    /// Defaults to locking at once, and stays there — see `AutoLockDelay`.
    /// This governs ONLY the app opened to browse: filling a password never
    /// touches it, because the AutoFill extension is a separate process that
    /// opens the vault itself. Someone doing a run of lookups can relax it;
    /// nobody has to, to use Arca normally.
    /// Stored, not computed over `UserDefaults`: `@Observable` tracks stored
    /// properties, so a computed one would leave the picker's checkmark on the
    /// old row until the menu was reopened — looking like the setting refused.
    var lockAfter: AutoLockDelay = AutoLockDelay(
        stored: UserDefaults.standard.string(forKey: VaultStore.lockAfterKey)
    ) {
        didSet { UserDefaults.standard.set(lockAfter.rawValue, forKey: Self.lockAfterKey) }
    }

    fileprivate static let lockAfterKey = "arca.autoLockDelay"

    /// When Arca last went to the background, if it is still there.
    private var leftAt: TimeInterval?

    /// Invalidate an unfinished unlock even when the normal grace period is on.
    func noteBackgrounded() {
        lifetime.background()
        if phase == .unlocking { lock(); return }
        guard phase == .unlocked else { return }
        leftAt = ProcessInfo.processInfo.systemUptime
        if lockAfter == .immediately { lock() }
    }

    func lockIfExpired() {
        lifetime.foreground()
        guard phase == .unlocked, let leftAt else { return }
        defer { self.leftAt = nil }
        guard let limit = lockAfter.seconds else { return }
        if ProcessInfo.processInfo.systemUptime - leftAt >= limit { lock() }
    }

    func lock() {
        lifetime.invalidate()
        syncing = false
        quickUnlockEnabled = false
        passkeyIdentities = []
        leftAt = nil
        // NOT clearing the credential identity store: it holds no secrets, and
        // it is what makes iOS offer Arca at all. The extension does its own
        // unlock when a suggestion is picked, so dropping the identities here
        // would make Arca invisible while protecting nothing.
        //
        // Frees the Rust handle on the vault queue, which re-seals and zeroizes.
        session = nil
        sync = nil
        syncStatus = nil
        items = []
        identities = []
        query = ""
        failure = nil
        phase = VaultFile.exists ? .locked : .needsVault
    }

    /// One password, fetched on demand and never stored here.
    func password(for item: VaultItemMeta) async -> String? {
        guard let session else { return nil }
        do {
            let password = try await session.password(forID: item.id)
            guard self.session === session else { return nil }
            return password
        } catch {
            guard self.session === session else { return nil }
            log.error("password fetch failed: \(vaultLogMessage(for: error), privacy: .public)")
            failure = Self.message(error, fallback: "Couldn't read that password.")
            return nil
        }
    }

    func passwordHistory(for item: VaultItemMeta) async -> [VaultPasswordHistory] {
        guard let session else { return [] }
        do {
            let entries = try await session.passwordHistory(forID: item.id)
            return self.session === session ? entries : []
        } catch {
            guard self.session === session else { return [] }
            failure = Self.message(error, fallback: "Couldn't read password history.")
            return []
        }
    }

    func copyHistoryPassword(for item: VaultItemMeta, revision: String) async -> Bool {
        guard let session else { return false }
        do {
            let password = try await session.historyPassword(forID: item.id, revision: revision)
            guard self.session === session else { return false }
            SecretPasteboard.copy(password)
            return true
        } catch {
            guard self.session === session else { return false }
            failure = Self.message(error, fallback: "Couldn't copy that password.")
            return false
        }
    }

    func restoreHistoryPassword(for item: VaultItemMeta, revision: String) async -> Bool {
        guard let session else { return false }
        do {
            try await session.restorePasswordHistory(forID: item.id, revision: revision)
            guard self.session === session else { return false }
            await didWrite(session)
            return self.session === session
        } catch {
            guard self.session === session else { return false }
            failure = Self.message(error, fallback: "Couldn't restore that password.")
            return false
        }
    }

    /// Create or update a login, then refresh the list and the AutoFill store.
    ///
    /// Returns nil on success, or a message to show in the editor. The error
    /// goes back to the caller instead of only into `failure` because the sheet
    /// stays open on failure, and a banner behind it would not be read.
    /// `totpSecret`: nil leaves any existing verification code untouched (the
    /// v11 semantics — the secret never crosses to Swift, so "send back what
    /// you got" is impossible); "" removes it; an otpauth:// URI or Base32
    /// value sets it.
    func saveLogin(
        id: String?,
        title: String,
        username: String,
        password: String,
        url: String,
        totpSecret: String? = nil
    ) async -> String? {
        guard let session else { return "The vault is locked." }
        do {
            try await session.upsertLogin(
                id: id, title: title, username: username,
                password: password, url: url, totpSecret: totpSecret)
            // The identity list and the credential store both describe the vault
            // we just changed; leaving either stale means the keyboard offers
            // yesterday's logins.
            await didWrite(session)
            return nil
        } catch {
            log.error("save login failed: \(vaultLogMessage(for: error), privacy: .public)")
            return Self.message(error, fallback: "Couldn't save that login.")
        }
    }

    /// Move a login to the Trash (restorable on the desktop).
    /// Create or edit a Wi-Fi entry. Returns a user-facing message on failure.
    func saveWifi(
        id: String?, title: String, ssid: String,
        password: String, security: String, hidden: Bool
    ) async -> String? {
        guard let session else { return "The vault is locked." }
        do {
            try await session.upsertWifi(
                id: id, title: title, ssid: ssid,
                password: password, security: security, hidden: hidden)
            await didWrite(session)
            return nil
        } catch {
            log.error("save wifi failed: \(vaultLogMessage(for: error), privacy: .public)")
            return Self.message(error, fallback: "Couldn't save that network.")
        }
    }

    /// Create or edit a secure note. Returns a user-facing message on failure.
    func saveNote(id: String?, title: String, body: String) async -> String? {
        guard let session else { return "The vault is locked." }
        do {
            try await session.upsertNote(id: id, title: title, body: body)
            await didWrite(session)
            return nil
        } catch {
            log.error("save note failed: \(vaultLogMessage(for: error), privacy: .public)")
            return Self.message(error, fallback: "Couldn't save that note.")
        }
    }

    func deleteItem(_ item: VaultItemMeta) async {
        guard let session else { return }
        do {
            try await session.deleteItem(id: item.id)
            await didWrite(session)
        } catch {
            guard self.session === session else { return }
            log.error("delete failed: \(vaultLogMessage(for: error), privacy: .public)")
            failure = Self.message(error, fallback: "Couldn't delete that item.")
        }
    }

    private func didWrite(_ session: VaultSession) async {
        guard self.session === session else { return }
        // Include notes, Wi-Fi and deletions, not just login edits.
        await sync?.markDirty()
        await reload(session)
    }

    /// Re-read the identities and republish them to AutoFill after a write.
    ///
    /// Same ordering as the unlock path, so a save does not silently reshuffle
    /// the list under the user.
    private func reload(_ session: VaultSession) async {
        do {
            try await load(session)
            let enabled = await CredentialIdentities.replace(
                with: identities, passkeys: passkeyIdentities)
            guard self.session === session else { return }
            autoFillEnabled = enabled
        } catch {
            guard self.session === session else { return }
            log.error("reload failed: \(vaultLogMessage(for: error), privacy: .public)")
            failure = Self.message(error, fallback: "Saved, but the list is out of date.")
        }
    }

    // MARK: - Sync

    /// Whether a Google credential is stored on this device (no keychain read).
    var syncConnected: Bool { SyncCredentialStore.exists }

    /// Build the engine for a freshly opened vault and, if this device is
    /// already signed in, reconnect and pull.
    private func startSync(_ session: VaultSession) async {
        do {
            guard self.session === session else { return }
            let engine = try await session.makeSync()
            guard self.session === session else { return }
            sync = engine
            guard let token = SyncCredentialStore.load() else { return }
            try await engine.connect(refreshToken: token, account: nil)
            guard self.session === session else { return }
            await runSync()
        } catch {
            // A sync that cannot start must never block using the vault.
            guard self.session === session else { return }
            log.error("sync start failed: \(vaultLogMessage(for: error), privacy: .public)")
        }
    }

    /// Run one cycle and fold the result into the UI.
    func runSync() async {
        guard let sync, let session, !syncing, phase == .unlocked else { return }
        syncing = true
        defer { if self.sync === sync { syncing = false } }
        do {
            // Fold the on-disk vault into the shared handle BEFORE the sync
            // write-back. syncNow serializes and writes the vault, and its
            // engine shares this session's vault — so without this a cycle that
            // integrates a Drive change writes the app's in-memory copy over a
            // passkey the AutoFill extension just committed to the file. If the
            // merge itself fails, skip the cycle rather than risk clobbering.
            try await session.foldDiskState()
            guard self.session === session else { return }
            let status = try await sync.syncNow()
            guard self.session === session else { return }
            syncStatus = status
            // A merge rewrote the vault file AND the shared in-memory vault, so
            // the list on screen is now behind what the engine already holds.
            if status.merged { await reload(session) }
            guard self.session === session else { return }
            if let message = status.lastError { failure = message }
        } catch {
            guard self.session === session else { return }
            log.error("sync failed: \(vaultLogMessage(for: error), privacy: .public)")
            failure = Self.message(error, fallback: "Sync failed.")
        }
    }

    /// Sign in to Google and start syncing. The consent screen is presented by
    /// `SyncSignIn`; the PKCE verifier never leaves Rust.
    func connectSync() async {
        guard let sync, let session, !syncing else { return }
        syncing = true
        defer { if self.sync === sync { syncing = false } }
        do {
            let (token, account) = try await SyncSignIn().run()
            guard self.session === session else { return }
            // Store BEFORE connecting: a token the engine uses but that was
            // never persisted works until the app quits and then silently stops.
            try SyncCredentialStore.save(token)
            try await sync.connect(refreshToken: token, account: account)
            guard self.session === session else { return }
            // runSync owns the busy flag while the cycle runs.
            syncing = false
            await runSync()
        } catch SyncError.cancelled {
            // The user closed the sheet. Not an error.
        } catch {
            guard self.session === session else { return }
            log.error("sync connect failed: \(vaultLogMessage(for: error), privacy: .public)")
            failure = Self.message(error, fallback: "Couldn't connect to Google.")
        }
    }

    /// Stop syncing and forget the credential on this device. The vault itself
    /// and the copy in Drive are both left alone.
    func disconnectSync() async {
        do {
            try await sync?.disconnect()
        } catch {
            log.error("sync disconnect failed: \(vaultLogMessage(for: error), privacy: .public)")
        }
        // Delete the token even if the engine call failed, or the next launch
        // would reconnect to an account the user just asked to forget.
        SyncCredentialStore.delete()
        syncStatus = nil
    }

    /// Import a vault picked from Files. Takes the picker's `Result` whole so
    /// every way this can fail — picker included — lands in `failure`.
    ///
    /// Locks first: the handle open right now belongs to the file being replaced.
    func importVault(_ picked: Result<URL, Error>) {
        do {
            let url = try picked.get()
            lock()
            try VaultFile.replace(with: url)
            // The stored device key was minted for the file just replaced, so it
            // opens nothing now. Left behind, the next launch would offer Face ID
            // and then fail.
            VaultSession.forgetDeviceKey()
            quickUnlockEnabled = false
            refreshQuickUnlockAvailability()
            lock()
            // These describe the vault that was just replaced. The next unlock
            // publishes the new one's.
            Task { await CredentialIdentities.removeAll() }
            autoFillEnabled = nil
            failure = nil
        } catch {
            log.error("import failed: \(vaultLogMessage(for: error), privacy: .public)")
            failure = Self.message(error, fallback: "Couldn't import that file.")
        }
    }

    private static func message(_ error: Error, fallback: String) -> String {
        (error as? LocalizedError)?.errorDescription ?? fallback
    }

    /// A cancelled biometric prompt is a decision, not a fault. Reporting it as
    /// an error would put a red line under a password field the user just chose
    /// to use instead.
    private static func cancelled(_ error: Error) -> Bool {
        guard let vaultError = error as? VaultError else { return false }
        switch vaultError {
        case .noDeviceKey(let status), .deviceKeyNotStored(let status):
            return status == errSecUserCanceled
        default:
            return false
        }
    }
}
