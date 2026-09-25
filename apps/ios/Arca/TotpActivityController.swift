// Starting, refreshing and ending the TOTP Live Activity.
//
// One at a time, deliberately. Two codes in the Dynamic Island is two chances to
// paste the wrong one, and the whole reason this exists is that you are looking
// somewhere else when you read it.
//
// The activity is NOT started automatically when a code comes on screen. A Live
// Activity outlives the app and shows on the lock screen, so it has to be
// something the user asked for — see the button in ItemDetailView.

import ActivityKit
import Foundation
import os

private let log = Logger(subsystem: "no.sybr.vault.ios", category: "liveactivity")

@MainActor
@Observable
final class TotpActivityController {

    /// The item whose code is currently on the Dynamic Island, if any.
    private(set) var showingItemID: String?

    /// The activity's id, NOT the activity.
    ///
    /// `Activity` is not `Sendable`, and `update`/`end` are nonisolated and
    /// async — holding the object here and awaiting on it would send it off this
    /// actor. Keeping the id and re-looking it up inside the async call means
    /// only a `String` crosses. It also gets the honest answer for free: if the
    /// user swiped the activity away, the lookup finds nothing and we stop,
    /// rather than talking to a handle the system has already retired.
    private var activityID: String?

    /// Whether the system will accept a Live Activity right now.
    ///
    /// False on a device where the user has switched them off in Settings, and
    /// on hardware without a Dynamic Island the lock-screen presentation still
    /// applies — so this is about permission, not about the notch.
    var isAvailable: Bool {
        ActivityAuthorizationInfo().areActivitiesEnabled
    }

    /// Put this item's code on the Dynamic Island.
    ///
    /// `staleDate` is the code's expiry: after it, iOS stops treating the
    /// content as current, and the widget swaps the digits for "Open Arca"
    /// rather than leaving six numbers that look valid and are not.
    /// Why the code is not on the Dynamic Island, when it is not.
    ///
    /// Every way this can fail was silent: activities switched off in Settings
    /// returned early, and a refused request only reached the log. From the
    /// user's chair those are identical to a feature that does not work, and
    /// there is nothing to try next. Now the section says which one it was.
    private(set) var lastFailure: String?

    func start(item: VaultItemMeta, code: VaultTotp, label: String) {
        guard isAvailable else {
            lastFailure = "Live Activities are turned off for Arca. "
                + "Settings ▸ Arca ▸ Live Activities."
            return
        }
        lastFailure = nil
        stop()

        let expiresAt = Date().addingTimeInterval(TimeInterval(code.remaining))
        let state = TotpActivityAttributes.ContentState(code: code.code, expiresAt: expiresAt)
        do {
            let activity = try Activity.request(
                attributes: TotpActivityAttributes(label: label),
                content: ActivityContent(state: state, staleDate: expiresAt),
                pushType: nil)
            activityID = activity.id
            showingItemID = item.id
        } catch {
            lastFailure = "iOS refused the Live Activity: \(error.localizedDescription)"
            log.error("could not start the live activity: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Push the next code, while Arca is still in front.
    ///
    /// Only possible in the foreground — there is no server pushing updates —
    /// so a code that rotates while you are in Safari goes stale rather than
    /// silently wrong. That is the honest half of the trade.
    func refresh(code: VaultTotp) async {
        guard let activityID else { return }
        let expiresAt = Date().addingTimeInterval(TimeInterval(code.remaining))
        await Self.push(id: activityID, code: code.code, expiresAt: expiresAt)
    }

    /// Take it down now, and take the code with it.
    func stop() {
        guard let activityID else { return }
        self.activityID = nil
        showingItemID = nil
        Task { await Self.end(id: activityID) }
    }

    // MARK: - off the actor

    private nonisolated static func push(id: String, code: String, expiresAt: Date) async {
        guard let activity = Self.find(id) else { return }
        await activity.update(
            ActivityContent(
                state: .init(code: code, expiresAt: expiresAt),
                staleDate: expiresAt))
    }

    private nonisolated static func end(id: String) async {
        guard let activity = Self.find(id) else { return }
        // `.immediate`: the code is a secret with seconds left on it. Leaving it
        // on the lock screen to fade out politely is the one dismissal policy
        // that would be wrong here.
        await activity.end(nil, dismissalPolicy: .immediate)
    }

    private nonisolated static func find(_ id: String) -> Activity<TotpActivityAttributes>? {
        Activity<TotpActivityAttributes>.activities.first { $0.id == id }
    }
}
