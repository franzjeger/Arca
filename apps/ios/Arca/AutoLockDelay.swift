// How long the vault stays open while Arca is in the background.
//
// The old behaviour was "immediately", which reads as the safe default and is
// not. Locking on every app switch means a Face ID prompt to copy a password, a
// second one after pasting it, and a third when you come back for the code —
// and a protection people work around is not protecting anything.
//
// Apple Passwords behaves this way too: the vault stays open for a while after
// you leave, and the device passcode is the outer gate.

import Foundation

enum AutoLockDelay: String, CaseIterable, Identifiable {
    case immediately
    case oneMinute
    case fiveMinutes
    case fifteenMinutes
    case oneHour
    case never

    /// Immediately, and the reasoning is worth keeping.
    ///
    /// This shipped once as five minutes, which quietly loosened every existing
    /// install: the app had always locked on leaving the foreground, and a
    /// default is exactly what nobody revisits. Relaxing a security property for
    /// people who never asked is not a default to choose casually.
    ///
    /// It also costs less than it looks. Filling a password does NOT go through
    /// this — the AutoFill extension is its own process and opens the vault
    /// itself from the shared container and keychain, with no app session
    /// involved. So this governs only the app you deliberately open to browse,
    /// and locking it at once leaves the everyday path untouched.
    ///
    /// Anyone who does browse a lot can move it, which is the point of having
    /// the setting rather than an opinion baked into the code.
    static let `default` = AutoLockDelay.immediately

    init(stored: String?) {
        self = stored.flatMap(AutoLockDelay.init(rawValue:)) ?? .default
    }

    var id: String { rawValue }

    /// nil means never lock on time alone.
    var seconds: TimeInterval? {
        switch self {
        case .immediately: return 0
        case .oneMinute: return 60
        case .fiveMinutes: return 5 * 60
        case .fifteenMinutes: return 15 * 60
        case .oneHour: return 60 * 60
        case .never: return nil
        }
    }

    var label: String {
        switch self {
        case .immediately: return "Immediately"
        case .oneMinute: return "After 1 minute"
        case .fiveMinutes: return "After 5 minutes"
        case .fifteenMinutes: return "After 15 minutes"
        case .oneHour: return "After 1 hour"
        // Named for what it costs, not just what it does. "Never" alone reads
        // as a convenience setting rather than a decision about the vault.
        case .never: return "Only when I lock it"
        }
    }
}
