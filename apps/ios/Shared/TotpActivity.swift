// The Live Activity contract: what the app sends and the widget draws.
//
// Compiled into BOTH targets. They are separate processes that must agree on
// this shape byte for byte — ActivityKit encodes it on one side and decodes it
// on the other, and a mismatch is a silent no-show rather than an error.
//
// WHY A CODE AND A DATE, and not a ticking counter: a Live Activity cannot be
// refreshed once a second from a backgrounded app. Sending an end time instead
// lets iOS render the countdown itself, with no updates at all — which is both
// the only thing that works and the only thing that stays accurate while Arca
// is not running.

import ActivityKit
import Foundation

struct TotpActivityAttributes: ActivityAttributes {
    struct ContentState: Codable, Hashable {
        /// The six digits, as they should be read.
        let code: String
        /// When this code stops being valid. iOS counts down to it unaided.
        let expiresAt: Date
    }

    /// Which login this is for — "github.com", not the username. The Dynamic
    /// Island is a few characters wide and a lock screen is a public place.
    let label: String
}
