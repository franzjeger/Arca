import Foundation

/// Tokens distinguish async work from the current unlock from work that was
/// still running when the user locked or replaced the vault.
struct SessionLifetime: Sendable {
    private var token: UUID?
    private(set) var isBackgrounded = false

    mutating func begin() -> UUID? {
        guard !isBackgrounded else { return nil }
        let next = UUID()
        token = next
        return next
    }

    func accepts(_ candidate: UUID) -> Bool { token == candidate }
    mutating func invalidate() { token = nil }
    mutating func background() { isBackgrounded = true }
    mutating func foreground() { isBackgrounded = false }
}
