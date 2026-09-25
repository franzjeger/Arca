// Tests for the Swift↔Rust bridge.
//
// The first Swift tests in this repository, and they exist for one reason above
// the others: `apps/macos/README.md` lists two invariants that are easy to
// break, and says of the second — VaultShared.requiredAbiVersion matching
// ABI_VERSION in the Rust — that *nothing enforces it, because there is no
// Swift test target*. There is now, and it does.
//
// Deliberately narrow. Everything here is either pure Swift logic or a call
// across the C ABI that needs no vault, no keychain and no user: opening a real
// vault needs a file in an App Group container and a biometric prompt, neither
// of which exists on a CI runner. What is left is still worth pinning — it is
// the layer where a silent mismatch fills the wrong bytes into a login form.

import XCTest

final class VaultBridgeTests: XCTestCase {

    func testSyncStatusPreservesErrorsAndLastSuccessfulSync() throws {
        // The Rust FFI uses camelCase. Dropping these optional fields makes a
        // failed cycle appear successful and erases the last-sync timestamp.
        let json = Data("""
            {"connected":true,"account":"test@example.invalid",\
            "lastSyncUnix":123456,"lastError":"upload failed","merged":false}
            """.utf8)
        let status = try JSONDecoder().decode(SyncStatus.self, from: json)
        XCTAssertEqual(status.lastSyncUnix, 123456)
        XCTAssertEqual(status.lastError, "upload failed")
        XCTAssertFalse(status.merged)
    }

    #if os(macOS)
    func testPasskeyCommitsAreIndependentAndSurviveMirrorReplacement() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let inbox = directory.appendingPathComponent("passkey-inbox")
        let first = Data("encrypted first snapshot".utf8)
        let second = Data("encrypted second snapshot".utf8)
        try VaultShared.commitPasskeyRegistration(first, in: inbox)
        try VaultShared.commitPasskeyRegistration(second, in: inbox)
        try Data("desktop mirror".utf8).write(to: directory.appendingPathComponent("default.vault"))
        let recovered = try VaultShared.pendingPasskeySnapshots(in: inbox)
        XCTAssertEqual(Set(recovered), Set([first, second]))
        for entry in try FileManager.default.contentsOfDirectory(at: inbox, includingPropertiesForKeys: nil) {
            let attributes = try FileManager.default.attributesOfItem(atPath: entry.path)
            XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        }
    }

    func testPasskeyCommitReportsUnwritableDestination() throws {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: file) }
        try Data("occupied".utf8).write(to: file)
        XCTAssertThrowsError(try VaultShared.commitPasskeyRegistration(Data([1, 2]), in: file))
        XCTAssertEqual(try Data(contentsOf: file), Data("occupied".utf8))
    }
    #endif

    // MARK: The contract with Rust

    /// The invariant the README calls out. `VaultSession.open*` checks this at
    /// runtime and fails closed, which means a mismatch turns every unlock into
    /// "Reinstall Arca" — discovered by a user rather than by CI. Now by CI.
    func testRequiredAbiVersionMatchesTheLinkedLibrary() {
        XCTAssertEqual(
            VaultShared.requiredAbiVersion,
            vault_ffi_abi_version(),
            """
            Swift expects ABI v\(VaultShared.requiredAbiVersion) but linked \
            v\(vault_ffi_abi_version()). Bump VaultShared.requiredAbiVersion \
            with ABI_VERSION in crates/vault-ffi/src/lib.rs.
            """)
    }

    /// `VaultFFICode` is a hand-copied mirror of the table in vault_ffi.h, so
    /// it can drift the same way the header did. Prove at least one code by
    /// asking the library for it rather than trusting the copy.
    func testNullArgumentCodeAgreesWithTheLibrary() {
        var handle: OpaquePointer?
        let code = vault_ffi_vault_open(nil, 0, nil, 0, &handle)
        XCTAssertEqual(code, VaultFFICode.nullArgument)
        XCTAssertNil(handle, "an error path must not leave a handle behind")

        XCTAssertEqual(vault_ffi_has_device_unlock(nil), VaultFFICode.nullArgument)
    }

    /// Freeing null is documented as a no-op. If that stopped being true the
    /// `defer { vault_ffi_free(...) }` in every read path would be a crash.
    func testFreeingNullIsSafe() {
        vault_ffi_free(nil, 0)
        vault_ffi_vault_free(nil)
    }

    // MARK: Identity decoding

    /// The exact JSON shape vault_ffi.h documents. A field rename on the Rust
    /// side would otherwise surface as an empty AutoFill list.
    func testDecodesTheDocumentedIdentityJSON() throws {
        let json = """
            [{"id":"3F2504E0-4F89-11D3-9A0C-0305E82C3301",\
            "user":"alice@example.test","domain":"github.com","label":"GitHub"}]
            """
        let identities = try JSONDecoder().decode(
            [VaultIdentity].self, from: Data(json.utf8))

        XCTAssertEqual(identities.count, 1)
        XCTAssertEqual(identities.first?.user, "alice@example.test")
        XCTAssertEqual(identities.first?.domain, "github.com")
        XCTAssertEqual(identities.first?.label, "GitHub")
    }

    // MARK: Errors stay secret-free

    /// These strings are logged at `.public` privacy, so they survive into a
    /// sysdiagnose. Nothing in them may be a password, a key, or a file path.
    func testLogMessagesCarryOnlyCodes() {
        let cases: [(VaultError, String)] = [
            (.ffi(code: -7, operation: "vault_open"), "ffi(vault_open=-7)"),
            (.abiMismatch(linked: 3, expected: 4), "abiMismatch(3!=4)"),
            (.noContainer, "noContainer"),
            (.noVaultFile, "noVaultFile"),
            (.emptyVaultFile, "emptyVaultFile"),
            (.malformedIdentities, "malformedIdentities"),
        ]
        for (error, expected) in cases {
            XCTAssertEqual(error.logMessage, expected)
        }
    }

    /// An arbitrary error must not have its own description spliced into a
    /// public log line — the whole point of not using String(describing:).
    func testUnknownErrorsAreReducedToADomainAndCode() {
        let underlying = NSError(
            domain: "TestDomain",
            code: 42,
            userInfo: [NSLocalizedDescriptionKey: "a-secret-looking-string"])
        let message = vaultLogMessage(for: underlying)

        XCTAssertEqual(message, "unexpected(TestDomain:42)")
        XCTAssertFalse(message.contains("a-secret-looking-string"))
    }

    /// A wrong key and a cancelled prompt are different situations for the
    /// person reading the message; both were "Couldn't open your vault" before.
    func testUserFacingMessagesDistinguishTheCommonFailures() {
        let wrongKey = VaultError.ffi(
            code: VaultFFICode.decryptionFailed, operation: "vault_open")
        let cancelled = VaultError.noDeviceKey(status: errSecUserCanceled)
        let noKeyYet = VaultError.noDeviceKey(status: errSecItemNotFound)

        XCTAssertNotEqual(wrongKey.errorDescription, cancelled.errorDescription)
        XCTAssertNotEqual(cancelled.errorDescription, noKeyYet.errorDescription)
        for error in [wrongKey, cancelled, noKeyYet] {
            XCTAssertFalse(
                error.errorDescription?.isEmpty ?? true,
                "every case needs text; a nil description renders as nothing")
        }
    }

    // MARK: Keychain group resolution

    /// A test bundle has no ArcaKeychainAccessGroup in its Info.plist, which is
    /// exactly the unresolved case the fallback exists for — the same thing an
    /// unsigned build sees. It must still produce a prefixed group rather than a
    /// bare one, or the query silently searches the wrong place.
    func testAccessGroupFallsBackToAPrefixedGroup() {
        let group = VaultShared.keychainAccessGroup

        XCTAssertTrue(
            group.hasSuffix("no.sybr.vault.shared"),
            "resolved group '\(group)' is not the shared vault group")
        XCTAssertNotEqual(
            group, "no.sybr.vault.shared",
            "a bare, prefix-less group means the fallback did not apply")
        XCTAssertFalse(
            group.contains("$("),
            "an unexpanded build variable reached the keychain query")
    }
}

final class SessionLifetimeTests: XCTestCase {
    func testBackgroundDuringUnlockInvalidatesDelayedCompletion() {
        var lifetime = SessionLifetime()
        let pending = lifetime.begin()!
        lifetime.background()
        lifetime.invalidate()
        XCTAssertFalse(lifetime.accepts(pending))
        XCTAssertNil(lifetime.begin())
        lifetime.foreground()
        let next = lifetime.begin()!
        XCTAssertFalse(lifetime.accepts(pending))
        XCTAssertTrue(lifetime.accepts(next))
    }

    func testLockRejectsPendingSyncEvenAfterAnotherUnlock() {
        var lifetime = SessionLifetime()
        let old = lifetime.begin()!
        lifetime.invalidate()
        let current = lifetime.begin()!
        XCTAssertFalse(lifetime.accepts(old))
        XCTAssertTrue(lifetime.accepts(current))
    }
}
