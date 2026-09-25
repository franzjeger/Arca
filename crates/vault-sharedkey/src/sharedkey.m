// Mirroring the device key into the AutoFill extension's keychain group.
//
// WHY A SECOND COPY OF THE SAME KEY EXISTS
//
// Arca keeps its device key (the quick-unlock token that unwraps the vault key)
// as a plain generic password in the FILE-BASED login keychain. That is
// deliberate and documented in crates/vault-store/src/keychain.rs: the earlier
// data-protection variant made a provisioning mismatch return "found but
// unreadable", so Touch ID fired and the unlock then fell back to the master
// password every single time.
//
// The sandboxed extension cannot read that keychain at all. It reads the
// DATA-PROTECTION keychain, in access group LY6LJ395B8.no.sybr.vault.shared —
// the only keychain that carries access groups and per-item access control.
//
// So the same key is written to both, and the two copies have different jobs:
// the app unlocks from the login-keychain copy, the extension from this one.
// Nothing here is allowed to affect the former. Every failure below is
// reported and swallowed by the caller, because a credential provider that
// cannot start must never take the app's own unlock down with it.
//
// This is what ArcaHost used to do at the moment the user unlocked it. Removing
// that harness removed the only writer, which is why AutoFill authenticated and
// then failed with errSecItemNotFound (-25300) on a machine where everything
// else looked correct.

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>

// Must match VaultShared in apps/apple-shared/VaultBridge.swift. Four
// attributes decide WHICH item is touched; a drift in any one of them is an
// extension that authenticates and then finds nothing.
static NSString *const kService = @"no.sybr.vault";
static NSString *const kAccessGroup = @"LY6LJ395B8.no.sybr.vault.shared";

// The extension's copy MUST NOT share service+account with the app's own
// login-keychain device key.
//
// It did for one build, and the app broke: its `keychain::get` has no
// LAContext and does not expect an access-controlled item, so the lookup
// resolved to THIS item, fired Touch ID (four times over one unlock), failed
// to read, and fell back to the master password every time. The app looked
// broken while AutoFill worked.
//
// crates/vault-store/src/keychain.rs documents that exact failure from an
// earlier attempt. A distinct account name is what keeps the two lookups from
// ever meeting.
static NSString *const kAccount = @"default-vault-autofill";

// What that one build wrote. Purged wherever it may still exist.
static NSString *const kLegacyAccount = @"default-vault";

static NSMutableDictionary *queryFor(NSString *account) {
  return [@{
    (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService : kService,
    (__bridge id)kSecAttrAccount : account,
    (__bridge id)kSecAttrAccessGroup : kAccessGroup,
    // Without this the query goes to the login keychain, which has no access
    // groups — it would find the app's own copy and quietly touch the wrong
    // item.
    (__bridge id)kSecUseDataProtectionKeychain : @YES,
  } mutableCopy];
}

static NSMutableDictionary *baseQuery(void) { return queryFor(kAccount); }

/// Remove the colliding item written by the build that shared an account name
/// with the app's own key. Safe to call always; missing is success.
int arca_sharedkey_purge_legacy(void) {
  @autoreleasepool {
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)queryFor(kLegacyAccount));
    return status == errSecItemNotFound ? 0 : (int)status;
  }
}

/// Write `key` (RAW bytes — the extension passes them straight to
/// vault_ffi_vault_open_device, so base64 here would decrypt nothing).
///
/// Returns 0 on success, otherwise the OSStatus, which the caller logs.
int arca_sharedkey_store(const unsigned char *key, unsigned long len) {
  @autoreleasepool {
    if (key == NULL || len == 0) {
      return errSecParam;
    }

    // Replace rather than update: SecItemAdd over an existing item fails with
    // errSecDuplicateItem, and a stale key from an earlier enrolment unwraps
    // nothing.
    SecItemDelete((__bridge CFDictionaryRef)baseQuery());

    // biometryCurrentSet invalidates the item when a finger is added, so
    // someone with the passcode cannot enrol their own biometrics and inherit
    // access. It cannot be satisfied where no biometrics exist, so fall back to
    // userPresence there. Same rule as storeDeviceKey in VaultBridge.swift.
    LAContext *context = [[LAContext alloc] init];
    BOOL hasBiometrics =
        [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                             error:nil];
    SecAccessControlCreateFlags flags =
        hasBiometrics ? kSecAccessControlBiometryCurrentSet
                      : kSecAccessControlUserPresence;

    CFErrorRef acError = NULL;
    // WhenUnlockedThisDeviceOnly: this key belongs to this Mac. It must never
    // reach a backup or another device through iCloud Keychain.
    SecAccessControlRef access = SecAccessControlCreateWithFlags(
        NULL, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &acError);
    if (access == NULL) {
      if (acError) {
        NSLog(@"[Arca] shared device key: access control failed: %@", acError);
        CFRelease(acError);
      }
      return errSecAllocate;
    }

    NSMutableDictionary *add = baseQuery();
    add[(__bridge id)kSecAttrAccessControl] = (__bridge id)access;
    add[(__bridge id)kSecValueData] = [NSData dataWithBytes:key length:len];

    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
    CFRelease(access);
    if (status != errSecSuccess) {
      NSLog(@"[Arca] shared device key: SecItemAdd failed with %d", (int)status);
    }
    return (int)status;
  }
}

/// Remove the shared copy. Used when quick unlock is switched off: leaving it
/// behind would let the extension keep opening a vault the user just said
/// should need the master password.
int arca_sharedkey_clear(void) {
  @autoreleasepool {
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)baseQuery());
    return status == errSecItemNotFound ? 0 : (int)status;
  }
}
