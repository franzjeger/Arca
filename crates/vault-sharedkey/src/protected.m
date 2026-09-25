// Desktop protected device keys. Each staged key has a unique account so a
// failed migration never overwrites the currently usable key.
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>

static NSMutableDictionary *protectedQuery(const char *account) {
  if (!account) return nil;
  NSString *name = [NSString stringWithUTF8String:account];
  if (!name || ![name hasPrefix:@"desktop-protected-"]) return nil;
  return [@{
    (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService: @"no.sybr.vault",
    (__bridge id)kSecAttrAccount: name,
    (__bridge id)kSecAttrAccessGroup: @"LY6LJ395B8.no.sybr.vault.shared",
    (__bridge id)kSecUseDataProtectionKeychain: @YES,
  } mutableCopy];
}

int arca_protected_create(const char *account, const unsigned char *bytes) {
  @autoreleasepool {
    NSMutableDictionary *q = protectedQuery(account);
    if (!q || !bytes) return errSecParam;
    LAContext *context = [[LAContext alloc] init];
    [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:nil];
    SecAccessControlCreateFlags flags = context.biometryType != LABiometryTypeNone
      ? kSecAccessControlBiometryCurrentSet : kSecAccessControlUserPresence;
    CFErrorRef error = NULL;
    SecAccessControlRef access = SecAccessControlCreateWithFlags(NULL,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error);
    if (!access) { if (error) CFRelease(error); return errSecAllocate; }
    q[(__bridge id)kSecAttrAccessControl] = (__bridge id)access;
    q[(__bridge id)kSecValueData] = [NSData dataWithBytes:bytes length:32];
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)q, NULL);
    CFRelease(access);
    return status;
  }
}

int arca_protected_read(const char *account, unsigned char *bytes, int interactive) {
  @autoreleasepool {
    NSMutableDictionary *q = protectedQuery(account);
    if (!q || !bytes) return errSecParam;
    LAContext *context = [[LAContext alloc] init];
    context.interactionNotAllowed = !interactive;
    context.localizedReason = @"Unlock Arca's protected device key";
    q[(__bridge id)kSecUseAuthenticationContext] = context;
    q[(__bridge id)kSecReturnData] = @YES;
    CFTypeRef value = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)q, &value);
    if (status == errSecSuccess) {
      NSData *data = CFBridgingRelease(value);
      if (![data isKindOfClass:NSData.class] || data.length != 32) status = errSecDecode;
      else memcpy(bytes, data.bytes, 32);
    } else if (value) CFRelease(value);
    [context invalidate];
    return status;
  }
}

int arca_protected_exists(const char *account) {
  @autoreleasepool {
    NSMutableDictionary *q = protectedQuery(account);
    if (!q) return errSecParam;
    LAContext *context = [[LAContext alloc] init];
    context.interactionNotAllowed = YES;
    q[(__bridge id)kSecUseAuthenticationContext] = context;
    q[(__bridge id)kSecReturnAttributes] = @YES;
    CFTypeRef value = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)q, &value);
    if (value) CFRelease(value);
    [context invalidate];
    // A matching ACL-protected item may require interaction even for its
    // metadata. This is presence, not permission to read the key (same as iOS).
    return status == errSecInteractionNotAllowed ? errSecSuccess : status;
  }
}

int arca_protected_delete(const char *account) {
  @autoreleasepool {
    NSMutableDictionary *q = protectedQuery(account);
    if (!q) return errSecParam;
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)q);
    return status == errSecItemNotFound ? errSecSuccess : status;
  }
}
