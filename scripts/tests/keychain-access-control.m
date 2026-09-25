// Signed, interactive macOS test. Only creates randomly named synthetic items.
#import <AppKit/AppKit.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>

extern int arca_protected_create(const char *, const unsigned char *);
extern int arca_protected_read(const char *, unsigned char *, int);
extern int arca_protected_exists(const char *);
extern int arca_protected_delete(const char *);

static NSMutableDictionary *query(NSString *service, BOOL protected) {
  NSMutableDictionary *q = [@{
    (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService: service,
    (__bridge id)kSecAttrAccount: @"synthetic-migration-test",
    (__bridge id)kSecUseDataProtectionKeychain: @(protected),
  } mutableCopy];
  if (protected) q[(__bridge id)kSecAttrAccessGroup] = @"LY6LJ395B8.no.sybr.vault.shared";
  return q;
}

static OSStatus readKey(NSString *service, BOOL protected, BOOL interactive, NSData **data) {
  if (protected) {
    unsigned char bytes[32] = {0};
    OSStatus status = arca_protected_read(service.UTF8String, bytes, interactive);
    if (!status) *data = [NSData dataWithBytes:bytes length:sizeof(bytes)];
    memset_s(bytes, sizeof(bytes), 0, sizeof(bytes));
    return status;
  }
  NSMutableDictionary *q = query(service, protected);
  q[(__bridge id)kSecReturnData] = @YES;
  LAContext *context = [[LAContext alloc] init];
  context.interactionNotAllowed = !interactive;
  context.localizedReason = @"Test Arca's stronger keychain protection with a temporary test key";
  q[(__bridge id)kSecUseAuthenticationContext] = context;
  CFTypeRef result = NULL;
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)q, &result);
  if (result) *data = CFBridgingRelease(result);
  [context invalidate];
  return status;
}

static int runTest(void) {
  NSString *service = [@"desktop-protected-" stringByAppendingString:NSUUID.UUID.UUIDString];
  unsigned char bytes[32];
  if (SecRandomCopyBytes(kSecRandomDefault, sizeof(bytes), bytes) != errSecSuccess) return 1;
  NSData *expected = [NSData dataWithBytes:bytes length:sizeof(bytes)];
  memset_s(bytes, sizeof(bytes), 0, sizeof(bytes));
  int exitCode = 1;
  @try {
    NSMutableDictionary *legacy = query(service, NO);
    legacy[(__bridge id)kSecValueData] = expected;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)legacy, NULL);
    if (status) { fprintf(stderr, "FAIL: synthetic legacy write (%d)\n", (int)status); return 1; }
    status = arca_protected_create(service.UTF8String, expected.bytes);
    if (status) { fprintf(stderr, "FAIL: protected write (%d)\n", (int)status); return 1; }
    status = arca_protected_exists(service.UTF8String);
    if (status) { fprintf(stderr, "FAIL: metadata presence check (%d)\n", (int)status); return 1; }
    NSData *read = nil;
    status = readKey(service, YES, NO, &read);
    if (status != errSecInteractionNotAllowed && status != errSecAuthFailed) {
      fprintf(stderr, "FAIL: unauthenticated read was not denied (%d)\n", (int)status); return 1;
    }
    puts("PASS: macOS denied reading the protected key without authentication"); fflush(stdout);
    puts("Touch ID: authenticate to verify migration, or cancel to verify preservation of the original test key."); fflush(stdout);
    status = readKey(service, YES, getenv("ARCA_TEST_DENY_AUTH") == NULL, &read);
    if (status != errSecSuccess) {
      NSData *original = nil;
      OSStatus legacyStatus = readKey(service, NO, NO, &original);
      if (legacyStatus || ![original isEqualToData:expected]) {
        fprintf(stderr, "FAIL: unsuccessful migration lost the original test key\n"); return 1;
      }
      fprintf(stderr, "Migration not completed (%d); original synthetic key retained correctly.\n", (int)status);
      return 2;
    }
    if (![read isEqualToData:expected]) { fprintf(stderr, "FAIL: authenticated key differs\n"); return 1; }
    puts("PASS: Touch ID released the exact test key");
    status = SecItemDelete((__bridge CFDictionaryRef)query(service, NO));
    if (status) { fprintf(stderr, "FAIL: retiring original test item (%d)\n", (int)status); return 1; }
    NSData *original = nil;
    if (readKey(service, NO, NO, &original) != errSecItemNotFound) {
      fprintf(stderr, "FAIL: original unprotected test item remains\n"); return 1;
    }
    puts("PASS: original test item retired only after successful verification");
    read = nil;
    status = readKey(service, YES, NO, &read);
    if (status != errSecInteractionNotAllowed && status != errSecAuthFailed) {
      fprintf(stderr, "FAIL: a fresh unauthenticated context could reuse authentication (%d)\n", (int)status); return 1;
    }
    puts("PASS: a fresh context still cannot read without authentication");
    exitCode = 0;
  } @finally {
    OSStatus first = arca_protected_delete(service.UTF8String);
    OSStatus second = SecItemDelete((__bridge CFDictionaryRef)query(service, NO));
    if ((first && first != errSecItemNotFound) || (second && second != errSecItemNotFound)) {
      fprintf(stderr, "FAIL: test-item cleanup (%d, %d), service %s\n", (int)first, (int)second, service.UTF8String);
      exitCode = 1;
    } else { puts("Temporary test items removed."); }
  }
  return exitCode;
}

int main(void) {
  @autoreleasepool {
    [NSApplication sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    [NSApp activateIgnoringOtherApps:YES];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
      @autoreleasepool { int result = runTest(); fflush(stdout); fflush(stderr); exit(result); }
    });
    [NSApp run];
  }
  return 1;
}
