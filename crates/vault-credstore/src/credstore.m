// Publishing credential identities to the OS AutoFill store.
//
// This is what makes macOS offer Arca in Safari and in native apps: the system
// only routes a fill or an assertion to a provider it has been told holds a
// credential for that site. Until now the only thing that ever told it was a
// button in a separate dev harness, so system AutoFill was as stale as the last
// time somebody remembered to press it.
//
// METADATA ONLY. A domain, a username, a record id — and for passkeys the
// credential id and user handle, which the relying party already knows. No
// password and no private key crosses this boundary; the extension fetches
// those itself, one per fill, which is exactly why this can be published while
// the vault is shut.

#import <AuthenticationServices/AuthenticationServices.h>
#import <Foundation/Foundation.h>

/// Replace the whole published set.
///
/// `json` is an array of objects:
///   {"kind":"password","domain":...,"user":...,"record":...}
///   {"kind":"passkey","rp":...,"user":...,"credential_id":<b64>,
///    "user_handle":<b64>,"record":...}
///
/// Returns 1 when the store accepted them, 0 when AutoFill is switched off for
/// Arca (the store silently discards everything in that state, so the caller
/// deserves to know), and -1 on a malformed argument.
///
/// Synchronous by design: it blocks the calling thread on a semaphore, so the
/// caller must not be a UI thread. Rust owns that decision, and doing it here
/// would mean a callback across the FFI boundary for no gain.
int arca_credstore_replace(const char *json) {
  @autoreleasepool {
    if (json == NULL) {
      return -1;
    }
    NSData *data = [[NSString stringWithUTF8String:json]
        dataUsingEncoding:NSUTF8StringEncoding];
    if (data == nil) {
      return -1;
    }
    NSArray *rows = [NSJSONSerialization JSONObjectWithData:data
                                                    options:0
                                                      error:nil];
    if (![rows isKindOfClass:[NSArray class]]) {
      return -1;
    }

    // Asked before publishing, not after: the store accepts a replace call
    // while disabled and drops it on the floor, which reads as "published 648
    // logins" followed by nothing working.
    __block BOOL enabled = NO;
    dispatch_semaphore_t stateWait = dispatch_semaphore_create(0);
    [[ASCredentialIdentityStore sharedStore]
        getCredentialIdentityStoreStateWithCompletion:^(
            ASCredentialIdentityStoreState *state) {
          enabled = state.enabled;
          dispatch_semaphore_signal(stateWait);
        }];
    dispatch_semaphore_wait(stateWait, DISPATCH_TIME_FOREVER);
    if (!enabled) {
      return 0;
    }

    NSMutableArray *entries = [NSMutableArray array];
    for (NSDictionary *row in rows) {
      if (![row isKindOfClass:[NSDictionary class]]) {
        continue;
      }
      NSString *kind = row[@"kind"];
      NSString *record = row[@"record"];
      NSString *user = row[@"user"] ?: @"";
      if (![record isKindOfClass:[NSString class]]) {
        continue;
      }

      if ([kind isEqualToString:@"password"]) {
        NSString *domain = row[@"domain"];
        // A login with no domain has nothing for the system to match on, so
        // publishing it would only ever clutter the suggestion list.
        if (![domain isKindOfClass:[NSString class]] || domain.length == 0) {
          continue;
        }
        ASCredentialServiceIdentifier *service = [[ASCredentialServiceIdentifier alloc]
            initWithIdentifier:domain
                          type:ASCredentialServiceIdentifierTypeDomain];
        [entries addObject:[[ASPasswordCredentialIdentity alloc]
                               initWithServiceIdentifier:service
                                                    user:user
                                        recordIdentifier:record]];
      } else if ([kind isEqualToString:@"passkey"]) {
        NSString *rp = row[@"rp"];
        NSString *credentialB64 = row[@"credential_id"];
        NSString *handleB64 = row[@"user_handle"];
        if (![rp isKindOfClass:[NSString class]] || rp.length == 0 ||
            ![credentialB64 isKindOfClass:[NSString class]]) {
          continue;
        }
        NSData *credentialID =
            [[NSData alloc] initWithBase64EncodedString:credentialB64 options:0];
        NSData *userHandle =
            [handleB64 isKindOfClass:[NSString class]]
                ? [[NSData alloc] initWithBase64EncodedString:handleB64 options:0]
                : [NSData data];
        if (credentialID == nil) {
          continue;
        }
        [entries addObject:[[ASPasskeyCredentialIdentity alloc]
                               initWithRelyingPartyIdentifier:rp
                                                     userName:user
                                                 credentialID:credentialID
                                                   userHandle:userHandle ?: [NSData data]
                                             recordIdentifier:record]];
      }
    }

    __block BOOL ok = NO;
    dispatch_semaphore_t wait = dispatch_semaphore_create(0);
    [[ASCredentialIdentityStore sharedStore]
        replaceCredentialIdentityEntries:entries
                              completion:^(BOOL success, NSError *error) {
                                ok = success;
                                if (!success) {
                                  NSLog(@"[Arca] credential identity publish "
                                        @"failed: %@",
                                        error);
                                }
                                dispatch_semaphore_signal(wait);
                              }];
    dispatch_semaphore_wait(wait, DISPATCH_TIME_FOREVER);
    return ok ? 1 : 0;
  }
}

/// Drop everything Arca has published. Used when the vault file is replaced —
/// the identities on file describe a vault that no longer exists.
int arca_credstore_clear(void) {
  @autoreleasepool {
    __block BOOL ok = NO;
    dispatch_semaphore_t wait = dispatch_semaphore_create(0);
    [[ASCredentialIdentityStore sharedStore]
        removeAllCredentialIdentitiesWithCompletion:^(BOOL success,
                                                      NSError *error) {
          ok = success;
          if (!success) {
            NSLog(@"[Arca] credential identity clear failed: %@", error);
          }
          dispatch_semaphore_signal(wait);
        }];
    dispatch_semaphore_wait(wait, DISPATCH_TIME_FOREVER);
    return ok ? 1 : 0;
  }
}
