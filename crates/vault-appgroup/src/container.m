#import <Foundation/Foundation.h>
#include <string.h>

// Resolve the App Group container path via Foundation. A raw filesystem path to
// ~/Library/Group Containers/<group> is denied (EPERM) to a non-sandboxed
// process even with the entitlement; asking NSFileManager for it grants the
// entitled process access to that container for the process lifetime.
//
// Writes the UTF-8 path into `out` (NUL-terminated, up to out_len-1 bytes) and
// returns its byte length, or 0 if the container is unavailable (entitlement
// missing/unprovisioned) or the buffer is too small.
size_t arca_app_group_container_path(const char *group, char *out, size_t out_len) {
    @autoreleasepool {
        if (group == NULL || out == NULL || out_len == 0) {
            return 0;
        }
        NSString *gid = [NSString stringWithUTF8String:group];
        if (gid == nil) {
            return 0;
        }
        NSFileManager *fm = [NSFileManager defaultManager];
        NSURL *url = [fm containerURLForSecurityApplicationGroupIdentifier:gid];
        if (url == nil) {
            return 0;
        }
        const char *path = [[url path] fileSystemRepresentation];
        if (path == NULL) {
            return 0;
        }
        size_t len = strlen(path);
        if (len >= out_len) { // must fit with a trailing NUL
            return 0;
        }
        memcpy(out, path, len);
        out[len] = '\0';
        return len;
    }
}
