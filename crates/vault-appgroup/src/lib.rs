//! macOS App Group container resolution for Arca.
//!
//! A non-sandboxed app can only reach its App Group container
//! (`~/Library/Group Containers/<group>`) by asking Foundation for it via
//! `-[NSFileManager containerURLForSecurityApplicationGroupIdentifier:]`. That
//! call grants the entitled process filesystem access to the container; a raw
//! path is denied with `EPERM`. This crate wraps that single Objective-C call
//! behind a safe API so the desktop app can keep `#![forbid(unsafe_code)]`.
//!
//! The App Group entitlement must be present and provisioned, or the call
//! returns `None`. On non-Apple platforms it always returns `None`.

use std::path::PathBuf;

/// The filesystem path of the shared App Group container, or `None` if it can't
/// be reached (missing/unprovisioned entitlement, or a non-Apple platform).
///
/// Calling this **grants the current process access** to that container for its
/// lifetime, so subsequent plain filesystem writes to the returned path (and its
/// children) succeed. Resolve it once at startup, before touching the container.
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub fn container_path(group: &str) -> Option<PathBuf> {
    use std::ffi::CString;
    use std::os::raw::c_char;

    extern "C" {
        fn arca_app_group_container_path(
            group: *const c_char,
            out: *mut c_char,
            out_len: usize,
        ) -> usize;
    }

    let c_group = CString::new(group).ok()?;
    // The container path is far under PATH_MAX (1024) on macOS.
    let mut buf = vec![0u8; 4096];
    // SAFETY: `c_group` is a valid NUL-terminated C string that outlives the
    // call; `buf` is a valid, writable buffer of `buf.len()` bytes. The callee
    // writes at most `out_len - 1` bytes plus a NUL and returns the byte length
    // written (0 on any failure), so `len < buf.len()` always holds.
    let len = unsafe {
        arca_app_group_container_path(c_group.as_ptr(), buf.as_mut_ptr() as *mut c_char, buf.len())
    };
    if len == 0 {
        return None;
    }
    buf.truncate(len);
    String::from_utf8(buf).ok().map(PathBuf::from)
}

/// Non-Apple platforms have no App Group containers.
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub fn container_path(_group: &str) -> Option<PathBuf> {
    None
}
