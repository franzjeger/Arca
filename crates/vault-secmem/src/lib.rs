//! Locked, zeroized secret memory.
//!
//! [`SecretBytes`] is a fixed-size heap buffer that is
//!   * **locked into physical RAM** (`mlock` on Unix, `VirtualLock` on Windows)
//!     so its contents can't be paged out to swap or a hibernation file, and
//!   * **zeroized on drop**.
//!
//! Locking is *best effort*: the OS may refuse it (e.g. `RLIMIT_MEMLOCK` on
//! Linux caps how much unprivileged memory a process can lock). On failure the
//! buffer still works and still zeroizes — it just isn't swap-protected. Query
//! [`SecretBytes::is_locked`] if you need to know.
//!
//! Use this for key material (see `vault-core`'s `SymmetricKey`). It does not
//! defend against a process reading its own memory (threat T9); it addresses
//! secrets leaking to disk via swap/hibernation (T5).

#![forbid(unsafe_code)]

use zeroize::Zeroize;

/// A fixed-size, mlock'd, zeroize-on-drop secret buffer.
pub struct SecretBytes {
    // `Box<[u8]>` has a stable heap address for the buffer's lifetime, so the
    // memory lock stays valid even if the `SecretBytes` value is moved.
    buf: Box<[u8]>,
    // Whether we locked the pages (and therefore must unlock on drop).
    locked: bool,
}

impl SecretBytes {
    /// A zero-filled buffer of `len` bytes, locked into RAM if the OS allows.
    pub fn zeroed(len: usize) -> Self {
        let buf = vec![0u8; len].into_boxed_slice();
        // We take the lock but immediately `forget` the guard, then unlock
        // ourselves in `Drop` with the error ignored. `region`'s guard panics
        // if the OS refuses the unlock (VirtualUnlock on Windows can, under
        // working-set pressure), and a panic in a drop aborts the process —
        // so we must never let its guard run.
        let locked = if buf.is_empty() {
            false
        } else if let Ok(guard) = region::lock(buf.as_ptr(), buf.len()) {
            core::mem::forget(guard);
            true
        } else {
            false
        };
        Self { buf, locked }
    }

    /// Copy `src` into a fresh locked buffer.
    pub fn from_slice(src: &[u8]) -> Self {
        let mut s = Self::zeroed(src.len());
        s.buf.copy_from_slice(src);
        s
    }

    /// The secret bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// The secret bytes, mutably (e.g. to fill from an RNG).
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Whether the buffer is actually locked into RAM (false if the OS refused).
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self::from_slice(&self.buf)
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // Wipe the secret while the pages are still locked, then unlock. Errors
        // are ignored (best-effort) so drop can never panic/abort.
        self.buf.zeroize();
        if self.locked {
            let _ = region::unlock(self.buf.as_ptr(), self.buf.len());
        }
    }
}

impl core::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never reveal secret contents.
        f.debug_struct("SecretBytes")
            .field("len", &self.buf.len())
            .field("locked", &self.is_locked())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holds_and_returns_the_bytes() {
        let s = SecretBytes::from_slice(&[1, 2, 3, 4, 5]);
        assert_eq!(s.as_slice(), &[1, 2, 3, 4, 5]);
        assert_eq!(s.len(), 5);
    }

    #[test]
    fn zeroed_is_zero_and_mutable() {
        let mut s = SecretBytes::zeroed(32);
        assert_eq!(s.as_slice(), &[0u8; 32]);
        s.as_mut_slice()[0] = 0xAB;
        assert_eq!(s.as_slice()[0], 0xAB);
    }

    #[test]
    fn clone_is_an_independent_copy() {
        let a = SecretBytes::from_slice(&[9; 16]);
        let mut b = a.clone();
        b.as_mut_slice()[0] = 0;
        assert_eq!(a.as_slice()[0], 9); // original unchanged
        assert_eq!(b.as_slice()[0], 0);
    }

    #[test]
    fn a_key_sized_buffer_works_and_locking_is_best_effort() {
        // Locking is best-effort: the OS may refuse it (RLIMIT_MEMLOCK on Linux,
        // working-set quotas on Windows), especially on constrained CI runners.
        // So we do NOT assert it succeeded — only that the buffer is usable and
        // `is_locked()` reports a definite bool without panicking on drop.
        let mut s = SecretBytes::zeroed(32);
        s.as_mut_slice().fill(0x42);
        assert_eq!(s.as_slice(), &[0x42u8; 32]);
        let _ = s.is_locked();
    }

    #[test]
    fn empty_is_handled() {
        let s = SecretBytes::zeroed(0);
        assert!(s.is_empty());
        assert!(!s.is_locked());
    }
}
