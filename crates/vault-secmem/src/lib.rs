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

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use zeroize::Zeroize;

/// Every page locked for a live buffer, with how many buffers need it and the
/// guard that unlocks it.
///
/// The OS locks and unlocks whole pages, and one page can hold several small
/// buffers. Unlocking the pages of the first buffer dropped put the secrets of
/// the others on those pages back within reach of swap, and on Windows the
/// next buffer's unlock then failed on a page no longer locked. So a page is
/// locked by the first buffer on it and unlocked when the last one goes, by
/// dropping `region`'s guard: the only way to unlock without `unsafe`, and it
/// unlocks each page exactly once.
type Pages = BTreeMap<usize, (usize, region::LockGuard)>;
static LOCKED_PAGES: Mutex<Pages> = Mutex::new(BTreeMap::new());

fn locked_pages() -> std::sync::MutexGuard<'static, Pages> {
    // A panic elsewhere must not stop a later drop from unlocking.
    LOCKED_PAGES.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The first address of each page `buf` touches.
fn pages(buf: &[u8]) -> impl Iterator<Item = usize> {
    let size = region::page::size();
    let start = buf.as_ptr() as usize;
    (start / size * size..start + buf.len()).step_by(size)
}

/// Locks the pages of `buf` that no other buffer holds. All or nothing: if the
/// OS refuses a page, the pages counted for `buf` so far are released again.
fn lock_pages(buf: &[u8]) -> bool {
    let mut locked = locked_pages();
    let mut taken = Vec::new();
    for page in pages(buf) {
        if let Some((count, _)) = locked.get_mut(&page) {
            *count += 1;
        } else if let Ok(guard) = region::lock(
            std::ptr::without_provenance::<u8>(page),
            region::page::size(),
        ) {
            locked.insert(page, (1, guard));
        } else {
            release(&mut locked, taken);
            return false;
        }
        taken.push(page);
    }
    true
}

fn unlock_pages(buf: &[u8]) {
    release(&mut locked_pages(), pages(buf));
}

fn release(locked: &mut Pages, pages: impl IntoIterator<Item = usize>) {
    for page in pages {
        if let Some((count, _)) = locked.get_mut(&page) {
            *count -= 1;
            if *count == 0 {
                // Dropping the guard unlocks the page.
                locked.remove(&page);
            }
        }
    }
}

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
        let locked = !buf.is_empty() && lock_pages(&buf);
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
        // Wipe the secret while the pages are still locked, then give them up.
        self.buf.zeroize();
        if self.locked {
            unlock_pages(&self.buf);
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

    /// The first whole page inside `buf`, which no other allocation, such as
    /// another test's running alongside, can share.
    fn owned_page(buf: &[u8]) -> usize {
        let size = region::page::size();
        (buf.as_ptr() as usize / size + 1) * size
    }

    fn count(page: usize) -> Option<usize> {
        locked_pages().get(&page).map(|(count, _)| *count)
    }

    #[test]
    fn a_page_stays_locked_until_the_last_buffer_on_it_goes() {
        let size = region::page::size();
        let backing = vec![0u8; 3 * size];
        let page = owned_page(&backing);
        let at = page - backing.as_ptr() as usize;
        let (first, second) = (&backing[at..at + 16], &backing[at + 64..at + 80]);
        // Where the OS refuses to lock anything there is nothing to count.
        if !lock_pages(first) {
            return;
        }
        assert!(lock_pages(second));
        assert_eq!(count(page), Some(2));
        unlock_pages(first);
        assert_eq!(count(page), Some(1), "still locked for the second buffer");
        unlock_pages(second);
        assert_eq!(count(page), None, "unlocked with the last buffer");
    }

    #[test]
    fn a_buffer_across_two_pages_holds_both() {
        let size = region::page::size();
        let backing = vec![0u8; 4 * size];
        let page = owned_page(&backing);
        let at = page - backing.as_ptr() as usize;
        let across = &backing[at + size / 2..at + size + size / 2];
        if !lock_pages(across) {
            return;
        }
        assert_eq!((count(page), count(page + size)), (Some(1), Some(1)));
        unlock_pages(across);
        assert_eq!((count(page), count(page + size)), (None, None));
    }
}
