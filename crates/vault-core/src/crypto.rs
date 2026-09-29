//! Low-level cryptographic primitives, composed from audited RustCrypto crates.
//!
//! NOTHING in this module rolls its own crypto:
//!   * KDF  — Argon2id via the `argon2` crate.
//!   * AEAD — XChaCha20-Poly1305 via the `chacha20poly1305` crate.
//!   * RNG  — the operating system CSPRNG via `getrandom`.
//!
//! All AEAD operations bind an Additional Authenticated Data (AAD) value so
//! ciphertexts cannot be relocated (e.g. swapped between item ids, or a
//! key-wrap blob reinterpreted as an item).

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::header::KdfParams;
use crate::secret::{SymmetricKey, KEY_LEN};

/// XChaCha20-Poly1305 nonce length (192-bit; large enough to pick at random).
pub const NONCE_LEN: usize = 24;

/// A self-describing AEAD ciphertext: random nonce + ciphertext-with-tag.
///
/// Used both for wrapped keys and for individually-encrypted items.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AeadBlob {
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext with the appended 16-byte Poly1305 authentication tag.
    pub ciphertext: Vec<u8>,
}

/// Fill a buffer with cryptographically-secure random bytes from the OS.
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::Random)
}

/// Derive the 256-bit master key from the master password and the vault's
/// stored Argon2id parameters. Deterministic for a given (password, params).
pub fn derive_master_key(master_password: &str, params: &KdfParams) -> Result<SymmetricKey> {
    use argon2::{Algorithm, Argon2, Block, Params, Version};

    params.validate()?;
    let a2params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|_| Error::KeyDerivation)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, a2params);

    // Argon2 fills m_cost KiB with blocks computed from the password, and the
    // last of them give the key. The buffer it allocates itself is freed
    // without being wiped, so it works in this one, which is.
    let mut memory = Zeroizing::new(vec![Block::new(); argon2.params().block_count()]);

    // Derive into a zeroizing buffer, then move into the key newtype.
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into_with_memory(
            master_password.as_bytes(),
            &params.salt,
            out.as_mut_slice(),
            memory.as_mut_slice(),
        )
        .map_err(|_| Error::KeyDerivation)?;

    Ok(SymmetricKey::from_bytes(*out))
}

/// Encrypt `plaintext` under `key`, binding `aad`. Returns nonce + ciphertext.
pub fn seal(key: &SymmetricKey, plaintext: &[u8], aad: &[u8]) -> Result<AeadBlob> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());

    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;

    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        // An encryption error here is non-secret (size/internal), not credential-related.
        .map_err(|_| Error::Decryption)?;

    Ok(AeadBlob { nonce, ciphertext })
}

/// Decrypt and authenticate `blob` under `key`, requiring `aad` to match.
///
/// Returns the plaintext in a zeroizing buffer. A failure here means either
/// the wrong key was supplied or the data was tampered with; the two cases are
/// intentionally indistinguishable.
pub fn open(key: &SymmetricKey, blob: &AeadBlob, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());

    let plaintext = cipher
        .decrypt(
            &XNonce::from(blob.nonce),
            Payload {
                msg: &blob.ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Decryption)?;

    Ok(Zeroizing::new(plaintext))
}

/// Wrap (encrypt) `target_key` under `wrapping_key`, binding `aad`.
pub fn wrap_key(
    wrapping_key: &SymmetricKey,
    target_key: &SymmetricKey,
    aad: &[u8],
) -> Result<AeadBlob> {
    seal(wrapping_key, target_key.as_bytes(), aad)
}

/// Unwrap (decrypt) a key previously produced by [`wrap_key`].
pub fn unwrap_key(
    wrapping_key: &SymmetricKey,
    wrapped: &AeadBlob,
    aad: &[u8],
) -> Result<SymmetricKey> {
    let bytes = open(wrapping_key, wrapped, aad)?;
    if bytes.len() != KEY_LEN {
        return Err(Error::Decryption);
    }
    let mut arr = [0u8; KEY_LEN];
    arr.copy_from_slice(&bytes);
    Ok(SymmetricKey::from_bytes(arr))
}

#[cfg(test)]
mod tests {
    use zeroize::ZeroizeOnDrop;

    fn wiped_when_dropped<T: ZeroizeOnDrop>() {}

    /// The crates keep their own copies of the keys they are handed, and wipe
    /// them on drop only where they say so. chacha20poly1305 0.11 moved that
    /// behind a feature flag; this stops compiling if one is lost again.
    #[test]
    fn the_keys_the_crates_copy_are_wiped_when_dropped() {
        wiped_when_dropped::<chacha20poly1305::XChaCha20Poly1305>();
        wiped_when_dropped::<p256::ecdsa::SigningKey>();
        wiped_when_dropped::<ed25519_dalek::SigningKey>();
        // HMAC and HKDF keep their keyed state in these hashes' cores.
        wiped_when_dropped::<sha2::Sha256>();
        wiped_when_dropped::<sha1::Sha1>();
    }
}
