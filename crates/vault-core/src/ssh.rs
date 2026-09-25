//! SSH agent key primitives (Ed25519 / `ssh-ed25519`).
//!
//! Arca acts as the *authenticator* for SSH the same way [`crate::passkey`] does
//! for WebAuthn: the private key is generated here, stored in the encrypted
//! vault, and **never leaves the device**. A consumer (an ssh client, via the
//! agent protocol) hands us the bytes to sign and gets back only a signature.
//!
//! Only the audited `ed25519-dalek` primitive is used for the signature. The
//! surrounding OpenSSH *wire encoding* is the simple, self-describing
//! length-prefixed-`string` framing from RFC 4251 §5, assembled explicitly here
//! and tested byte-for-byte against the `ssh` CLI. There is no custom crypto.
//!
//! SECURITY: the private key is a 32-byte Ed25519 seed held in [`Zeroizing`] and
//! sealed in the vault like any other secret. Errors carry no key material.

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// The only key algorithm this module handles, as it appears on the wire.
/// Exposed so callers store the matching `key_type` on the vault item.
pub const ALGORITHM: &str = "ssh-ed25519";
const ALG: &[u8] = ALGORITHM.as_bytes();

/// Length of an Ed25519 seed (the stored private key), in bytes.
const SEED_LEN: usize = 32;

/// Outputs of generating a new SSH key. The seed is stored in the vault;
/// everything else is public and handed to the UI / relying host.
pub struct NewSshKey {
    /// Ed25519 seed (32 bytes) — the secret. Store this in the vault.
    pub private_key: Zeroizing<Vec<u8>>,
    /// OpenSSH public-key blob (`string "ssh-ed25519" || string pubkey`). This
    /// is the identity blob the agent advertises and the base64 body of the
    /// `authorized_keys` line.
    pub public_blob: Vec<u8>,
    /// A ready-to-paste `authorized_keys` line: `ssh-ed25519 <base64> <comment>`.
    pub authorized_key: String,
    /// OpenSSH SHA-256 fingerprint (`SHA256:<base64-nopad>`), as shown by
    /// `ssh-add -l` and `ssh-keygen -l`.
    pub fingerprint: String,
}

/// Append an SSH `string`: a big-endian u32 length followed by the bytes
/// (RFC 4251 §5). All call sites here pass small, fixed-size values; the
/// assertion guards against a future variable-length reuse silently truncating
/// the length prefix.
fn push_string(buf: &mut Vec<u8>, s: &[u8]) {
    debug_assert!(
        s.len() <= u32::MAX as usize,
        "ssh string exceeds u32 length"
    );
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s);
}

/// The OpenSSH public-key blob for a raw 32-byte Ed25519 public key.
fn encode_public_blob(public_key: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(4 + ALG.len() + 4 + public_key.len());
    push_string(&mut b, ALG);
    push_string(&mut b, public_key);
    b
}

/// Reconstruct the signing key from a stored seed, zeroizing the temporary copy.
fn signing_key(private_seed: &[u8]) -> Result<SigningKey> {
    let seed: Zeroizing<[u8; SEED_LEN]> =
        Zeroizing::new(private_seed.try_into().map_err(|_| Error::Ssh)?);
    Ok(SigningKey::from_bytes(&seed))
}

/// The `authorized_keys` line for a public blob (base64 of the blob + comment).
///
/// The comment is trimmed and MUST NOT contain interior control characters:
/// a newline (or other control byte) would split the single "ready-to-paste"
/// line into two, letting a crafted comment inject a second `authorized_keys`
/// entry. Such a comment is rejected rather than silently corrupting the line.
/// Spaces are allowed (OpenSSH treats the whole remainder as the comment).
fn authorized_key_line(public_blob: &[u8], comment: &str) -> Result<String> {
    let comment = comment.trim();
    if comment.chars().any(char::is_control) {
        return Err(Error::Ssh);
    }
    let b64 = data_encoding::BASE64.encode(public_blob);
    Ok(if comment.is_empty() {
        format!("ssh-ed25519 {b64}")
    } else {
        format!("ssh-ed25519 {b64} {comment}")
    })
}

/// The OpenSSH SHA-256 fingerprint of a public-key blob.
pub fn fingerprint(public_blob: &[u8]) -> String {
    let digest = Sha256::digest(public_blob);
    format!("SHA256:{}", data_encoding::BASE64_NOPAD.encode(&digest))
}

/// Generate a fresh Ed25519 key. `comment` is the free-text label OpenSSH shows
/// (conventionally `user@host`); it is not secret and may be empty, but must not
/// contain control characters (see [`authorized_key_line`]).
///
/// The seed comes straight from the OS CSPRNG via `getrandom`, which surfaces an
/// entropy failure as an error rather than panicking.
pub fn generate(comment: &str) -> Result<NewSshKey> {
    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    getrandom::getrandom(&mut seed[..]).map_err(|_| Error::Random)?;
    let signing = SigningKey::from_bytes(&seed);
    let public_blob = encode_public_blob(signing.verifying_key().as_bytes());
    let authorized_key = authorized_key_line(&public_blob, comment)?;
    let fingerprint = fingerprint(&public_blob);
    Ok(NewSshKey {
        private_key: Zeroizing::new(signing.to_bytes().to_vec()),
        public_blob,
        authorized_key,
        fingerprint,
    })
}

/// Sign `data` with the stored key, returning an OpenSSH *signature blob*
/// (`string "ssh-ed25519" || string signature`) as the agent protocol's
/// SIGN_RESPONSE expects. The caller supplies the exact bytes to sign; Ed25519
/// signs them directly (no pre-hash), per RFC 8709.
pub fn sign(private_seed: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let signing = signing_key(private_seed)?;
    let signature = signing.sign(data);
    let mut blob = Vec::with_capacity(4 + ALG.len() + 4 + 64);
    push_string(&mut blob, ALG);
    push_string(&mut blob, &signature.to_bytes());
    Ok(blob)
}

/// The OpenSSH public-key blob for a stored seed (for advertising the identity
/// without touching the private half beyond deriving the public key).
pub fn public_blob(private_seed: &[u8]) -> Result<Vec<u8>> {
    let signing = signing_key(private_seed)?;
    Ok(encode_public_blob(signing.verifying_key().as_bytes()))
}

/// A ready-to-paste `authorized_keys` line for a stored seed. Errors if the
/// comment contains control characters (see [`authorized_key_line`]).
pub fn authorized_key(private_seed: &[u8], comment: &str) -> Result<String> {
    authorized_key_line(&public_blob(private_seed)?, comment)
}

/// A ready-to-paste `authorized_keys` line from a public-key blob (no secret
/// needed — used to display a stored key's public half). Errors if the comment
/// contains control characters (see [`authorized_key_line`]).
pub fn authorized_key_from_blob(public_blob: &[u8], comment: &str) -> Result<String> {
    authorized_key_line(public_blob, comment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    /// Read one SSH `string` from `buf` at `pos`, returning (bytes, next_pos).
    fn read_string(buf: &[u8], pos: usize) -> (Vec<u8>, usize) {
        let len = u32::from_be_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
        let start = pos + 4;
        (buf[start..start + len].to_vec(), start + len)
    }

    #[test]
    fn generated_signature_verifies_against_the_public_key() {
        let key = generate("frank@sybr").unwrap();
        assert_eq!(key.private_key.len(), SEED_LEN);

        // Public blob decodes to alg + raw 32-byte key.
        let (alg, p) = read_string(&key.public_blob, 0);
        let (pubkey, end) = read_string(&key.public_blob, p);
        assert_eq!(alg, ALG);
        assert_eq!(pubkey.len(), 32);
        assert_eq!(end, key.public_blob.len());

        // Sign an arbitrary challenge, decode the signature blob, verify.
        let challenge = b"session-id||SSH_MSG_USERAUTH_REQUEST||...";
        let sig_blob = sign(&key.private_key, challenge).unwrap();
        let (sig_alg, sp) = read_string(&sig_blob, 0);
        let (raw_sig, send) = read_string(&sig_blob, sp);
        assert_eq!(sig_alg, ALG);
        assert_eq!(raw_sig.len(), 64);
        assert_eq!(send, sig_blob.len());

        let vk = VerifyingKey::from_bytes(pubkey.as_slice().try_into().unwrap()).unwrap();
        let sig = Signature::from_slice(&raw_sig).unwrap();
        assert!(vk.verify(challenge, &sig).is_ok());
    }

    #[test]
    fn a_different_key_does_not_verify() {
        let a = generate("a").unwrap();
        let b = generate("b").unwrap();
        let msg = b"challenge";
        let sig_blob = sign(&a.private_key, msg).unwrap();
        let (_, sp) = read_string(&sig_blob, 0);
        let (raw_sig, _) = read_string(&sig_blob, sp);

        let (_, p) = read_string(&b.public_blob, 0);
        let (pubkey_b, _) = read_string(&b.public_blob, p);
        let vk_b = VerifyingKey::from_bytes(pubkey_b.as_slice().try_into().unwrap()).unwrap();
        let sig = Signature::from_slice(&raw_sig).unwrap();
        // b's public key must reject a's signature.
        assert!(vk_b.verify(msg, &sig).is_err());
    }

    #[test]
    fn authorized_key_line_is_well_formed() {
        let key = generate("frank@host").unwrap();
        let line = key.authorized_key;
        let parts: Vec<&str> = line.split(' ').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "ssh-ed25519");
        assert_eq!(parts[2], "frank@host");
        // The base64 body decodes back to exactly the public blob.
        let decoded = data_encoding::BASE64.decode(parts[1].as_bytes()).unwrap();
        assert_eq!(decoded, key.public_blob);
    }

    #[test]
    fn empty_comment_omits_the_trailing_field() {
        let key = generate("").unwrap();
        assert_eq!(key.authorized_key.split(' ').count(), 2);
        assert!(key.authorized_key.starts_with("ssh-ed25519 "));
    }

    #[test]
    fn comment_with_spaces_is_allowed() {
        // OpenSSH treats the whole remainder of the line as the comment.
        let key = generate("frank on the office laptop").unwrap();
        assert!(key.authorized_key.ends_with(" frank on the office laptop"));
    }

    #[test]
    fn comment_with_control_chars_is_rejected() {
        // A newline would split the "ready-to-paste" line and inject a second
        // authorized_keys entry; interior control chars must be refused.
        for bad in ["laptop\nssh-ed25519 AAAA... attacker", "a\rb", "a\tb"] {
            assert!(matches!(generate(bad), Err(Error::Ssh)), "accepted {bad:?}");
        }
        // A stored key with a poisoned comment also refuses to emit a line.
        let seed = generate("ok").unwrap().private_key;
        assert!(matches!(authorized_key(&seed, "x\ny"), Err(Error::Ssh)));
    }

    #[test]
    fn fingerprint_has_the_openssh_shape() {
        let key = generate("x").unwrap();
        assert_eq!(key.fingerprint, fingerprint(&key.public_blob));
        assert!(key.fingerprint.starts_with("SHA256:"));
        // SHA-256 (32 bytes) as unpadded base64 is 43 chars.
        assert_eq!(key.fingerprint.len(), "SHA256:".len() + 43);
    }

    #[test]
    fn derived_public_blob_matches_generation() {
        let key = generate("c").unwrap();
        assert_eq!(public_blob(&key.private_key).unwrap(), key.public_blob);
        assert_eq!(
            authorized_key(&key.private_key, "c").unwrap(),
            key.authorized_key
        );
    }

    #[test]
    fn bad_seed_is_an_error_not_a_panic() {
        assert!(matches!(sign(&[0u8; 4], b"x"), Err(Error::Ssh)));
        assert!(matches!(public_blob(&[9u8; 100]), Err(Error::Ssh)));
    }
}
