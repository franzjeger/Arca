//! WebAuthn passkey authenticator (ES256 / P-256).
//!
//! This is the *authenticator* half of WebAuthn: it generates and stores the
//! credential private key and produces the two ceremony outputs a relying party
//! needs — an **attestation object** at registration (`navigator.credentials
//! .create`) and an **assertion signature** at login (`.get`). The browser /
//! OS still drives the ceremony; on macOS the AutoFill Credential Provider
//! extension calls into this via the `vault-ffi` C ABI, handing us the already
//! computed `clientDataHash` and expecting these outputs back.
//!
//! Only audited RustCrypto primitives are used (`p256` for ECDSA, `sha2` for
//! SHA-256, `ciborium` for the CBOR structures). No custom elliptic-curve math.
//!
//! SECURITY: the credential private key is a P-256 scalar held as bytes and
//! wrapped in [`Zeroizing`]; it lives inside the encrypted vault like any other
//! secret and never leaves the device. Errors carry no key material.

use ciborium::value::{Integer, Value as Cbor};
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// AAGUID for this authenticator. All-zero is the conventional value for a
/// software authenticator that does not wish to be individually identifiable.
const AAGUID: [u8; 16] = [0u8; 16];

// authenticatorData flag bits (WebAuthn §6.1).
const FLAG_UP: u8 = 0x01; // user present
const FLAG_UV: u8 = 0x04; // user verified
const FLAG_BE: u8 = 0x08; // backup eligible
const FLAG_BS: u8 = 0x10; // backup state (currently backed up)
const FLAG_AT: u8 = 0x40; // attested credential data included

/// Length of a generated credential id, in bytes.
const CREDENTIAL_ID_LEN: usize = 16;

/// Outputs of creating a new passkey. The private key is stored in the vault;
/// everything else is handed back to the relying party.
pub struct NewPasskey {
    /// Random credential id the RP will present on future assertions.
    pub credential_id: Vec<u8>,
    /// SEC1 P-256 private scalar (32 bytes) — store this in the vault.
    pub private_key: Zeroizing<Vec<u8>>,
    /// CBOR attestation object (`fmt: "none"`) for `create()`.
    pub attestation_object: Vec<u8>,
    /// COSE-encoded public key (kept for reference / verification).
    pub cose_public_key: Vec<u8>,
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn int(n: i64) -> Cbor {
    Cbor::Integer(Integer::from(n))
}

/// COSE_Key (RFC 9052) for a P-256 public key used with ES256.
fn cose_ec2_public_key(vk: &VerifyingKey) -> Vec<u8> {
    let point = vk.to_encoded_point(false); // 0x04 || X || Y (uncompressed)
    let x = point.x().expect("P-256 point has X").to_vec();
    let y = point.y().expect("P-256 point has Y").to_vec();
    // kty(1)=EC2(2), alg(3)=ES256(-7), crv(-1)=P-256(1), x(-2), y(-3).
    let map = Cbor::Map(vec![
        (int(1), int(2)),
        (int(3), int(-7)),
        (int(-1), int(1)),
        (int(-2), Cbor::Bytes(x)),
        (int(-3), Cbor::Bytes(y)),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&map, &mut out).expect("COSE key encodes");
    out
}

/// Assemble authenticatorData (WebAuthn §6.1). With `attested`, the
/// attestedCredentialData block (aaguid + credential id + COSE key) is appended,
/// as required for registration.
///
/// UP (user present) is ALWAYS set — the caller must not invoke this without a
/// genuine user approval, so presence is real. UV (user verified) is set only
/// when `user_verified` (a real biometric/PIN check happened); asserting UV
/// without verification would be a false "the user was just verified" claim
/// that relying parties rely on for step-up defenses.
fn authenticator_data(
    rp_id: &str,
    sign_count: u32,
    attested: Option<(&[u8], &[u8])>, // (credential_id, cose_public_key)
    user_verified: bool,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(37);
    data.extend_from_slice(&sha256(rp_id.as_bytes())); // rpIdHash (32)
    let mut flags = FLAG_UP | FLAG_BE | FLAG_BS;
    if user_verified {
        flags |= FLAG_UV;
    }
    if attested.is_some() {
        flags |= FLAG_AT;
    }
    data.push(flags); // flags (1)
    data.extend_from_slice(&sign_count.to_be_bytes()); // signCount (4, big-endian)
    if let Some((cred_id, cose)) = attested {
        data.extend_from_slice(&AAGUID);
        data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        data.extend_from_slice(cred_id);
        data.extend_from_slice(cose);
    }
    data
}

/// Create a new passkey for `rp_id`. The sign counter starts at 0. `user_verified`
/// records whether a biometric/PIN verification gated this registration.
pub fn create(rp_id: &str, user_verified: bool) -> Result<NewPasskey> {
    let signing = SigningKey::random(&mut rand_core::OsRng);
    let verifying = VerifyingKey::from(&signing);
    let cose = cose_ec2_public_key(&verifying);

    let mut credential_id = vec![0u8; CREDENTIAL_ID_LEN];
    getrandom::getrandom(&mut credential_id).map_err(|_| Error::Random)?;

    let auth_data = authenticator_data(rp_id, 0, Some((&credential_id, &cose)), user_verified);

    // attestationObject = { fmt: "none", attStmt: {}, authData }.
    let att = Cbor::Map(vec![
        (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
        (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
        (Cbor::Text("authData".into()), Cbor::Bytes(auth_data)),
    ]);
    let mut attestation_object = Vec::new();
    ciborium::into_writer(&att, &mut attestation_object).expect("attestation encodes");

    Ok(NewPasskey {
        credential_id,
        private_key: Zeroizing::new(signing.to_bytes().to_vec()),
        attestation_object,
        cose_public_key: cose,
    })
}

/// Produce an assertion for a stored passkey. Returns
/// `(authenticatorData, DER-encoded ES256 signature)`; the signature is over
/// `authenticatorData || clientDataHash` per WebAuthn §6.3.3.
///
/// The signature counter is always **0**. These passkeys are backup-eligible
/// (synced with the vault), and WebAuthn L3 §6.1.1 recommends a constant 0 for
/// credentials that cannot guarantee a single monotonic counter across devices
/// — a non-monotonic counter would trip a relying party's clone detection.
///
/// `user_verified` must reflect whether a real biometric/PIN check gated this
/// assertion; the caller MUST require a genuine user approval before calling
/// this (user presence is otherwise a false claim).
pub fn assert(
    private_key: &[u8],
    rp_id: &str,
    client_data_hash: &[u8],
    user_verified: bool,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let signing = SigningKey::from_slice(private_key).map_err(|_| Error::Passkey)?;
    let auth_data = authenticator_data(rp_id, 0, None, user_verified);

    let mut signed = auth_data.clone();
    signed.extend_from_slice(client_data_hash);
    // ES256: SigningKey signs the SHA-256 digest of the message internally.
    let signature: Signature = signing.sign(&signed);

    Ok((auth_data, signature.to_der().as_bytes().to_vec()))
}

/// The public key (SEC1 uncompressed, 65 bytes) for a stored private key, so a
/// caller can verify or re-publish it without touching the secret scalar.
pub fn public_key_sec1(private_key: &[u8]) -> Result<Vec<u8>> {
    let signing = SigningKey::from_slice(private_key).map_err(|_| Error::Passkey)?;
    Ok(VerifyingKey::from(&signing)
        .to_encoded_point(false)
        .as_bytes()
        .to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;

    #[test]
    fn create_produces_a_valid_attestation_and_usable_key() {
        let pk = create("github.com", true).unwrap();
        assert_eq!(pk.credential_id.len(), CREDENTIAL_ID_LEN);
        assert_eq!(pk.private_key.len(), 32);

        // attestationObject is well-formed CBOR with fmt "none" and authData.
        let att: Cbor = ciborium::from_reader(&pk.attestation_object[..]).unwrap();
        let map = match att {
            Cbor::Map(m) => m,
            _ => panic!("attestation is not a map"),
        };
        let get = |k: &str| {
            map.iter()
                .find(|(key, _)| matches!(key, Cbor::Text(t) if t == k))
                .map(|(_, v)| v.clone())
        };
        assert!(matches!(get("fmt"), Some(Cbor::Text(t)) if t == "none"));
        let auth_data = match get("authData") {
            Some(Cbor::Bytes(b)) => b,
            _ => panic!("authData missing"),
        };
        // rpIdHash is SHA-256("github.com"); AT + UP + UV set at a verified
        // registration.
        assert_eq!(&auth_data[..32], &sha256(b"github.com"));
        assert_eq!(auth_data[32] & FLAG_AT, FLAG_AT);
        assert_eq!(auth_data[32] & FLAG_UP, FLAG_UP);
        assert_eq!(auth_data[32] & FLAG_UV, FLAG_UV);
        assert_eq!(&auth_data[33..37], &0u32.to_be_bytes()); // signCount == 0
    }

    #[test]
    fn uv_flag_reflects_verification_but_up_is_always_set() {
        // Not verified: UP set (presence required by the caller), UV clear.
        let (ad, _) = assert(
            &create("rp", false).unwrap().private_key,
            "rp",
            &[0u8; 32],
            false,
        )
        .unwrap();
        assert_eq!(ad[32] & FLAG_UP, FLAG_UP);
        assert_eq!(ad[32] & FLAG_UV, 0);
    }

    #[test]
    fn assertion_signature_verifies_against_the_public_key() {
        let pk = create("example.com", true).unwrap();
        let client_data_hash = sha256(b"{\"type\":\"webauthn.get\"}");

        let (auth_data, der_sig) =
            assert(&pk.private_key, "example.com", &client_data_hash, true).unwrap();

        // Reconstruct what was signed and verify with the credential's pubkey.
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&client_data_hash);
        let vk = VerifyingKey::from_sec1_bytes(&public_key_sec1(&pk.private_key).unwrap()).unwrap();
        let sig = Signature::from_der(&der_sig).unwrap();
        assert!(vk.verify(&signed, &sig).is_ok());

        // Assertion authData has NO attested-credential block, and the counter
        // is always 0 (synced credential; WebAuthn L3 §6.1.1).
        assert_eq!(auth_data.len(), 37);
        assert_eq!(auth_data[32] & FLAG_AT, 0);
        assert_eq!(&auth_data[33..37], &0u32.to_be_bytes());
    }

    #[test]
    fn a_wrong_key_does_not_verify() {
        let a = create("rp.example", true).unwrap();
        let b = create("rp.example", true).unwrap();
        let hash = sha256(b"challenge");
        let (auth_data, sig_a) = assert(&a.private_key, "rp.example", &hash, true).unwrap();

        let mut signed = auth_data;
        signed.extend_from_slice(&hash);
        // b's public key must reject a's signature.
        let vk_b =
            VerifyingKey::from_sec1_bytes(&public_key_sec1(&b.private_key).unwrap()).unwrap();
        let sig = Signature::from_der(&sig_a).unwrap();
        assert!(vk_b.verify(&signed, &sig).is_err());
    }

    #[test]
    fn bad_private_key_is_an_error_not_a_panic() {
        assert!(assert(&[0u8; 4], "rp", &[0u8; 32], true).is_err());
        assert!(public_key_sec1(&[9u8; 10]).is_err());
    }
}
