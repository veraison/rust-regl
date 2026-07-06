//! Cryptographic operations for CCA token signing and key management.
//!
//! Handles P-384 key loading, COSE key building, ES384 signing,
//! and SHA-2 hashing.

use coset::{AsCborValue, CoseKeyBuilder, CoseSign1Builder, HeaderBuilder};
use ecdsa::signature::Signer;
use p384::SecretKey;
use p384::ecdsa::{Signature, SigningKey};
use p384::elliptic_curve::JwkEcKey;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::attesters::cca::CcaError;

/// Load a P-384 JWK private key from a JSON string.
pub fn load_p384_jwk(jwk_json: &str, label: &str) -> Result<SigningKey, CcaError> {
    let jwk: JwkEcKey = jwk_json
        .parse()
        .map_err(|e| CcaError::custom(format!("parsing {label} JWK: {e}")))?;
    let secret = SecretKey::from_jwk(&jwk)
        .map_err(|e| CcaError::custom(format!("{label} JWK to secret key: {e}")))?;
    Ok(SigningKey::from(secret))
}

/// Build a COSE_Key (CBOR-encoded) from a P-384 signing key's public part.
///
/// Returns the raw CBOR bytes of the COSE_Key map.
pub fn build_rak_cose_key(rak: &SigningKey) -> Result<Vec<u8>, CcaError> {
    let verifying_key = rak.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let x = point
        .x()
        .ok_or_else(|| CcaError::custom("RAK public key x coordinate".to_string()))?;
    let y = point
        .y()
        .ok_or_else(|| CcaError::custom("RAK public key y coordinate".to_string()))?;

    let cose_key =
        CoseKeyBuilder::new_ec2_pub_key(coset::iana::EllipticCurve::P_384, x.to_vec(), y.to_vec())
            .algorithm(coset::iana::Algorithm::ES384)
            .build();

    let value = cose_key
        .to_cbor_value()
        .map_err(|e| CcaError::custom(format!("COSE_Key to CBOR value: {e}")))?;

    let mut buf = Vec::new();
    ciborium::into_writer(&value, &mut buf)
        .map_err(|e| CcaError::custom(format!("COSE_Key CBOR: {e}")))?;
    Ok(buf)
}

/// Create a COSE_Sign1 (CBOR tag 18) over `payload` signed with `key`.
///
/// Uses ES384 (ECDSA with SHA-384 on P-384) as the signing algorithm,
/// deterministic nonce generation per RFC 6979 (built into the p384 crate).
pub fn sign_cose_sign1(payload: &[u8], key: &SigningKey) -> Result<Vec<u8>, CcaError> {
    let protected = HeaderBuilder::new()
        .algorithm(coset::iana::Algorithm::ES384)
        .build();

    let cose = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload.to_vec())
        .create_signature(b"", |to_sign| {
            let sig: Signature = key.sign(to_sign);
            sig.to_bytes().to_vec()
        })
        .build();

    use coset::TaggedCborSerializable;
    let tagged = cose
        .to_tagged_vec()
        .map_err(|e| CcaError::custom(format!("COSE_Sign1 serialize: {e}")))?;
    Ok(tagged)
}

/// Check whether a hash algorithm string is supported.
///
/// Accepts `"sha-256"`, `"sha-384"`, and `"sha-512"` per the IANA Named
/// Information Hash Algorithm Registry and the RMM specification.
/// This is intentionally broader than `ccatoken::token::is_valid_hash`
/// which currently omits SHA-384.
pub fn is_supported_hash_alg(s: &str) -> bool {
    matches!(s, "sha-256" | "sha-384" | "sha-512")
}

/// Hash `data` using the algorithm named in `algo`.
///
/// Accepts `"sha-256"`, `"sha-384"`, and `"sha-512"` per the IANA Named
/// Information Hash Algorithm Registry referenced by the CCA token spec.
pub fn compute_hash(data: &[u8], algo: &str) -> Result<Vec<u8>, CcaError> {
    match algo {
        "sha-256" => Ok(Sha256::digest(data).to_vec()),
        "sha-384" => Ok(Sha384::digest(data).to_vec()),
        "sha-512" => Ok(Sha512::digest(data).to_vec()),
        other => Err(CcaError::custom(format!(
            "unsupported hash algorithm '{other}' for cca-realm-public-key-hash-algo-id; \
             expected sha-256, sha-384, or sha-512"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    // -----------------------------------------------------------------------
    // is_supported_hash_alg
    // -----------------------------------------------------------------------

    #[test]
    fn supported_hash_alg_accepts_sha256_sha384_sha512() {
        assert!(is_supported_hash_alg("sha-256"));
        assert!(is_supported_hash_alg("sha-384"));
        assert!(is_supported_hash_alg("sha-512"));
    }

    #[test]
    fn supported_hash_alg_rejects_unknown() {
        assert!(!is_supported_hash_alg("md5"));
        assert!(!is_supported_hash_alg("sha-1"));
        assert!(!is_supported_hash_alg("SHA-256"));
        assert!(!is_supported_hash_alg(""));
        assert!(!is_supported_hash_alg("sha384"));
    }

    // -----------------------------------------------------------------------
    // compute_hash
    // -----------------------------------------------------------------------

    #[test]
    fn compute_hash_sha256_produces_32_bytes() {
        let hash = compute_hash(b"hello", "sha-256").unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn compute_hash_sha384_produces_48_bytes() {
        let hash = compute_hash(b"hello", "sha-384").unwrap();
        assert_eq!(hash.len(), 48);
    }

    #[test]
    fn compute_hash_sha512_produces_64_bytes() {
        let hash = compute_hash(b"hello", "sha-512").unwrap();
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn compute_hash_is_deterministic() {
        let a = compute_hash(b"same input", "sha-256").unwrap();
        let b = compute_hash(b"same input", "sha-256").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn compute_hash_different_inputs_differ() {
        let a = compute_hash(b"input A", "sha-256").unwrap();
        let b = compute_hash(b"input B", "sha-256").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn compute_hash_unknown_algorithm_returns_error() {
        let err = compute_hash(b"data", "md5").unwrap_err();
        assert!(format!("{err}").contains("unsupported hash algorithm"));
    }

    // -----------------------------------------------------------------------
    // sign_cose_sign1
    // -----------------------------------------------------------------------

    #[test]
    fn sign_cose_sign1_produces_non_empty_output() {
        let key = SigningKey::random(&mut OsRng);
        let payload = b"test payload for signing";
        let signed = sign_cose_sign1(payload, &key).unwrap();
        assert!(!signed.is_empty());
    }

    #[test]
    fn sign_cose_sign1_is_deterministic() {
        let key = SigningKey::random(&mut OsRng);
        let payload = b"deterministic test";
        let sig1 = sign_cose_sign1(payload, &key).unwrap();
        let sig2 = sign_cose_sign1(payload, &key).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn sign_cose_sign1_different_payloads_differ() {
        let key = SigningKey::random(&mut OsRng);
        let sig_a = sign_cose_sign1(b"payload A", &key).unwrap();
        let sig_b = sign_cose_sign1(b"payload B", &key).unwrap();
        assert_ne!(sig_a, sig_b);
    }

    // -----------------------------------------------------------------------
    // build_rak_cose_key
    // -----------------------------------------------------------------------

    #[test]
    fn build_rak_cose_key_produces_cbor() {
        let key = SigningKey::random(&mut OsRng);
        let cose_key_bytes = build_rak_cose_key(&key).unwrap();
        assert!(!cose_key_bytes.is_empty());
    }

    #[test]
    fn build_rak_cose_key_is_deterministic() {
        let key = SigningKey::random(&mut OsRng);
        let k1 = build_rak_cose_key(&key).unwrap();
        let k2 = build_rak_cose_key(&key).unwrap();
        assert_eq!(k1, k2);
    }

    // -----------------------------------------------------------------------
    // load_p384_jwk
    // -----------------------------------------------------------------------

    fn test_iak_jwk() -> &'static str {
        r#"{
            "crv": "P-384",
            "d": "isCQyZWGn2GsE1jwKwIaJqtus4YgOsc1186YVVOLkfdMRLDVgCQ--3maKT3LqgiZ",
            "kty": "EC",
            "x": "IShnxS4rlQiwpCCpBWDzlNLfqiG911FP8akBr-fh94uxHU5m-Kijivp2r2oxxN6M",
            "y": "hM4tr8mWQli1P61xh3T0ViDREbF26DGOEYfbAjWjGNN7pZf-6A4OTHYqEryz6m7U"
        }"#
    }

    #[test]
    fn load_p384_jwk_valid_key_succeeds() {
        let key = load_p384_jwk(test_iak_jwk(), "IAK");
        assert!(key.is_ok(), "expected Ok, got {:?}", key.err());
    }

    #[test]
    fn load_p384_jwk_invalid_json_returns_error() {
        let err = load_p384_jwk("not-json", "IAK").unwrap_err();
        assert!(format!("{err}").contains("parsing IAK JWK"));
    }

    #[test]
    fn load_p384_jwk_label_appears_in_error() {
        let err = load_p384_jwk("not-json", "RAK").unwrap_err();
        assert!(format!("{err}").contains("RAK"));
    }
}
