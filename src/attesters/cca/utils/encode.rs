// Copyright 2026 Contributors to the Veraison project
// SPDX-License-Identifier: Apache-2.0

//! CCA token construction from typed claims.
//!
//! Converts [`PlatformClaims`] and [`RealmClaims`] into a CBOR tag 399
//! token with two COSE_Sign1 signatures (platform + realm).
//!
//! The typed structs are converted to [`ciborium::Value`] via their
//! [`From`] implementations, then signed and wrapped.

use ccatoken::token::{is_valid_lifecycle, is_valid_measurement};
use ciborium::Value as CborValue;
use p384::ecdsa::SigningKey;
use rand_core::OsRng;

use super::constants::*;
use super::crypto::{
    build_rak_cose_key, compute_hash, is_supported_hash_alg, load_p384_jwk, sign_cose_sign1,
};
use super::types::{CcaToken, PlatformClaims, RealmClaims};
use crate::attesters::cca::CcaError;

/// Build a full CCA token (CBOR tag 399) from typed claims and signing keys.
///
/// The caller's nonce is injected as the realm challenge. The platform challenge
/// is derived from the RAK public key (per the CCA spec) and injected into the
/// platform claims before conversion.
pub fn encode_cca_token(
    mut platform_claims: PlatformClaims,
    mut realm_claims: RealmClaims,
    iak: &SigningKey,
    rak: &SigningKey,
    nonce: &[u8],
) -> Result<Vec<u8>, CcaError> {
    // Build the RAK COSE_Key and derive the platform challenge from it.
    let rak_cose_key_bytes = build_rak_cose_key(rak)?;
    let rak_hash_algo = &realm_claims.public_key_hash_algo_id;
    let platform_challenge = compute_hash(&rak_cose_key_bytes, rak_hash_algo)?;

    // Validate typed fields before encoding.
    validate_platform(&platform_claims)?;
    validate_realm(&realm_claims)?;

    // Inject runtime fields.
    platform_claims.challenge = platform_challenge;
    realm_claims.challenge = nonce.to_vec();
    realm_claims.public_key = rak_cose_key_bytes;

    // Convert typed claims into CBOR map values.
    // The From<PlatformClaims> for CborValue and From<RealmClaims> for CborValue
    // implementations (in types.rs) map each claim field to its spec-defined
    // CBOR integer key and value type.
    let platform_payload_raw: CborValue = platform_claims.into();
    let realm_payload_raw: CborValue = realm_claims.into();

    // Serialize to CBOR bytes.
    let mut platform_payload = Vec::new();
    ciborium::into_writer(&platform_payload_raw, &mut platform_payload)
        .map_err(|e| CcaError::custom(format!("platform payload CBOR: {e}")))?;
    let mut realm_payload = Vec::new();
    ciborium::into_writer(&realm_payload_raw, &mut realm_payload)
        .map_err(|e| CcaError::custom(format!("realm payload CBOR: {e}")))?;

    // Sign both payloads.
    let platform_cose = sign_cose_sign1(&platform_payload, iak)?;
    let realm_cose = sign_cose_sign1(&realm_payload, rak)?;

    // Wrap in CBOR tag 399.
    let outer = CborValue::Tag(
        CCA_TOKEN_TAG,
        Box::new(CborValue::Map(vec![
            (
                CborValue::Integer(CCA_PLATFORM_TOKEN_KEY.into()),
                CborValue::Bytes(platform_cose),
            ),
            (
                CborValue::Integer(CCA_REALM_TOKEN_KEY.into()),
                CborValue::Bytes(realm_cose),
            ),
        ])),
    );

    let mut buf = Vec::new();
    ciborium::into_writer(&outer, &mut buf)
        .map_err(|e| CcaError::custom(format!("CBOR encode: {e}")))?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

fn validate_platform(p: &PlatformClaims) -> Result<(), CcaError> {
    if !is_valid_lifecycle(p.lifecycle as i128) {
        return Err(CcaError::custom(format!(
            "invalid lifecycle value 0x{:04x}",
            p.lifecycle
        )));
    }
    if let Some(ref algo) = p.hash_algo_id
        && !is_supported_hash_alg(algo)
    {
        return Err(CcaError::custom(format!(
            "platform: unsupported hash algorithm '{algo}'"
        )));
    }
    for (i, c) in p.sw_components.iter().enumerate() {
        if !is_valid_measurement(&c.measurement_value) {
            return Err(CcaError::custom(format!(
                "sw component {i}: invalid measurement length {}",
                c.measurement_value.len()
            )));
        }
        if !is_valid_measurement(&c.signer_id) {
            return Err(CcaError::custom(format!(
                "sw component {i}: invalid signer ID length {}",
                c.signer_id.len()
            )));
        }
    }
    Ok(())
}

fn validate_realm(r: &RealmClaims) -> Result<(), CcaError> {
    if !is_valid_measurement(&r.initial_measurement) {
        return Err(CcaError::custom(format!(
            "invalid initial measurement length {}",
            r.initial_measurement.len()
        )));
    }
    for (i, m) in r.extensible_measurements.iter().enumerate() {
        if !is_valid_measurement(m) {
            return Err(CcaError::custom(format!(
                "extensible measurement {i}: invalid length {}",
                m.len()
            )));
        }
    }
    if !is_supported_hash_alg(&r.hash_algo_id) {
        return Err(CcaError::custom(format!(
            "realm: unsupported hash algorithm '{}'",
            r.hash_algo_id
        )));
    }
    if !is_supported_hash_alg(&r.public_key_hash_algo_id) {
        return Err(CcaError::custom(format!(
            "realm: unsupported public key hash algo '{}'",
            r.public_key_hash_algo_id
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SimulatedTokenBuilder - convenience wrapper
// ---------------------------------------------------------------------------

/// Token builder that holds parsed claims and signing keys.
///
/// Two construction paths are available:
///
/// | Constructor | IAK | RAK |
/// |---|---|---|
/// | [`new`](SimulatedTokenBuilder::new) | JWK JSON string | JWK JSON string (optional) |
/// | [`with_keys`](SimulatedTokenBuilder::with_keys) | [`SigningKey`] | [`SigningKey`] |
///
/// Both delegate to [`encode_cca_token`] for the actual CBOR construction
/// and signing.
#[derive(Debug)]
pub(crate) struct SimulatedTokenBuilder {
    platform_claims: PlatformClaims,
    realm_claims: RealmClaims,
    iak: SigningKey,
    rak: SigningKey,
}

impl SimulatedTokenBuilder {
    /// Create a builder from JSON claims and JWK key text.
    ///
    /// If `rak_jwk` is `None`, a random RAK is generated.
    pub fn new(claims_json: &str, iak_jwk: &str, rak_jwk: Option<&str>) -> Result<Self, CcaError> {
        let claims: CcaToken = serde_json::from_str(claims_json)
            .map_err(|e| CcaError::custom(format!("parsing claims JSON: {e}")))?;

        let iak = load_p384_jwk(iak_jwk, "IAK")?;
        let rak = match rak_jwk {
            Some(jwk) => load_p384_jwk(jwk, "RAK")?,
            None => SigningKey::random(&mut OsRng),
        };

        Ok(Self {
            platform_claims: claims.platform,
            realm_claims: claims.realm,
            iak,
            rak,
        })
    }

    /// Create a builder from JSON claims and P-384 [`SigningKey`]s.
    ///
    /// This constructor accepts COSE keys directly, skipping the JWK
    /// parsing step.  The `rak` key is used for both signing the realm
    /// token and deriving the platform challenge (per the CCA spec).
    pub fn with_keys(
        claims_json: &str,
        iak: SigningKey,
        rak: SigningKey,
    ) -> Result<Self, CcaError> {
        let claims: CcaToken = serde_json::from_str(claims_json)
            .map_err(|e| CcaError::custom(format!("parsing claims JSON: {e}")))?;

        Ok(Self {
            platform_claims: claims.platform,
            realm_claims: claims.realm,
            iak,
            rak,
        })
    }

    pub fn build_token(&self, nonce: &[u8]) -> Result<Vec<u8>, CcaError> {
        encode_cca_token(
            self.platform_claims.clone(),
            self.realm_claims.clone(),
            &self.iak,
            &self.rak,
            nonce,
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn load_test_claims() -> String {
        std::fs::read_to_string("test-data/cca-claims.json").unwrap()
    }

    fn load_test_iak() -> String {
        std::fs::read_to_string("test-data/iak.jwk").unwrap()
    }

    fn load_test_rak() -> String {
        std::fs::read_to_string("test-data/rak.jwk").unwrap()
    }

    // -----------------------------------------------------------------------
    // SimulatedTokenBuilder::new
    // -----------------------------------------------------------------------

    #[test]
    fn builder_new_with_test_data_succeeds() {
        let claims = load_test_claims();
        let iak = load_test_iak();
        let rak = load_test_rak();
        let builder = SimulatedTokenBuilder::new(&claims, &iak, Some(&rak));
        assert!(builder.is_ok(), "expected Ok, got {:?}", builder.err());
    }

    #[test]
    fn builder_new_without_rak_generates_key() {
        let claims = load_test_claims();
        let iak = load_test_iak();
        let builder = SimulatedTokenBuilder::new(&claims, &iak, None).unwrap();
        let token = builder.build_token(&[0u8; 64]).unwrap();
        assert!(!token.is_empty());
    }

    #[test]
    fn builder_new_with_invalid_claims_returns_error() {
        let iak = load_test_iak();
        let rak = load_test_rak();
        let err = SimulatedTokenBuilder::new("not-json", &iak, Some(&rak)).unwrap_err();
        assert!(format!("{err}").contains("parsing claims JSON"));
    }

    #[test]
    fn builder_new_with_invalid_iak_returns_error() {
        let claims = load_test_claims();
        let rak = load_test_rak();
        let err = SimulatedTokenBuilder::new(&claims, "not-a-jwk", Some(&rak)).unwrap_err();
        assert!(format!("{err}").contains("IAK"));
    }

    #[test]
    fn builder_new_with_invalid_rak_returns_error() {
        let claims = load_test_claims();
        let iak = load_test_iak();
        let err = SimulatedTokenBuilder::new(&claims, &iak, Some("not-a-jwk")).unwrap_err();
        assert!(format!("{err}").contains("RAK"));
    }

    // -----------------------------------------------------------------------
    // SimulatedTokenBuilder::with_keys
    // -----------------------------------------------------------------------

    #[test]
    fn builder_with_keys_succeeds() {
        let claims = load_test_claims();
        let iak = SigningKey::random(&mut OsRng);
        let rak = SigningKey::random(&mut OsRng);
        let builder = SimulatedTokenBuilder::with_keys(&claims, iak, rak);
        assert!(builder.is_ok());
    }

    // -----------------------------------------------------------------------
    // build_token
    // -----------------------------------------------------------------------

    #[test]
    fn build_token_produces_valid_cbor_tag_399() {
        let claims = load_test_claims();
        let iak = load_test_iak();
        let rak = load_test_rak();
        let builder = SimulatedTokenBuilder::new(&claims, &iak, Some(&rak)).unwrap();
        let token = builder.build_token(&[0u8; 64]).unwrap();
        assert!(!token.is_empty());

        // Verify outer structure: must be a CBOR tag 399 containing a map.
        let value: CborValue =
            ciborium::from_reader(token.as_slice()).expect("token should be valid CBOR");
        match value {
            CborValue::Tag(tag, inner) => {
                assert_eq!(tag, CCA_TOKEN_TAG);
                match *inner {
                    CborValue::Map(ref entries) => {
                        assert_eq!(entries.len(), 2);
                        let has_platform = entries.iter().any(|(k, _)| {
                            if let CborValue::Integer(i) = k {
                                i128::from(*i) == CCA_PLATFORM_TOKEN_KEY as i128
                            } else {
                                false
                            }
                        });
                        let has_realm = entries.iter().any(|(k, _)| {
                            if let CborValue::Integer(i) = k {
                                i128::from(*i) == CCA_REALM_TOKEN_KEY as i128
                            } else {
                                false
                            }
                        });
                        assert!(has_platform, "missing platform token key");
                        assert!(has_realm, "missing realm token key");
                    }
                    other => panic!("expected Map under tag, got {other:?}"),
                }
            }
            other => panic!("expected Tag, got {other:?}"),
        }
    }

    #[test]
    fn build_token_is_deterministic() {
        let claims = load_test_claims();
        let iak = load_test_iak();
        let rak = load_test_rak();
        let builder = SimulatedTokenBuilder::new(&claims, &iak, Some(&rak)).unwrap();
        let token1 = builder.build_token(&[0u8; 64]).unwrap();
        let token2 = builder.build_token(&[0u8; 64]).unwrap();
        assert_eq!(token1, token2);
    }

    #[test]
    fn build_token_different_nonce_produces_different_token() {
        let claims = load_test_claims();
        let iak = load_test_iak();
        let rak = load_test_rak();
        let builder = SimulatedTokenBuilder::new(&claims, &iak, Some(&rak)).unwrap();
        let token_a = builder.build_token(&[0u8; 64]).unwrap();
        let token_b = builder.build_token(&[1u8; 64]).unwrap();
        assert_ne!(token_a, token_b);
    }

    // -----------------------------------------------------------------------
    // encode_cca_token
    // -----------------------------------------------------------------------

    #[test]
    fn encode_cca_token_produces_non_empty_output() {
        let claims = load_test_claims();
        let iak = load_test_iak();
        let rak = load_test_rak();
        let builder = SimulatedTokenBuilder::new(&claims, &iak, Some(&rak)).unwrap();
        let token = encode_cca_token(
            builder.platform_claims,
            builder.realm_claims,
            &builder.iak,
            &builder.rak,
            &[0u8; 64],
        )
        .unwrap();
        assert!(!token.is_empty());
    }
}
