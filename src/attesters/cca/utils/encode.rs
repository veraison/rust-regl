// Copyright 2026 Contributors to the Veraison project
// SPDX-License-Identifier: Apache-2.0

//! CCA token construction from typed claims.
//!
//! Converts [`PlatformClaims`] and [`RealmClaims`] into a CBOR tag 399
//! token with two COSE_Sign1 signatures (platform + realm).
//!
//! The typed structs are converted to [`ciborium::Value`] via their
//! [`From`] implementations, then signed and wrapped.

use ccatoken::token::{
    PLATFORM_PROFILE as CCA_PLATFORM_PROFILE, REALM_PROFILE as CCA_REALM_PROFILE, is_valid_hash,
    is_valid_lifecycle, is_valid_measurement,
};
use ciborium::Value as CborValue;
use p384::ecdsa::SigningKey;
use rand_core::OsRng;

use super::constants::*;
use super::crypto::{build_rak_cose_key, compute_hash, load_p384_jwk, sign_cose_sign1};
use super::types::{CcaToken, PlatformClaims, RealmClaims};
use crate::attesters::cca::CcaError;

/// Fixed claim sizes from draft-ffm-rats-cca-token-01.
const IMPLEMENTATION_ID_SIZE: usize = 32;
const INSTANCE_ID_SIZE: usize = 33;
const PERSONALIZATION_VALUE_SIZE: usize = 64;
/// The realm delegated token carries exactly four extensible measurements.
const EXTENSIBLE_MEASUREMENTS_COUNT: usize = 4;

/// Build a full CCA token (CBOR tag 399) from typed claims and signing keys.
///
/// Claims are validated against draft-ffm-rats-cca-token-01 (profile
/// strings, claim sizes and cardinalities) and rejected before signing if
/// they violate it. The caller's nonce is injected as the realm challenge;
/// the platform challenge is derived from the RAK public key (per the CCA
/// spec) and injected into the platform claims before conversion.
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
    if p.profile != CCA_PLATFORM_PROFILE {
        return Err(CcaError::custom(format!(
            "cca-platform-profile: unsupported profile '{}'",
            p.profile
        )));
    }
    if !is_valid_lifecycle(p.lifecycle as i128) {
        return Err(CcaError::custom(format!(
            "invalid lifecycle value 0x{:04x}",
            p.lifecycle
        )));
    }
    match p.hash_algo_id.as_deref() {
        None => {
            return Err(CcaError::custom(
                "cca-platform-hash-algo-id: missing (required by draft-ffm-rats-cca-token-01)",
            ));
        }
        Some(algo) if !is_valid_hash(algo) => {
            return Err(CcaError::custom(format!(
                "platform: unsupported hash algorithm '{algo}'"
            )));
        }
        Some(_) => {}
    }
    if p.implementation_id.len() != IMPLEMENTATION_ID_SIZE {
        return Err(CcaError::custom(format!(
            "cca-platform-implementation-id: expected {IMPLEMENTATION_ID_SIZE} bytes, got {}",
            p.implementation_id.len()
        )));
    }
    if p.instance_id.len() != INSTANCE_ID_SIZE {
        return Err(CcaError::custom(format!(
            "cca-platform-instance-id: expected {INSTANCE_ID_SIZE} bytes, got {}",
            p.instance_id.len()
        )));
    }
    if p.sw_components.is_empty() {
        return Err(CcaError::custom(
            "cca-platform-sw-components: at least one SW component is required",
        ));
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
        if let Some(algo) = c.measurement_description.as_deref()
            && !is_valid_hash(algo)
        {
            return Err(CcaError::custom(format!(
                "sw component {i}: unsupported measurement-description '{algo}' \
                 (expected sha-256, sha-384 or sha-512)"
            )));
        }
    }
    Ok(())
}

fn validate_realm(r: &RealmClaims) -> Result<(), CcaError> {
    match r.profile.as_deref() {
        None => {
            return Err(CcaError::custom(
                "cca-realm-profile: required when the platform profile does not cover realm claims",
            ));
        }
        Some(profile) if profile != CCA_REALM_PROFILE => {
            return Err(CcaError::custom(format!(
                "cca-realm-profile: unsupported profile '{profile}'"
            )));
        }
        Some(_) => {}
    }
    if r.personalization_value.len() != PERSONALIZATION_VALUE_SIZE {
        return Err(CcaError::custom(format!(
            "cca-realm-personalization-value: expected {PERSONALIZATION_VALUE_SIZE} bytes, got {}",
            r.personalization_value.len()
        )));
    }
    if !is_valid_measurement(&r.initial_measurement) {
        return Err(CcaError::custom(format!(
            "invalid initial measurement length {}",
            r.initial_measurement.len()
        )));
    }
    if r.extensible_measurements.len() != EXTENSIBLE_MEASUREMENTS_COUNT {
        return Err(CcaError::custom(format!(
            "cca-realm-extensible-measurements: expected exactly {EXTENSIBLE_MEASUREMENTS_COUNT} entries, got {}",
            r.extensible_measurements.len()
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
    if !is_valid_hash(&r.hash_algo_id) {
        return Err(CcaError::custom(format!(
            "realm: unsupported hash algorithm '{}'",
            r.hash_algo_id
        )));
    }
    // `public_key_hash_algo_id` is validated by `compute_hash` in
    // `encode_cca_token` (called before this function), which reports the
    // algorithm name in its error message.
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

    // -----------------------------------------------------------------------
    // Test helpers for payload inspection and claims edits
    // -----------------------------------------------------------------------

    fn claims_with(edit: impl FnOnce(&mut serde_json::Value)) -> String {
        let mut doc: serde_json::Value =
            serde_json::from_str(&load_test_claims()).expect("bundled claims should parse");
        edit(&mut doc);
        doc.to_string()
    }

    fn b64(bytes: &[u8]) -> String {
        use base64::{Engine, engine::general_purpose};
        general_purpose::STANDARD.encode(bytes)
    }

    fn build_token_from(claims: &str) -> Result<Vec<u8>, CcaError> {
        SimulatedTokenBuilder::new(claims, &load_test_iak(), Some(&load_test_rak()))?
            .build_token(&[0u8; 64])
    }

    fn map_get(entries: &[(CborValue, CborValue)], key: u64) -> Option<&CborValue> {
        entries.iter().find_map(|(k, v)| match k {
            CborValue::Integer(i) if i128::from(*i) == i128::from(key) => Some(v),
            _ => None,
        })
    }

    /// Decode the platform token payload of a full CCA token.
    fn platform_payload(token: &[u8]) -> CborValue {
        let outer: CborValue = ciborium::from_reader(token).expect("token should be valid CBOR");
        let CborValue::Tag(tag, inner) = outer else {
            panic!("expected a CBOR tag");
        };
        assert_eq!(tag, CCA_TOKEN_TAG);
        let CborValue::Map(entries) = *inner else {
            panic!("expected a map under the tag");
        };
        let platform = map_get(&entries, CCA_PLATFORM_TOKEN_KEY)
            .expect("platform token claim")
            .clone();
        let CborValue::Bytes(cose_bytes) = platform else {
            panic!("platform token should be bytes");
        };
        let cose: CborValue =
            ciborium::from_reader(cose_bytes.as_slice()).expect("COSE_Sign1 should parse");
        let CborValue::Tag(18, cose_inner) = cose else {
            panic!("expected COSE_Sign1 tag 18");
        };
        let CborValue::Array(items) = *cose_inner else {
            panic!("expected a COSE_Sign1 array");
        };
        let payload = items
            .get(2)
            .and_then(|v| v.as_bytes())
            .expect("COSE_Sign1 payload");
        ciborium::from_reader(payload.as_slice()).expect("payload should parse")
    }

    fn first_sw_component(payload: &CborValue) -> &[(CborValue, CborValue)] {
        let CborValue::Map(entries) = payload else {
            panic!("platform payload should be a map");
        };
        let CborValue::Array(components) =
            map_get(entries, PLAT_SW_COMPONENTS).expect("sw components claim")
        else {
            panic!("sw components should be an array");
        };
        let CborValue::Map(first) = &components[0] else {
            panic!("first sw component should be a map");
        };
        first
    }

    // -----------------------------------------------------------------------
    // SW component version claim
    // -----------------------------------------------------------------------

    #[test]
    fn sw_component_version_is_encoded_as_key_4() {
        let claims = claims_with(|doc| {
            doc["cca-platform-token"]["cca-platform-sw-components"][0]["version"] =
                serde_json::Value::from("1.2.3");
        });
        let token = build_token_from(&claims).unwrap();
        let payload = platform_payload(&token);
        let first = first_sw_component(&payload);
        assert_eq!(
            map_get(first, SW_VERSION),
            Some(&CborValue::Text("1.2.3".to_owned()))
        );
    }

    #[test]
    fn sw_component_without_version_omits_key_4() {
        let token = build_token_from(&load_test_claims()).unwrap();
        let payload = platform_payload(&token);
        let first = first_sw_component(&payload);
        assert!(map_get(first, SW_VERSION).is_none());
    }

    // -----------------------------------------------------------------------
    // Validation against draft-ffm-rats-cca-token-01
    // -----------------------------------------------------------------------

    #[test]
    fn claims_with_invalid_personalization_value_are_rejected() {
        let claims = claims_with(|doc| {
            doc["cca-realm-delegated-token"]["cca-realm-personalization-value"] =
                b64(&[0u8; 8]).into();
        });
        let err = build_token_from(&claims).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("cca-realm-personalization-value"), "{msg}");
        assert!(msg.contains("64"), "{msg}");
    }

    #[test]
    fn claims_with_invalid_implementation_id_are_rejected() {
        let claims = claims_with(|doc| {
            doc["cca-platform-token"]["cca-platform-implementation-id"] = b64(&[0u8; 8]).into();
        });
        let err = build_token_from(&claims).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("cca-platform-implementation-id"), "{msg}");
        assert!(msg.contains("32"), "{msg}");
    }

    #[test]
    fn claims_with_invalid_instance_id_are_rejected() {
        let claims = claims_with(|doc| {
            doc["cca-platform-token"]["cca-platform-instance-id"] = b64(&[0u8; 8]).into();
        });
        let err = build_token_from(&claims).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("cca-platform-instance-id"), "{msg}");
        assert!(msg.contains("33"), "{msg}");
    }

    #[test]
    fn claims_with_empty_sw_components_are_rejected() {
        let claims = claims_with(|doc| {
            doc["cca-platform-token"]["cca-platform-sw-components"] = serde_json::json!([]);
        });
        let err = build_token_from(&claims).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("cca-platform-sw-components"), "{msg}");
    }

    #[test]
    fn claims_with_valid_measurement_description_are_accepted() {
        // The key 6 hash algorithm identifier may differ from the bundled
        // sha-256; sha-384 is in the accepted set and must survive encoding.
        let claims = claims_with(|doc| {
            doc["cca-platform-token"]["cca-platform-sw-components"][0]["measurement-description"] =
                serde_json::Value::from("sha-384");
        });
        let token = build_token_from(&claims).unwrap();
        let payload = platform_payload(&token);
        let first = first_sw_component(&payload);
        assert_eq!(
            map_get(first, SW_MEASUREMENT_DESC),
            Some(&CborValue::Text("sha-384".to_owned()))
        );
    }

    #[test]
    fn claims_with_invalid_measurement_description_are_rejected() {
        let claims = claims_with(|doc| {
            doc["cca-platform-token"]["cca-platform-sw-components"][0]["measurement-description"] =
                serde_json::Value::from("1.2.3");
        });
        let err = build_token_from(&claims).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("measurement-description"), "{msg}");
        assert!(msg.contains("1.2.3"), "{msg}");
    }

    #[test]
    fn claims_with_wrong_extensible_measurement_count_are_rejected() {
        let claims = claims_with(|doc| {
            let list = doc["cca-realm-delegated-token"]["cca-realm-extensible-measurements"]
                .as_array_mut()
                .expect("extensible measurements should be an array");
            list.truncate(3);
        });
        let err = build_token_from(&claims).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("cca-realm-extensible-measurements"), "{msg}");
    }

    #[test]
    fn claims_without_platform_hash_algo_are_rejected() {
        let claims = claims_with(|doc| {
            doc["cca-platform-token"]
                .as_object_mut()
                .expect("platform token should be an object")
                .remove("cca-platform-hash-algo-id");
        });
        let err = build_token_from(&claims).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("cca-platform-hash-algo-id"), "{msg}");
    }

    #[test]
    fn claims_with_unsupported_platform_hash_algo_are_rejected() {
        let claims = claims_with(|doc| {
            doc["cca-platform-token"]["cca-platform-hash-algo-id"] = serde_json::Value::from("md5");
        });
        let err = build_token_from(&claims).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("platform: unsupported hash algorithm"),
            "{msg}"
        );
        assert!(msg.contains("md5"), "{msg}");
    }

    #[test]
    fn claims_with_unsupported_realm_hash_algo_are_rejected() {
        let claims = claims_with(|doc| {
            doc["cca-realm-delegated-token"]["cca-realm-hash-algo-id"] =
                serde_json::Value::from("md5");
        });
        let err = build_token_from(&claims).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("realm: unsupported hash algorithm"), "{msg}");
        assert!(msg.contains("md5"), "{msg}");
    }

    #[test]
    fn claims_with_unknown_platform_profile_are_rejected() {
        let claims = claims_with(|doc| {
            doc["cca-platform-token"]["cca-platform-profile"] =
                serde_json::Value::from("tag:example.com,2026:x");
        });
        let err = build_token_from(&claims).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("cca-platform-profile"), "{msg}");
    }

    #[test]
    fn claims_without_realm_profile_are_rejected() {
        let claims = claims_with(|doc| {
            doc["cca-realm-delegated-token"]
                .as_object_mut()
                .expect("realm token should be an object")
                .remove("cca-realm-profile");
        });
        let err = build_token_from(&claims).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("cca-realm-profile"), "{msg}");
    }

    #[test]
    fn claims_with_unknown_realm_profile_are_rejected() {
        let claims = claims_with(|doc| {
            doc["cca-realm-delegated-token"]["cca-realm-profile"] =
                serde_json::Value::from("tag:example.com,2026:x");
        });
        let err = build_token_from(&claims).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("cca-realm-profile"), "{msg}");
    }

    #[test]
    fn claims_with_unknown_keys_are_rejected() {
        let claims = claims_with(|doc| {
            doc["cca-platform-token"]["cca-platform-bogus"] = serde_json::Value::from("x");
        });
        let err = build_token_from(&claims).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unknown field"), "{msg}");
        assert!(msg.contains("cca-platform-bogus"), "{msg}");
    }
}
