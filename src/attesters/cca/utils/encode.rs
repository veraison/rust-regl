// Copyright 2026 Contributors to the Veraison project
// SPDX-License-Identifier: Apache-2.0

//! CCA token construction from typed claims.
//!
//! Converts [`PlatformClaims`] and [`RealmClaims`] into a CCA token with
//! two COSE_Sign1 signatures (platform + realm). Two framings are produced:
//!
//! * [`encode_cca_token_legacy`] - the CBOR tag 399 collection of
//!   draft-ffm-rats-cca-token-01 (2023 profiles).
//! * [`encode_cca_token`] - the CBOR tag 907 CMW collection of
//!   draft-ffm-03 (2024 profiles).
//!
//! The typed structs are converted to [`ciborium::Value`] via their
//! [`From`] implementations, then signed and wrapped.

use ccatoken::token::{
    PLATFORM_PROFILE as CCA_PLATFORM_PROFILE, PLATFORM_PROFILE_2024 as CCA_PLATFORM_PROFILE_2024,
    REALM_PROFILE as CCA_REALM_PROFILE, REALM_PROFILE_2024 as CCA_REALM_PROFILE_2024,
    is_valid_hash, is_valid_lifecycle, is_valid_measurement,
};
use ciborium::Value as CborValue;
use p384::ecdsa::SigningKey;
use rand_core::OsRng;

use super::constants::*;
use super::crypto::{build_rak_cose_key, compute_hash, load_p384_jwk, sign_cose_sign1};
use super::types::{CcaToken, ExtensionDevice, PlatformClaims, RealmClaims, SwComponent};
use crate::attesters::cca::CcaError;

/// Fixed claim sizes from draft-ffm-rats-cca-token-01.
const IMPLEMENTATION_ID_SIZE: usize = 32;
const INSTANCE_ID_SIZE: usize = 33;
const PERSONALIZATION_VALUE_SIZE: usize = 64;
/// The realm delegated token carries exactly four extensible measurements.
const EXTENSIBLE_MEASUREMENTS_COUNT: usize = 4;
/// First byte of a UEID RAND instance id, as required by the 2024 profiles.
const UEID_RAND_FIRST_BYTE: u8 = 0x01;

/// CCA token framing produced by [`SimulatedTokenBuilder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CcaTokenFormat {
    /// draft-ffm-rats-cca-token-01: CBOR tag 399 collection with the 2023
    /// profiles.
    Draft01,
    /// draft-ffm-03: CBOR tag 907 CMW collection with the 2024 profiles.
    #[default]
    Draft03,
}

/// Build a full CCA token (CBOR tag 399) from typed claims and signing keys.
///
/// Claims are validated against draft-ffm-rats-cca-token-01 (profile
/// strings, claim sizes and cardinalities) and rejected before signing if
/// they violate it. The caller's nonce is injected as the realm challenge;
/// the platform challenge is derived from the RAK public key (per the CCA
/// spec) and injected into the platform claims before conversion.
pub fn encode_cca_token_legacy(
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

/// Build a full CCA token in the draft-ffm-03 framing (CBOR tag 907 CMW
/// collection, 2024 profiles) from typed claims and signing keys.
///
/// Claims are validated against the 2024 platform and realm profiles
/// (profile strings, the 2024-only mandatory claims, claim sizes and
/// cardinalities) and rejected before signing if they violate them. The
/// caller's nonce is injected as the realm challenge; the platform challenge
/// is derived from the RAK public key (per the CCA spec) and injected into
/// the platform claims before conversion.
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
    validate_platform_2024(&platform_claims)?;
    validate_realm_2024(&realm_claims)?;

    // Inject runtime fields.
    platform_claims.challenge = platform_challenge;
    realm_claims.challenge = nonce.to_vec();
    realm_claims.public_key = rak_cose_key_bytes;

    // Convert typed claims into CBOR map values (2024 claim sets).
    let platform_payload_raw: CborValue = platform_claims.into_cbor_2024();
    let realm_payload_raw: CborValue = realm_claims.into_cbor_2024();

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

    // Wrap in the CMW collection (CBOR tag 907); each token is carried as a
    // [263, bstr] (eat+cwt+coap) entry, per draft-ietf-rats-msg-wrap.
    let outer = CborValue::Tag(
        CCA_TOKEN_CMW_TAG,
        Box::new(CborValue::Map(vec![
            (
                CborValue::Integer(CCA_PLATFORM_TOKEN_KEY.into()),
                cmw_collection_entry(platform_cose),
            ),
            (
                CborValue::Integer(CCA_REALM_TOKEN_KEY.into()),
                cmw_collection_entry(realm_cose),
            ),
        ])),
    );

    let mut buf = Vec::new();
    ciborium::into_writer(&outer, &mut buf)
        .map_err(|e| CcaError::custom(format!("CBOR encode: {e}")))?;
    Ok(buf)
}

/// One CMW collection entry: `[263, bstr]` (eat+cwt+coap content type and
/// the COSE_Sign1 token).
fn cmw_collection_entry(token: Vec<u8>) -> CborValue {
    CborValue::Array(vec![
        CborValue::Integer(EAT_CWT_COAP_CBOR_TAG.into()),
        CborValue::Bytes(token),
    ])
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
    validate_sw_components(&p.sw_components)?;
    Ok(())
}

/// SW component checks shared by the draft-01 and draft-ffm-03 validators.
fn validate_sw_components(components: &[SwComponent]) -> Result<(), CcaError> {
    if components.is_empty() {
        return Err(CcaError::custom(
            "cca-platform-sw-components: at least one SW component is required",
        ));
    }
    for (i, c) in components.iter().enumerate() {
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

/// Extension device checks for the 2024 platform profile.
///
/// The upstream `ccatoken` decoder constrains a device's `hash-algo-id` to
/// sha-256/384/512; mirror that here so a token built from these claims can
/// be decoded again.
fn validate_extension_devices(devices: &[ExtensionDevice]) -> Result<(), CcaError> {
    for (i, d) in devices.iter().enumerate() {
        if let Some(algo) = d.hash_algo_id.as_deref()
            && !is_valid_hash(algo)
        {
            return Err(CcaError::custom(format!(
                "extension device {i}: unsupported hash-algo-id '{algo}' \
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
    // `encode_cca_token_legacy` (called before this function), which reports the
    // algorithm name in its error message.
    Ok(())
}

/// Validation against the 2024 platform profile (draft-ffm-03).
///
/// Mirrors what the upstream `ccatoken` decoder enforces for a
/// `Platform2024` claim set, so a token produced from these claims can be
/// decoded/verified by evcli and ccatoken.
fn validate_platform_2024(p: &PlatformClaims) -> Result<(), CcaError> {
    if p.profile != CCA_PLATFORM_PROFILE_2024 {
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
                "cca-platform-hash-algo-id: missing (required by the 2024 platform profile)",
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
    if p.instance_id.first() != Some(&UEID_RAND_FIRST_BYTE) {
        return Err(CcaError::custom(
            "cca-platform-instance-id: first byte must be 0x01 (UEID RAND) \
             in the 2024 platform profile",
        ));
    }
    validate_sw_components(&p.sw_components)?;
    if let Some(devices) = &p.extension {
        validate_extension_devices(devices)?;
    }
    if let Some(client_id) = p.client_id
        && client_id != 1
    {
        return Err(CcaError::custom(format!(
            "cca-platform-client-id: must be 1, got {client_id}"
        )));
    }
    Ok(())
}

/// Validation against the 2024 realm profile (draft-ffm-03).
///
/// Mirrors what the upstream `ccatoken` decoder enforces for a
/// `Realm2024` claim set.
fn validate_realm_2024(r: &RealmClaims) -> Result<(), CcaError> {
    match r.profile.as_deref() {
        None => {
            return Err(CcaError::custom(
                "cca-realm-profile: required for the 2024 realm profile",
            ));
        }
        Some(profile) if profile != CCA_REALM_PROFILE_2024 => {
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
    match r.mec_policy {
        None => {
            return Err(CcaError::custom(
                "cca-realm-mec-policy: missing (required by the 2024 realm profile)",
            ));
        }
        Some(policy) if policy > 1 => {
            return Err(CcaError::custom(format!(
                "cca-realm-mec-policy: expected 0 or 1, got {policy}"
            )));
        }
        Some(_) => {}
    }
    match &r.instance_id {
        None => {
            return Err(CcaError::custom(
                "cca-realm-instance-id: missing (required by the 2024 realm profile)",
            ));
        }
        Some(id) => {
            if id.len() != INSTANCE_ID_SIZE {
                return Err(CcaError::custom(format!(
                    "cca-realm-instance-id: expected {INSTANCE_ID_SIZE} bytes, got {}",
                    id.len()
                )));
            }
            if id.first() != Some(&UEID_RAND_FIRST_BYTE) {
                return Err(CcaError::custom(
                    "cca-realm-instance-id: first byte must be 0x01 (UEID RAND)",
                ));
            }
        }
    }
    // `public_key_hash_algo_id` is validated by `compute_hash` in
    // `encode_cca_token` (called before this function).
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
/// Both build with [`CcaTokenFormat::Draft03`] by default; use
/// [`with_format`](SimulatedTokenBuilder::with_format) to select the framing.
/// Construction and signing are delegated to [`encode_cca_token_legacy`] (draft-01)
/// or [`encode_cca_token`] (draft-ffm-03).
#[derive(Debug)]
pub(crate) struct SimulatedTokenBuilder {
    platform_claims: PlatformClaims,
    realm_claims: RealmClaims,
    iak: SigningKey,
    rak: SigningKey,
    format: CcaTokenFormat,
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
            format: CcaTokenFormat::default(),
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
            format: CcaTokenFormat::default(),
        })
    }

    /// Override the token framing produced by [`build_token`](Self::build_token).
    ///
    /// The default is [`CcaTokenFormat::Draft03`] (2024 profiles); pass
    /// [`CcaTokenFormat::Draft01`] to create legacy draft-01 tokens.
    pub fn with_format(mut self, format: CcaTokenFormat) -> Self {
        self.format = format;
        self
    }

    pub fn build_token(&self, nonce: &[u8]) -> Result<Vec<u8>, CcaError> {
        match self.format {
            CcaTokenFormat::Draft01 => encode_cca_token_legacy(
                self.platform_claims.clone(),
                self.realm_claims.clone(),
                &self.iak,
                &self.rak,
                nonce,
            ),
            CcaTokenFormat::Draft03 => encode_cca_token(
                self.platform_claims.clone(),
                self.realm_claims.clone(),
                &self.iak,
                &self.rak,
                nonce,
            ),
        }
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

    fn load_test_claims_2024() -> String {
        std::fs::read_to_string("test-data/cca-claims-2024.json").unwrap()
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
        let token = builder
            .with_format(CcaTokenFormat::Draft01)
            .build_token(&[0u8; 64])
            .unwrap();
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
        let token = builder
            .with_format(CcaTokenFormat::Draft01)
            .build_token(&[0u8; 64])
            .unwrap();
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
        let builder = builder.with_format(CcaTokenFormat::Draft01);
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
        let builder = builder.with_format(CcaTokenFormat::Draft01);
        let token_a = builder.build_token(&[0u8; 64]).unwrap();
        let token_b = builder.build_token(&[1u8; 64]).unwrap();
        assert_ne!(token_a, token_b);
    }

    // -----------------------------------------------------------------------
    // encode_cca_token_legacy
    // -----------------------------------------------------------------------

    #[test]
    fn encode_cca_token_legacy_produces_non_empty_output() {
        let claims = load_test_claims();
        let iak = load_test_iak();
        let rak = load_test_rak();
        let builder = SimulatedTokenBuilder::new(&claims, &iak, Some(&rak)).unwrap();
        let token = encode_cca_token_legacy(
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

    /// Build a legacy draft-01 token from the given claims.
    fn build_token_from(claims: &str) -> Result<Vec<u8>, CcaError> {
        SimulatedTokenBuilder::new(claims, &load_test_iak(), Some(&load_test_rak()))?
            .with_format(CcaTokenFormat::Draft01)
            .build_token(&[0u8; 64])
    }

    /// Build a draft-ffm-03 (2024 profile) token from the given claims.
    fn build_2024_token_from(claims: &str) -> Result<Vec<u8>, CcaError> {
        SimulatedTokenBuilder::new(claims, &load_test_iak(), Some(&load_test_rak()))?
            .with_format(CcaTokenFormat::Draft03)
            .build_token(&[0u8; 64])
    }

    fn claims_2024_with(edit: impl FnOnce(&mut serde_json::Value)) -> String {
        let mut doc: serde_json::Value = serde_json::from_str(&load_test_claims_2024())
            .expect("bundled 2024 claims should parse");
        edit(&mut doc);
        doc.to_string()
    }

    /// Decode the two COSE_Sign1 payloads of a draft-ffm-03 (tag 907) token.
    fn cmw_payloads(token: &[u8]) -> (CborValue, CborValue) {
        let outer: CborValue = ciborium::from_reader(token).expect("token should be valid CBOR");
        let CborValue::Tag(tag, inner) = outer else {
            panic!("expected a CBOR tag");
        };
        assert_eq!(tag, CCA_TOKEN_CMW_TAG);
        let CborValue::Map(entries) = *inner else {
            panic!("expected a map under the CMW tag");
        };
        let payload = |key: u64| -> CborValue {
            let entry = map_get(&entries, key).expect("CMW entry");
            let CborValue::Array(items) = entry else {
                panic!("CMW entry should be a [263, token] array");
            };
            assert_eq!(items.len(), 2);
            assert_eq!(items[0], CborValue::Integer(EAT_CWT_COAP_CBOR_TAG.into()));
            let CborValue::Bytes(cose_bytes) = &items[1] else {
                panic!("CMW entry should carry COSE_Sign1 bytes");
            };
            let cose: CborValue =
                ciborium::from_reader(cose_bytes.as_slice()).expect("COSE_Sign1 should parse");
            let CborValue::Tag(18, cose_inner) = cose else {
                panic!("expected COSE_Sign1 tag 18");
            };
            let CborValue::Array(cose_items) = *cose_inner else {
                panic!("expected a COSE_Sign1 array");
            };
            let payload = cose_items
                .get(2)
                .and_then(|v| v.as_bytes())
                .expect("COSE_Sign1 payload");
            ciborium::from_reader(payload.as_slice()).expect("payload should parse")
        };
        (
            payload(CCA_PLATFORM_TOKEN_KEY),
            payload(CCA_REALM_TOKEN_KEY),
        )
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
    // TBB RoTPK / extension claims (2024 profile)
    // -----------------------------------------------------------------------

    /// First entry of a map-valued array claim in a token payload.
    fn first_array_entry(payload: &CborValue, claim: u64) -> &[(CborValue, CborValue)] {
        let CborValue::Map(entries) = payload else {
            panic!("payload should be a map");
        };
        let CborValue::Array(items) = map_get(entries, claim).expect("array claim") else {
            panic!("claim should be an array");
        };
        let CborValue::Map(first) = &items[0] else {
            panic!("first entry should be a map");
        };
        first
    }

    #[test]
    fn tbb_rotpk_item_is_encoded_with_keys_1_2_3() {
        let claims = claims_2024_with(|doc| {
            doc["cca-platform-token"]["cca-platform-tbb-rotpk"] = serde_json::json!([{
                "name": "DM",
                "index": 0,
                "hash": b64(&[0x07u8; 32]),
            }]);
        });
        let token = build_2024_token_from(&claims).unwrap();
        let payload = cmw_payloads(&token).0;
        let item = first_array_entry(&payload, PLAT_TBB_ROTPK);
        // Current Evidence Profile numbering: name = 1, index = 2, hash = 3.
        assert_eq!(item.len(), 3);
        assert_eq!(
            map_get(item, TBB_NAME),
            Some(&CborValue::Text("DM".to_owned()))
        );
        assert_eq!(
            map_get(item, TBB_INDEX),
            Some(&CborValue::Integer(0i64.into()))
        );
        assert_eq!(
            map_get(item, TBB_HASH),
            Some(&CborValue::Bytes(vec![0x07u8; 32]))
        );
    }

    #[test]
    fn tbb_rotpk_active_array_index_is_rejected() {
        // The claim was removed from the Evidence Profile; the JSON input no
        // longer accepts it (breaking change for claims files).
        let claims = claims_2024_with(|doc| {
            doc["cca-platform-token"]["cca-platform-tbb-rotpk"] = serde_json::json!([{
                "name": "DM",
                "active-array-index": 0,
                "index": 0,
                "hash": b64(&[0x07u8; 32]),
            }]);
        });
        let err = build_2024_token_from(&claims).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("active-array-index"), "{msg}");
    }

    #[test]
    fn extension_device_with_supported_hash_algo_is_encoded() {
        let claims = claims_2024_with(|doc| {
            doc["cca-platform-token"]["cca-platform-extension"] = serde_json::json!([{
                "hash-algo-id": "sha-384",
                "device-measurements-digest": b64(&[0x07u8; 48]),
                "certificate-chain-digest": b64(&[0x08u8; 48]),
                "uses-ide": true,
                "protocol": "spdm-1.3.0",
                "vca-digest": b64(&[0x09u8; 48]),
                "device-type": "cxl-type-3",
                "encryption-type": 1,
            }]);
        });
        let token = build_2024_token_from(&claims).unwrap();
        let payload = cmw_payloads(&token).0;
        let device = first_array_entry(&payload, PLAT_EXTENSION);
        assert_eq!(
            map_get(device, EXT_HASH_ALGO),
            Some(&CborValue::Text("sha-384".to_owned()))
        );
    }

    #[test]
    fn extension_device_with_unsupported_hash_algo_is_rejected() {
        let claims = claims_2024_with(|doc| {
            doc["cca-platform-token"]["cca-platform-extension"] = serde_json::json!([{
                "hash-algo-id": "md5",
                "device-measurements-digest": b64(&[0x07u8; 32]),
                "certificate-chain-digest": b64(&[0x08u8; 32]),
                "uses-ide": false,
                "protocol": "spdm-1.3.0",
                "vca-digest": b64(&[0x09u8; 32]),
                "device-type": "cxl-type-3",
                "encryption-type": 0,
            }]);
        });
        let err = build_2024_token_from(&claims).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("hash-algo-id"), "{msg}");
        assert!(msg.contains("md5"), "{msg}");
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

    // -----------------------------------------------------------------------
    // encode_cca_token (draft-ffm-03)
    // -----------------------------------------------------------------------

    #[test]
    fn encode_cca_token_produces_tag_907_cmw_collection() {
        let token = build_2024_token_from(&load_test_claims_2024()).unwrap();
        let outer: CborValue = ciborium::from_reader(token.as_slice()).unwrap();
        let CborValue::Tag(tag, inner) = outer else {
            panic!("expected a CBOR tag");
        };
        assert_eq!(tag, CCA_TOKEN_CMW_TAG);
        let CborValue::Map(entries) = *inner else {
            panic!("expected a map under the CMW tag");
        };
        assert_eq!(entries.len(), 2);
        // cmw_payloads asserts the [263, COSE_Sign1] entry shape of both
        // entries as well as the COSE_Sign1 framing.
        let _ = cmw_payloads(&token);
    }

    #[test]
    fn encode_cca_token_emits_2024_only_claims() {
        let token = build_2024_token_from(&load_test_claims_2024()).unwrap();
        let (platform, realm) = cmw_payloads(&token);
        let CborValue::Map(platform_entries) = &platform else {
            panic!("platform claims should be a map");
        };
        assert_eq!(
            map_get(platform_entries, PLAT_CLIENT_ID),
            Some(&CborValue::Integer(1_u64.into()))
        );
        let CborValue::Map(realm_entries) = &realm else {
            panic!("realm claims should be a map");
        };
        assert_eq!(
            map_get(realm_entries, REALM_MEC_POLICY),
            Some(&CborValue::Integer(1_u64.into()))
        );
        assert_eq!(
            map_get(realm_entries, REALM_INSTANCE_ID)
                .and_then(|v| v.as_bytes())
                .map(|id| id.len()),
            Some(33)
        );
    }

    #[test]
    fn encode_cca_token_round_trips_through_decode() {
        let token = build_2024_token_from(&load_test_claims_2024()).unwrap();
        let decoded = crate::attesters::cca::utils::decode_cca_token(&token).unwrap();
        assert_eq!(
            decoded.platform.profile,
            "tag:arm.com,2024:cca_platform#2.0.0"
        );
        assert_eq!(
            decoded.realm.profile.as_deref(),
            Some("tag:arm.com,2024:realm#2.0.0")
        );
        assert_eq!(decoded.platform.client_id, Some(1));
        assert_eq!(decoded.realm.mec_policy, Some(1));
        assert!(
            decoded
                .realm
                .instance_id
                .as_ref()
                .is_some_and(|id| id.len() == 33)
        );
        assert_eq!(decoded.platform.sw_components.len(), 13);
    }

    #[test]
    fn tbb_rotpk_and_extension_claims_round_trip_through_decode() {
        // The encoder emits the current Evidence Profile shape, so a token
        // carrying tbb-rotpk and extension claims must decode back through
        // ccatoken.
        let claims = claims_2024_with(|doc| {
            doc["cca-platform-token"]["cca-platform-tbb-rotpk"] = serde_json::json!([{
                "name": "DM",
                "index": 0,
                "hash": b64(&[0x07u8; 32]),
            }]);
            doc["cca-platform-token"]["cca-platform-extension"] = serde_json::json!([{
                "hash-algo-id": "sha-256",
                "device-measurements-digest": b64(&[0x07u8; 32]),
                "certificate-chain-digest": b64(&[0x07u8; 32]),
                "uses-ide": true,
                "protocol": "spdm-1.2.0",
                "vca-digest": b64(&[0x07u8; 32]),
                "device-type": "cxl-type-3",
                "encryption-type": 0,
            }]);
        });
        let token = build_2024_token_from(&claims).unwrap();
        let decoded = crate::attesters::cca::utils::decode_cca_token(&token).unwrap();

        let tbb = decoded.platform.tbb_rotpk.expect("tbb-rotpk claim");
        assert_eq!(tbb.len(), 1);
        assert_eq!(tbb[0].name, "DM");
        assert_eq!(tbb[0].index, 0);
        assert_eq!(tbb[0].hash, vec![0x07u8; 32]);

        let extension = decoded.platform.extension.expect("extension claim");
        assert_eq!(extension.len(), 1);
        assert_eq!(extension[0].hash_algo_id.as_deref(), Some("sha-256"));
        assert_eq!(extension[0].device_type, "cxl-type-3");
    }

    #[test]
    fn encode_cca_token_rejects_legacy_claims() {
        let err = build_2024_token_from(&load_test_claims()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("cca-platform-profile"), "{msg}");
    }

    #[test]
    fn encode_cca_token_defaults_client_id_to_1() {
        let claims = claims_2024_with(|doc| {
            doc["cca-platform-token"]
                .as_object_mut()
                .expect("platform token should be an object")
                .remove("cca-platform-client-id");
        });
        let token = build_2024_token_from(&claims).unwrap();
        let (platform, _) = cmw_payloads(&token);
        let CborValue::Map(platform_entries) = &platform else {
            panic!("platform claims should be a map");
        };
        assert_eq!(
            map_get(platform_entries, PLAT_CLIENT_ID),
            Some(&CborValue::Integer(1_u64.into()))
        );
    }

    #[test]
    fn encode_cca_token_rejects_client_id_other_than_1() {
        let claims = claims_2024_with(|doc| {
            doc["cca-platform-token"]["cca-platform-client-id"] = serde_json::Value::from(2);
        });
        let err = build_2024_token_from(&claims).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("cca-platform-client-id"), "{msg}");
        assert!(msg.contains('2'), "{msg}");
    }

    #[test]
    fn encode_cca_token_rejects_missing_mec_policy() {
        let claims = claims_2024_with(|doc| {
            doc["cca-realm-delegated-token"]
                .as_object_mut()
                .expect("realm token should be an object")
                .remove("cca-realm-mec-policy");
        });
        let err = build_2024_token_from(&claims).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("cca-realm-mec-policy"), "{msg}");
    }

    #[test]
    fn encode_cca_token_rejects_invalid_mec_policy() {
        let claims = claims_2024_with(|doc| {
            doc["cca-realm-delegated-token"]["cca-realm-mec-policy"] = serde_json::Value::from(2);
        });
        let err = build_2024_token_from(&claims).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("cca-realm-mec-policy"), "{msg}");
    }

    #[test]
    fn encode_cca_token_rejects_missing_realm_instance_id() {
        let claims = claims_2024_with(|doc| {
            doc["cca-realm-delegated-token"]
                .as_object_mut()
                .expect("realm token should be an object")
                .remove("cca-realm-instance-id");
        });
        let err = build_2024_token_from(&claims).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("cca-realm-instance-id"), "{msg}");
    }

    #[test]
    fn encode_cca_token_rejects_wrong_realm_instance_id_length() {
        let claims = claims_2024_with(|doc| {
            doc["cca-realm-delegated-token"]["cca-realm-instance-id"] = b64(&[1u8; 32]).into();
        });
        let err = build_2024_token_from(&claims).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("cca-realm-instance-id"), "{msg}");
        assert!(msg.contains("33"), "{msg}");
    }

    #[test]
    fn encode_cca_token_rejects_realm_instance_id_first_byte() {
        let claims = claims_2024_with(|doc| {
            doc["cca-realm-delegated-token"]["cca-realm-instance-id"] = b64(&[0u8; 33]).into();
        });
        let err = build_2024_token_from(&claims).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("cca-realm-instance-id"), "{msg}");
        assert!(msg.contains("0x01"), "{msg}");
    }

    #[test]
    fn encode_cca_token_rejects_platform_instance_id_first_byte() {
        let claims = claims_2024_with(|doc| {
            doc["cca-platform-token"]["cca-platform-instance-id"] = b64(&[0u8; 33]).into();
        });
        let err = build_2024_token_from(&claims).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("cca-platform-instance-id"), "{msg}");
        assert!(msg.contains("0x01"), "{msg}");
    }
}
