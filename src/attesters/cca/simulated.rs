// Copyright 2026 Contributors to the Veraison project
// SPDX-License-Identifier: Apache-2.0

//! Simulated CCA attester - Rust equivalent of `evcli cca create`.
//!
//! Builds a structurally valid CCA token (CBOR tag 399) with two
//! COSE_Sign1 tokens (platform + realm) signed with ES384.
//!
//! The application is responsible for reading files and passing their contents
//! to the builder - no environment variables are read by the library itself.

use super::Attester;
use super::CcaError;
use super::utils::SimulatedTokenBuilder;
use p384::ecdsa::SigningKey;

/// Simulated CCA attester that builds tokens from JSON claims and JWK key texts.
#[derive(Debug)]
pub struct CcaSimulatedAttester {
    builder: SimulatedTokenBuilder,
}

impl CcaSimulatedAttester {
    /// Create a new simulated attester from JSON claims and JWK key texts.
    ///
    /// See [`SimulatedTokenBuilder::new`] for parameter details.
    pub fn new(claims_json: &str, iak_jwk: &str, rak_jwk: Option<&str>) -> Result<Self, CcaError> {
        Ok(Self {
            builder: SimulatedTokenBuilder::new(claims_json, iak_jwk, rak_jwk)?,
        })
    }

    /// Create a new simulated attester from JSON claims and P-384 [`SigningKey`]s.
    ///
    /// This constructor accepts COSE keys directly, skipping the JWK
    /// parsing step.
    pub fn with_keys(
        claims_json: &str,
        iak: SigningKey,
        rak: SigningKey,
    ) -> Result<Self, CcaError> {
        Ok(Self {
            builder: SimulatedTokenBuilder::with_keys(claims_json, iak, rak)?,
        })
    }
}

impl Attester for CcaSimulatedAttester {
    type AttesterError = CcaError;

    fn get_evidence(&self, challenge: &[u8]) -> Result<Vec<u8>, CcaError> {
        if challenge.len() != super::NONCE_SIZE {
            return Err(CcaError::InvalidNonce(format!(
                "expected {} bytes, got {}",
                super::NONCE_SIZE,
                challenge.len()
            )));
        }
        self.builder.build_token(challenge)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attesters::Attester;

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
    // CcaSimulatedAttester::new
    // -----------------------------------------------------------------------

    #[test]
    fn new_with_test_data_succeeds() {
        let claims = load_test_claims();
        let iak = load_test_iak();
        let rak = load_test_rak();
        let attester = CcaSimulatedAttester::new(&claims, &iak, Some(&rak));
        assert!(attester.is_ok(), "expected Ok, got {:?}", attester.err());
    }

    #[test]
    fn new_without_rak_generates_key() {
        let claims = load_test_claims();
        let iak = load_test_iak();
        let attester = CcaSimulatedAttester::new(&claims, &iak, None);
        assert!(attester.is_ok(), "expected Ok, got {:?}", attester.err());
    }

    #[test]
    fn new_with_invalid_claims_returns_error() {
        let iak = load_test_iak();
        let rak = load_test_rak();
        let err = CcaSimulatedAttester::new("not-valid-json", &iak, Some(&rak)).unwrap_err();
        assert!(format!("{err}").contains("parsing claims JSON"));
    }

    #[test]
    fn new_with_invalid_iak_returns_error() {
        let claims = load_test_claims();
        let rak = load_test_rak();
        let err = CcaSimulatedAttester::new(&claims, "not-a-jwk", Some(&rak)).unwrap_err();
        assert!(format!("{err}").contains("IAK"));
    }

    // -----------------------------------------------------------------------
    // CcaSimulatedAttester::with_keys
    // -----------------------------------------------------------------------

    #[test]
    fn with_keys_produces_valid_attester_and_token() {
        use p384::ecdsa::SigningKey;
        use rand_core::OsRng;
        let claims = load_test_claims();
        let iak = SigningKey::random(&mut OsRng);
        let rak = SigningKey::random(&mut OsRng);
        let attester = CcaSimulatedAttester::with_keys(&claims, iak, rak).unwrap();
        let evidence = attester.get_evidence(&[0u8; 64]).unwrap();
        assert!(!evidence.is_empty());
    }

    // -----------------------------------------------------------------------
    // get_evidence
    // -----------------------------------------------------------------------

    #[test]
    fn get_evidence_returns_valid_token() {
        let claims = load_test_claims();
        let iak = load_test_iak();
        let rak = load_test_rak();
        let attester = CcaSimulatedAttester::new(&claims, &iak, Some(&rak)).unwrap();
        let evidence = attester.get_evidence(&[0u8; 64]).unwrap();
        assert!(!evidence.is_empty());
    }

    #[test]
    fn get_evidence_different_nonce_produces_different_token() {
        let claims = load_test_claims();
        let iak = load_test_iak();
        let rak = load_test_rak();
        let attester = CcaSimulatedAttester::new(&claims, &iak, Some(&rak)).unwrap();
        let token_a = attester.get_evidence(&[0u8; 64]).unwrap();
        let token_b = attester.get_evidence(&[1u8; 64]).unwrap();
        assert_ne!(token_a, token_b);
    }

    #[test]
    fn get_evidence_same_nonce_is_deterministic() {
        let claims = load_test_claims();
        let iak = load_test_iak();
        let rak = load_test_rak();
        let attester = CcaSimulatedAttester::new(&claims, &iak, Some(&rak)).unwrap();
        let token1 = attester.get_evidence(&[0u8; 64]).unwrap();
        let token2 = attester.get_evidence(&[0u8; 64]).unwrap();
        assert_eq!(token1, token2);
    }

    // -----------------------------------------------------------------------
    // Nonce validation
    // -----------------------------------------------------------------------

    #[test]
    fn get_evidence_rejects_short_nonce() {
        let claims = load_test_claims();
        let iak = load_test_iak();
        let rak = load_test_rak();
        let attester = CcaSimulatedAttester::new(&claims, &iak, Some(&rak)).unwrap();
        let err = attester.get_evidence(b"short").unwrap_err();
        assert!(matches!(err, CcaError::InvalidNonce(_)));
    }

    #[test]
    fn get_evidence_rejects_long_nonce() {
        let claims = load_test_claims();
        let iak = load_test_iak();
        let rak = load_test_rak();
        let attester = CcaSimulatedAttester::new(&claims, &iak, Some(&rak)).unwrap();
        let err = attester.get_evidence(&[0u8; 65]).unwrap_err();
        assert!(matches!(err, CcaError::InvalidNonce(_)));
    }
}
