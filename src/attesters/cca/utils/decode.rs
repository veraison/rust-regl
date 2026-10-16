// Copyright 2026 Contributors to the Veraison project
// SPDX-License-Identifier: Apache-2.0

//! CCA token decoding and type conversion.
//!
//! The `ccatoken` crate decodes CBOR into its own claims types (per-profile
//! variants abstracted behind a legacy/2024 enum). This module maps those
//! into our public serde-enabled types (`PlatformClaims`, `RealmClaims`,
//! `SwComponent`) for use by callers that need JSON output (e.g.
//! `pretty_print_token`).
//!
//! Both token framings supported by the upstream library are accepted: the
//! CBOR tag 399 collection (draft-ffm-rats-cca-token-01, 2023 profiles) and
//! the CBOR tag 907 CMW collection (draft-ffm-03, 2024 profiles).
//!
//! This indirection keeps our public API stable even if the ccatoken library
//! changes its field names.

use ccatoken::token::Evidence;

use super::super::CcaError;
use super::types::*;

/// Decode raw CBOR bytes of a CCA token into a [`CcaToken`].
///
/// Accepts both framings handled by the upstream `ccatoken` library: the
/// CBOR tag 399 collection (draft-ffm-rats-cca-token-01, 2023 profiles) and
/// the CBOR tag 907 CMW collection (draft-ffm-03, 2024 profiles). The
/// decoded claims are converted into our serde-enabled types
/// (`PlatformClaims`, `RealmClaims`) for JSON output.
pub fn decode_cca_token(data: &[u8]) -> Result<CcaToken, CcaError> {
    let evidence =
        Evidence::decode(data).map_err(|e| CcaError::custom(format!("ccatoken decode: {e}")))?;

    Ok(CcaToken {
        platform: evidence.platform_claims.try_into()?,
        realm: evidence.realm_claims.try_into()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_evidence() -> &'static [u8] {
        include_bytes!("../data/evidence.cbor")
    }

    /// draft-ffm-03 (2024 profile) token carrying every claim; taken from
    /// the upstream `rust-ccatoken` test data (Apache-2.0, commit d1b66e7).
    fn mock_evidence_ffm03() -> &'static [u8] {
        include_bytes!("../data/evidence-ffm-03.cbor")
    }

    #[test]
    fn decode_produces_populated_token() {
        // Verify the full CBOR → typed-struct pipeline works end-to-end
        // and both platform and realm claims are populated.
        let token = decode_cca_token(mock_evidence()).unwrap();
        assert!(!token.platform.challenge.is_empty());
        assert!(!token.platform.sw_components.is_empty());
        assert!(!token.realm.challenge.is_empty());
        assert!(!token.realm.extensible_measurements.is_empty());
    }

    #[test]
    fn decode_rejects_invalid_input() {
        // Both garbage data and empty input must be rejected without panicking.
        assert!(decode_cca_token(b"not valid cbor").is_err());
        assert!(decode_cca_token(b"").is_err());
    }

    #[test]
    fn decode_ffm03_produces_populated_token() {
        // The draft-ffm-03 / 2024 profile token (tag 907 CMW collection)
        // decodes through the same entry point; the 2024-only claims are
        // mapped into the optional fields of our serde types.
        let token = decode_cca_token(mock_evidence_ffm03()).unwrap();
        assert_eq!(
            token.platform.profile,
            "tag:arm.com,2024:cca_platform#2.0.0"
        );
        assert_eq!(
            token.realm.profile.as_deref(),
            Some("tag:arm.com,2024:realm#2.0.0")
        );
        assert_eq!(token.platform.client_id, Some(1));
        assert!(token.platform.manufacturing_config.is_some());
        assert!(token.platform.peer_signers.is_some());
        assert!(
            token
                .platform
                .extension
                .as_ref()
                .is_some_and(|v| v.len() == 2)
        );
        assert!(
            token
                .platform
                .tbb_rotpk
                .as_ref()
                .is_some_and(|v| v.len() == 1)
        );
        assert_eq!(token.realm.mec_policy, Some(1));
        assert!(
            token
                .realm
                .instance_id
                .as_ref()
                .is_some_and(|v| v.len() == 33)
        );
        assert_eq!(token.platform.sw_components.len(), 1);
        assert_eq!(token.realm.public_key_hash_algo_id, "sha-512");
    }
}

// ---------------------------------------------------------------------------
// pretty_print_token - convenience wrapper
// ---------------------------------------------------------------------------

/// Decode a raw CCA token and serialize it as an indented JSON string.
///
/// This is a convenience wrapper that calls [`decode_cca_token`] followed
/// by `serde_json::to_string_pretty`.
pub fn pretty_print_token(data: &[u8]) -> Result<String, CcaError> {
    let token = decode_cca_token(data)?;
    serde_json::to_string_pretty(&token)
        .map_err(|e| CcaError::custom(format!("JSON serialize: {e}")))
}

#[cfg(test)]
mod print_tests {
    use super::*;
    use crate::attesters::Attester;
    use crate::attesters::cca::CcaSimulatedAttester;
    use std::fs;

    #[test]
    fn pretty_print_token_produces_valid_json_with_expected_keys() {
        let claims = fs::read_to_string("test-data/cca-claims.json").unwrap();
        let iak = fs::read_to_string("test-data/iak.jwk").unwrap();
        let rak = fs::read_to_string("test-data/rak.jwk").unwrap();

        let evidence = CcaSimulatedAttester::new(&claims, &iak, Some(&rak))
            .unwrap()
            .get_evidence(&[0u8; 64])
            .unwrap();
        let json = pretty_print_token(&evidence).unwrap();
        assert!(json.contains("cca-platform-profile"));
        assert!(json.contains("cca-realm-delegated-token"));
        assert!(json.contains("cca-platform-challenge"));
        assert!(json.contains("cca-realm-challenge"));
    }
}
