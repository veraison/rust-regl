// Copyright 2026 Contributors to the Veraison project
// SPDX-License-Identifier: Apache-2.0

//! CCA token decoding and type conversion.
//!
//! The `ccatoken` crate decodes CBOR into its own internal types (`Platform`,
//! `Realm`, `SwComponent`). This module provides bridge functions -
//! `convert_platform`, `convert_sw_component`, `convert_realm` - that map
//! those internal types into our public serde-enabled types (`PlatformClaims`,
//! `RealmClaims`, `SwComponent`) for use by callers that need JSON output
//! (e.g. `pretty_print_token`).
//!
//! This indirection keeps our public API stable even if the ccatoken library
//! changes its field names.

use ccatoken::token::Evidence;

use super::super::CcaError;
use super::types::*;

/// Decode raw CBOR bytes of a CCA token (tag 399) into a [`CcaToken`].
///
/// This uses the upstream `ccatoken` library to decode the CBOR into its
/// internal types (`Platform`, `Realm`), then converts them to our own
/// serde-enabled types (`PlatformClaims`, `RealmClaims`) for JSON output.
pub fn decode_cca_token(data: &[u8]) -> Result<CcaToken, CcaError> {
    let evidence =
        Evidence::decode(data).map_err(|e| CcaError::custom(format!("ccatoken decode: {e}")))?;

    Ok(CcaToken {
        platform: evidence.platform_claims.into(),
        realm: evidence.realm_claims.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_evidence() -> &'static [u8] {
        include_bytes!("../data/evidence.cbor")
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
