//! CCA token decoding and type conversion.
//!
//! The `ccatoken` crate decodes CBOR into its own internal types (`Platform`,
//! `Realm`, `SwComponent`). This module provides bridge functions —
//! `convert_platform`, `convert_sw_component`, `convert_realm` — that map
//! those internal types into our public serde-enabled types (`PlatformClaims`,
//! `RealmClaims`, `SwComponent`) for use by callers that need JSON output
//! (e.g. `pretty_print_token`).
//!
//! This indirection keeps our public API stable even if the ccatoken library
//! changes its field names.

use ccatoken::token::SwComponent as CcaSwComponent;
use ccatoken::token::{Evidence, Platform, Realm};

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
        platform: convert_platform(&evidence.platform_claims),
        realm: convert_realm(&evidence.realm_claims),
    })
}

/// Convert the upstream `ccatoken::Platform` struct into our
/// serde-enabled [`PlatformClaims`].
///
/// This is a simple field-by-field copy with minor transformations:
/// - `lifecycle` is narrowed from `i128` to `u64`
/// - `verification_service` is mapped to `service_indicator`
/// - `hash_alg` is mapped to `hash_algo_id` (stored as `Option<String>`
///   so that empty strings from the library become `None`)
/// - each software component is converted via [`convert_sw_component`]
fn convert_platform(p: &Platform) -> PlatformClaims {
    PlatformClaims {
        profile: p.profile.clone(),
        challenge: p.challenge.to_vec(),
        implementation_id: p.impl_id.to_vec(),
        instance_id: p.inst_id.to_vec(),
        config: p.config.clone(),
        lifecycle: p.lifecycle as u64,
        sw_components: p.sw_components.iter().map(convert_sw_component).collect(),
        service_indicator: p.verification_service.clone(),
        hash_algo_id: Some(p.hash_alg.clone()).filter(|s| !s.is_empty()),
    }
}

/// Convert the upstream `ccatoken::SwComponent` into our
/// serde-enabled [`SwComponent`].
///
/// Field name mapping from the ccatoken library:
/// - `mtyp`  → `measurement_type`
/// - `mval`  → `measurement_value`
/// - `hash_alg` → `measurement_description`
fn convert_sw_component(c: &CcaSwComponent) -> SwComponent {
    SwComponent {
        measurement_type: c.mtyp.clone(),
        measurement_value: c.mval.clone(),
        version: c.version.clone(),
        signer_id: c.signer_id.clone(),
        measurement_description: c.hash_alg.clone(),
    }
}

/// Convert the upstream `ccatoken::Realm` struct into our
/// serde-enabled [`RealmClaims`].
///
/// Uses `get_realm_key()` to select the correct public key encoding
/// (COSE_Key for realm-profile tokens, raw bytes otherwise) — matching
/// the logic in the ccatoken library itself.
fn convert_realm(r: &Realm) -> RealmClaims {
    let public_key = r.get_realm_key().unwrap_or_default();

    RealmClaims {
        profile: Some(r.profile.clone()).filter(|s| !s.is_empty()),
        challenge: r.challenge.to_vec(),
        personalization_value: r.perso.to_vec(),
        initial_measurement: r.rim.clone(),
        extensible_measurements: r.rem.to_vec(),
        hash_algo_id: r.hash_alg.clone(),
        public_key,
        public_key_hash_algo_id: r.rak_hash_alg.clone(),
    }
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
