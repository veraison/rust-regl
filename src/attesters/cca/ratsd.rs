// Copyright 2026 Contributors to the Veraison project
// SPDX-License-Identifier: Apache-2.0

//! CCA-specific RATSD attester.
//!
//! Uses the generic [`RatsdAttester`](crate::attesters::ratsd::RatsdAttester)
//! to communicate with a RATSD daemon, then parses the CMW envelope to
//! extract the CCA attestation token.
//!
//! The caller receives only the raw CCA token bytes (CBOR-encoded COSE_Sign1).

use base64::{Engine, engine::general_purpose};
use cmw::CMW as CmwEnum;
use cmw::collection::{Collection, Label as CmwLabel};
use cmw::monad::Monad;
use serde_json::Value as JsonValue;
use std::str;

use super::{Attester, CcaError};
use crate::attesters::ratsd::{RatsdAttester, RatsdError};

const CCA_PROVIDER: &str = "arm_cca_guest";

/// RATSD media types from the RATSD API spec (docs/api/ratsd.yaml).
/// Only TSM report evidence is considered for CCA extraction; matching is
/// exact, per the `ratsd-collection-legacy` definition in
/// docs/ratsd-token.cddl.
pub const RATSD_TSM_REPORT_JSON: &str = "application/vnd.veraison.tsm-report+json";
pub const RATSD_TSM_REPORT_CBOR: &str = "application/vnd.veraison.tsm-report+cbor";
const RATSD_TSM_REPORT_TYPES: [&str; 2] = [RATSD_TSM_REPORT_JSON, RATSD_TSM_REPORT_CBOR];

/// Collection type of the legacy CMW collection (ratsd-token.cddl).
const RATSD_CMWCT_LEGACY: &str = "tag:github.com,2025:veraison/ratsd/cmw";

/// eat_profile of the legacy RATSD token (ratsd-token.cddl).
const RATSD_LEGACY_PROFILE: &str = "tag:github.com,2024:veraison/ratsd";

/// CCA attester backed by a running RATSD daemon.
///
/// Wraps a generic [`RatsdAttester`] and applies CCA-specific
/// evidence extraction on top of the raw RATSD response.
pub struct CcaRatsdAttester {
    ratsd: RatsdAttester,
}

impl CcaRatsdAttester {
    /// Construct a CCA RATSD attester that posts to `url`.
    pub fn with_url(url: url::Url) -> Self {
        Self {
            ratsd: RatsdAttester::with_url(url),
        }
    }
}

impl Attester for CcaRatsdAttester {
    type AttesterError = CcaError;

    fn get_evidence(&self, challenge: &[u8]) -> std::result::Result<Vec<u8>, CcaError> {
        if challenge.len() != super::NONCE_SIZE {
            return Err(CcaError::InvalidNonce(format!(
                "expected {} bytes, got {}",
                super::NONCE_SIZE,
                challenge.len()
            )));
        }
        let resp_bytes = self.ratsd.get_evidence(challenge)?;
        let resp_body = str::from_utf8(&resp_bytes)
            .map_err(|e| RatsdError::ResponseParse(format!("invalid UTF-8: {e}")))?;
        Ok(extract_cca_token(resp_body)?)
    }
}

// ---------------------------------------------------------------------------
// CCA evidence extraction
// ---------------------------------------------------------------------------

fn extract_cca_token(resp_body: &str) -> Result<Vec<u8>, RatsdError> {
    let envelope: JsonValue = serde_json::from_str(resp_body)
        .map_err(|e| RatsdError::ResponseParse(format!("invalid JSON: {e}")))?;

    // Per ratsd-token.cddl, the legacy token carries an eat_profile claim
    // identifying the RATSD profile.
    let profile = envelope["eat_profile"]
        .as_str()
        .ok_or_else(|| RatsdError::ResponseParse("missing eat_profile field".into()))?;
    if profile != RATSD_LEGACY_PROFILE {
        return Err(RatsdError::ResponseParse(format!(
            "unexpected eat_profile: {profile}"
        )));
    }

    // Per ratsd-token.cddl, the cmw field is base64url-encoded (.b64u).
    let cmw_b64 = envelope["cmw"]
        .as_str()
        .ok_or_else(|| RatsdError::ResponseParse("missing cmw field".into()))?;

    let cmw_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(cmw_b64)
        .map_err(|e| RatsdError::ResponseParse(format!("cmw base64url decode: {e}")))?;

    let items = parse_cmw_items(&cmw_bytes)?;
    find_cca_outblob(&items)
}

fn parse_cmw_items(cmw_json: &[u8]) -> Result<Vec<Monad>, RatsdError> {
    let collection = Collection::unmarshal_json(cmw_json)
        .map_err(|e| RatsdError::ResponseParse(format!("CMW collection: {e}")))?;

    // Per ratsd-token.cddl, the legacy collection type is fixed.
    match collection.get_type() {
        Some(ctyp) if ctyp.to_string() == RATSD_CMWCT_LEGACY => {}
        Some(ctyp) => {
            return Err(RatsdError::ResponseParse(format!(
                "unexpected CMW collection type: {ctyp}"
            )));
        }
        None => {
            return Err(RatsdError::ResponseParse(
                "missing CMW collection type".into(),
            ));
        }
    }

    let mut items = Vec::new();
    for meta in collection.get_meta() {
        if matches!(&meta.key, CmwLabel::Str(s) if s == "__cmwc_t") {
            continue;
        }
        if let Some(CmwEnum::Monad(monad)) = collection.get_item(&meta.key) {
            items.push(monad.clone());
        }
    }

    Ok(items)
}

fn find_cca_outblob(items: &[Monad]) -> Result<Vec<u8>, RatsdError> {
    for item in items {
        // Exact match against the RATSD TSM report media types.
        if !RATSD_TSM_REPORT_TYPES.iter().any(|t| *t == item.type_()) {
            continue;
        }

        let json: JsonValue = match serde_json::from_slice(&item.value()) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let provider = json
            .get("provider")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if provider != CCA_PROVIDER {
            continue;
        }

        let outblob_b64 =
            json.get("outblob")
                .and_then(|v| v.as_str())
                .ok_or(RatsdError::Custom(
                    "CCA evidence not found in RATSD response".into(),
                ))?;

        let outblob = general_purpose::URL_SAFE_NO_PAD
            .decode(outblob_b64)
            .map_err(|e| RatsdError::ResponseParse(format!("outblob decode: {e}")))?;

        return Ok(outblob);
    }

    Err(RatsdError::Custom(
        "CCA evidence not found in RATSD response".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attesters::Attester;
    use crate::attesters::cca::CcaError;

    // Build a legacy RATSD envelope (per ratsd-token.cddl) wrapping a
    // CMW collection whose items are given as JSON records.
    fn build_envelope(cmw_type: &str, media_type: &str, evidence_b64: &str) -> String {
        let cmw_json = serde_json::json!({
            "__cmwc_t": cmw_type,
            "mock-cca": [media_type, evidence_b64],
        });
        let cmw_b64 =
            general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&cmw_json).unwrap());
        serde_json::json!({
            "eat_profile": "tag:github.com,2024:veraison/ratsd",
            "eat_nonce": "test-nonce",
            "cmw": cmw_b64,
        })
        .to_string()
    }

    fn build_cca_evidence() -> (Vec<u8>, String) {
        let outblob = b"fake-cca-token-bytes".to_vec();
        let outblob_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&outblob);
        let tsm_report = serde_json::json!({
            "provider": "arm_cca_guest",
            "outblob": outblob_b64,
        });
        let evidence_b64 =
            general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&tsm_report).unwrap());
        (outblob, evidence_b64)
    }

    // -----------------------------------------------------------------------
    // CcaRatsdAttester nonce validation
    // -----------------------------------------------------------------------

    #[test]
    fn cca_ratsd_attester_rejects_invalid_nonce() {
        // CCA requires exactly 64 bytes; the attester must enforce this
        // before making any HTTP call.
        let attester = CcaRatsdAttester::with_url(url::Url::parse("http://127.0.0.1").unwrap());
        let result = attester.get_evidence(b"short");
        assert!(matches!(result.unwrap_err(), CcaError::InvalidNonce(_)));
    }

    // -----------------------------------------------------------------------
    // extract_cca_token - success cases
    // -----------------------------------------------------------------------

    #[test]
    fn extract_cca_token_returns_outblob_for_tsm_report_json() {
        // A well-formed legacy envelope containing a tsm-report+json item
        // with a CCA provider must yield the decoded outblob bytes.
        let (outblob, evidence_b64) = build_cca_evidence();
        let envelope = build_envelope(
            "tag:github.com,2025:veraison/ratsd/cmw",
            RATSD_TSM_REPORT_JSON,
            &evidence_b64,
        );
        let result = extract_cca_token(&envelope).unwrap();
        assert_eq!(result, outblob);
    }

    #[test]
    fn extract_cca_token_returns_outblob_for_tsm_report_cbor() {
        // The tsm-report+cbor media type must also be accepted.
        let (outblob, evidence_b64) = build_cca_evidence();
        let envelope = build_envelope(
            "tag:github.com,2025:veraison/ratsd/cmw",
            RATSD_TSM_REPORT_CBOR,
            &evidence_b64,
        );
        let result = extract_cca_token(&envelope).unwrap();
        assert_eq!(result, outblob);
    }

    // -----------------------------------------------------------------------
    // extract_cca_token - error cases
    // -----------------------------------------------------------------------

    #[test]
    fn extract_cca_token_returns_error_on_invalid_json() {
        // Completely malformed input must not panic.
        assert!(extract_cca_token("not-json-at-all").is_err());
    }

    #[test]
    fn extract_cca_token_returns_error_when_eat_profile_missing() {
        // A JSON object that lacks "eat_profile" must be rejected.
        let json = r#"{"cmw": "abc"}"#;
        assert!(extract_cca_token(json).is_err());
    }

    #[test]
    fn extract_cca_token_returns_error_on_unexpected_eat_profile() {
        // A legacy envelope with a different eat_profile must be rejected.
        let (_, evidence_b64) = build_cca_evidence();
        let envelope = serde_json::json!({
            "eat_profile": "tag:example.com,2026:not-ratsd",
            "cmw": general_purpose::URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&serde_json::json!({
                    "__cmwc_t": "tag:github.com,2025:veraison/ratsd/cmw",
                    "mock-cca": [RATSD_TSM_REPORT_JSON, evidence_b64],
                }))
                .unwrap()
            ),
        })
        .to_string();
        assert!(extract_cca_token(&envelope).is_err());
    }

    #[test]
    fn extract_cca_token_returns_error_when_cmw_field_missing() {
        // A JSON object with a valid profile but no "cmw" must be rejected.
        let json = r#"{"eat_profile":"tag:github.com,2024:veraison/ratsd"}"#;
        assert!(extract_cca_token(json).is_err());
    }

    #[test]
    fn extract_cca_token_returns_error_on_unexpected_cmw_collection_type() {
        // A CMW collection whose type is not the legacy RATSD collection
        // type must be rejected.
        let (_, evidence_b64) = build_cca_evidence();
        let envelope = build_envelope(
            "tag:example.com,2026:not-ratsd-cmw",
            RATSD_TSM_REPORT_JSON,
            &evidence_b64,
        );
        let err = extract_cca_token(&envelope).unwrap_err();
        assert!(
            matches!(err, RatsdError::ResponseParse(_)),
            "expected ResponseParse error, got {err:?}"
        );
    }

    #[test]
    fn extract_cca_token_returns_error_when_no_cca_provider_in_cmw() {
        // A well-formed envelope whose CMW contains only non-TSM items must
        // return a custom error, not a panic or a spurious success.
        let (_, evidence_b64) = build_cca_evidence();
        let envelope = build_envelope(
            "tag:github.com,2025:veraison/ratsd/cmw",
            "application/vnd.veraison.not-tsm+json",
            &evidence_b64,
        );
        let err = extract_cca_token(&envelope).unwrap_err();
        assert!(
            matches!(err, RatsdError::Custom(_)),
            "expected Custom error, got {err:?}"
        );
    }

    #[test]
    fn extract_cca_token_returns_error_on_non_cca_provider() {
        // A tsm-report item whose provider is not the CCA provider must
        // not yield evidence.
        let tsm_report = serde_json::json!({
            "provider": "some_other_provider",
            "outblob": general_purpose::URL_SAFE_NO_PAD.encode(b"x"),
        });
        let evidence_b64 =
            general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&tsm_report).unwrap());
        let envelope = build_envelope(
            "tag:github.com,2025:veraison/ratsd/cmw",
            RATSD_TSM_REPORT_JSON,
            &evidence_b64,
        );
        let err = extract_cca_token(&envelope).unwrap_err();
        assert!(
            matches!(err, RatsdError::Custom(_)),
            "expected Custom error, got {err:?}"
        );
    }

    #[test]
    fn extract_cca_token_returns_error_on_invalid_cmw_base64() {
        // An envelope with a "cmw" value that is not valid base64url must
        // be rejected.
        let envelope =
            r#"{"eat_profile":"tag:github.com,2024:veraison/ratsd","cmw":"!!!not-base64!!!"}"#;
        assert!(extract_cca_token(envelope).is_err());
    }
}
