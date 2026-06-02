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

    let cmw_b64 = envelope["cmw"]
        .as_str()
        .ok_or_else(|| RatsdError::ResponseParse("missing cmw field".into()))?;

    let cmw_bytes = general_purpose::STANDARD
        .decode(cmw_b64)
        .map_err(|e| RatsdError::ResponseParse(format!("cmw base64 decode: {e}")))?;

    let items = parse_cmw_items(&cmw_bytes)?;
    find_cca_outblob(&items)
}

fn parse_cmw_items(cmw_json: &[u8]) -> Result<Vec<Monad>, RatsdError> {
    let collection = Collection::unmarshal_json(cmw_json)
        .map_err(|e| RatsdError::ResponseParse(format!("CMW collection: {e}")))?;

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
        if !item.type_().contains("configfs-tsm") {
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
    // extract_cca_token — success case
    // -----------------------------------------------------------------------

    #[test]
    fn extract_cca_token_returns_outblob_for_valid_cca_cmw_envelope() {
        // A well-formed CMW envelope containing a CCA provider item must
        // yield the decoded outblob bytes.
        let outblob = b"fake-cca-token-bytes";
        let outblob_b64 = general_purpose::URL_SAFE_NO_PAD.encode(outblob);

        let tsm_report = serde_json::json!({
            "provider": "arm_cca_guest",
            "outblob": outblob_b64,
        });
        let evidence_b64 =
            general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&tsm_report).unwrap());

        let cmw_json = serde_json::json!({
            "__cmwc_t": "tag:github.com,2025:veraison/ratsd/cmw",
            "mock-cca": [
                "application/vnd.veraison.configfs-tsm+json",
                evidence_b64,
            ],
        });
        let cmw_b64 = general_purpose::STANDARD.encode(serde_json::to_vec(&cmw_json).unwrap());
        let envelope = format!(r#"{{"cmw": "{cmw_b64}"}}"#);

        let result = extract_cca_token(&envelope).unwrap();
        assert_eq!(result, outblob);
    }

    // -----------------------------------------------------------------------
    // extract_cca_token — error cases
    // -----------------------------------------------------------------------

    #[test]
    fn extract_cca_token_returns_error_on_invalid_json() {
        // Completely malformed input must not panic.
        assert!(extract_cca_token("not-json-at-all").is_err());
    }

    #[test]
    fn extract_cca_token_returns_error_when_cmw_field_missing() {
        // A valid JSON object that lacks "cmw" must be rejected.
        let json = r#"{"other_field": "somevalue"}"#;
        assert!(extract_cca_token(json).is_err());
    }

    #[test]
    fn extract_cca_token_returns_error_when_no_cca_provider_in_cmw() {
        // A well-formed envelope whose CMW contains only non-CCA items must
        // return a custom error, not a panic or a spurious success.
        // Build a minimal valid CMW collection with a non-CCA media type.
        let cmw_json =
            r#"{"__cmwc_t":"tag:example.com,2024:test","item1":["application/vnd.not-cca","YQ"]}"#;
        let b64 = general_purpose::STANDARD.encode(cmw_json.as_bytes());
        let envelope = format!(r#"{{"cmw": "{b64}"}}"#);
        let err = extract_cca_token(&envelope).unwrap_err();
        assert!(
            matches!(err, RatsdError::Custom(_)),
            "expected Custom error, got {err:?}"
        );
    }

    #[test]
    fn extract_cca_token_returns_error_on_invalid_cmw_base64() {
        // An envelope with a "cmw" value that is not valid base64 must be rejected.
        let envelope = r#"{"cmw": "!!!not-base64!!!"}"#;
        assert!(extract_cca_token(envelope).is_err());
    }
}
