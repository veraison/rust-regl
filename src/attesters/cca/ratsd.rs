// Copyright 2026 Contributors to the Veraison project
// SPDX-License-Identifier: Apache-2.0

//! CCA-specific RATSD attester.
//!
//! Uses the generic [`RatsdAttester`](crate::attesters::ratsd::RatsdAttester)
//! to communicate with a RATSD daemon, then uses
//! [`RatsdToken`](crate::attesters::ratsd::utils::RatsdToken) to parse the
//! RATSD v2 token and extract the CCA attestation token from its CMW
//! collection.
//!
//! The caller receives only the raw CCA token bytes (CBOR-encoded COSE_Sign1).

use base64::{Engine, engine::general_purpose};
use cmw::CMW as CmwEnum;
use cmw::collection::Collection;
use serde_json::Value as JsonValue;

use super::{Attester, CcaError};
use crate::attesters::ratsd::utils::RatsdToken;
use crate::attesters::ratsd::{RatsdAttester, RatsdError};

const CCA_PROVIDER: &str = "arm_cca_guest";

/// RATSD media types from the RATSD API spec (docs/api/ratsd.yaml).
/// Only TSM report evidence is considered for CCA extraction; matching is
/// exact, per the `ratsd-collection` definition in docs/ratsd-token.cddl.
pub const RATSD_TSM_REPORT_JSON: &str = "application/vnd.veraison.tsm-report+json";
pub const RATSD_TSM_REPORT_CBOR: &str = "application/vnd.veraison.tsm-report+cbor";

/// CCA attester backed by a running RATSD daemon.
///
/// Wraps a generic [`RatsdAttester`] and applies CCA-specific
/// evidence extraction on top of the raw RATSD v2 token.
pub struct CcaRatsdAttester {
    ratsd: RatsdAttester,
}

impl CcaRatsdAttester {
    /// Construct a CCA RATSD attester that posts to `url`.
    pub fn with_url(url: &str) -> Result<Self, CcaError> {
        Ok(Self {
            ratsd: RatsdAttester::with_url(url)?,
        })
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
        let token = self.ratsd.get_evidence(challenge)?;
        Ok(extract_cca_token(&token)?)
    }
}

// ---------------------------------------------------------------------------
// CCA evidence extraction
// ---------------------------------------------------------------------------

fn extract_cca_token(token: &[u8]) -> Result<Vec<u8>, RatsdError> {
    let ratsd_token =
        RatsdToken::from_slice(token).map_err(|e| RatsdError::ResponseParse(e.to_string()))?;
    find_cca_outblob(&ratsd_token.collection)
}

fn find_cca_outblob(collection: &Collection) -> Result<Vec<u8>, RatsdError> {
    for meta in collection.get_meta() {
        let Some(CmwEnum::Monad(monad)) = collection.get_item(&meta.key) else {
            continue;
        };

        let media_type = monad.type_();
        let value = monad.value();

        // Exact match against the RATSD TSM report media types; the value
        // encoding differs between the JSON and CBOR variants.
        let parsed = match media_type.as_str() {
            RATSD_TSM_REPORT_JSON => parse_tsm_report_json(&value),
            RATSD_TSM_REPORT_CBOR => parse_tsm_report_cbor(&value),
            _ => None,
        };

        let Some((provider, outblob)) = parsed else {
            continue;
        };
        if provider != CCA_PROVIDER {
            continue;
        }

        return Ok(outblob);
    }

    Err(RatsdError::Custom(
        "CCA evidence not found in RATSD response".into(),
    ))
}

/// Parse a `tsm-report+json` monad value (docs/tsm-report.cddl): a JSON
/// object with a base64url-encoded `outblob`. Returns `None` if the value
/// is not a well-formed TSM report, so the caller can skip to the next item.
fn parse_tsm_report_json(value: &[u8]) -> Option<(String, Vec<u8>)> {
    let json: JsonValue = serde_json::from_slice(value).ok()?;
    let provider = json.get("provider")?.as_str()?.trim().to_string();
    let outblob_b64 = json.get("outblob")?.as_str()?;
    let outblob = general_purpose::URL_SAFE_NO_PAD.decode(outblob_b64).ok()?;
    Some((provider, outblob))
}

/// Parse a `tsm-report+cbor` monad value (docs/tsm-report.cddl): a CBOR map
/// with a raw byte-string `outblob`. Returns `None` if the value is not a
/// well-formed TSM report, so the caller can skip to the next item.
fn parse_tsm_report_cbor(value: &[u8]) -> Option<(String, Vec<u8>)> {
    let cbor: ciborium::Value = ciborium::from_reader(value).ok()?;
    let map = cbor.as_map()?;
    let provider = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("provider"))
        .and_then(|(_, v)| v.as_text())?
        .trim()
        .to_string();
    let outblob = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("outblob"))
        .and_then(|(_, v)| v.as_bytes())?
        .clone();
    Some((provider, outblob))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attesters::Attester;
    use crate::attesters::cca::CcaError;
    use crate::attesters::ratsd::utils::{RATSD_CLAIMS_KEY, RATSD_CMWCT_V2, RATSD_V2_PROFILE};
    use cmw::collection::{Label as CmwLabel, Type as CmwType};
    use cmw::monad::Monad;
    use coset::CoseSign1Builder;
    use coset::TaggedCborSerializable;
    use httpmock::prelude::*;

    // -----------------------------------------------------------------------
    // Test fixtures
    //
    // RatsdToken parsing itself (COSE_Sign1, CMW collection, claims) is
    // covered by attesters::ratsd::utils's own tests; the fixtures and
    // tests here only need to build well-formed RATSD v2 tokens and focus
    // on CCA-specific outblob extraction.
    // -----------------------------------------------------------------------

    /// Build the CBOR-encoded, tag-601 RATSD claims record (ratsd-token.cddl).
    fn build_claims_cbor(profile: &str) -> Vec<u8> {
        let map = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(265.into()),
                ciborium::Value::Text(profile.to_string()),
            ),
            (
                ciborium::Value::Integer(10.into()),
                ciborium::Value::Bytes(vec![0u8; 32]),
            ),
            (
                ciborium::Value::Integer(258.into()),
                ciborium::Value::Integer(48482.into()),
            ),
            (
                ciborium::Value::Integer(270.into()),
                ciborium::Value::Text("ratsd".into()),
            ),
            (
                ciborium::Value::Integer(271.into()),
                ciborium::Value::Array(vec![ciborium::Value::Text("1.0.0".into())]),
            ),
        ]);
        let tagged = ciborium::Value::Tag(601, Box::new(map));
        let mut buf = Vec::new();
        ciborium::into_writer(&tagged, &mut buf).unwrap();
        buf
    }

    /// Build a RATSD v2 token (COSE_Sign1-wrapped CMW collection, per
    /// ratsd-token.cddl) carrying a single leaf-attester record.
    fn build_v2_token(profile: &str, media_type: &str, value: Vec<u8>) -> Vec<u8> {
        let mut collection =
            Collection::new(Some(CmwType::new(RATSD_CMWCT_V2).unwrap()), None).unwrap();

        let claims_media_type = format!("application/eat-ucs+cbor; eat_profile=\"{profile}\"");
        let claims_monad = Monad::new_media_type(
            claims_media_type.parse().unwrap(),
            build_claims_cbor(profile),
            None,
        )
        .unwrap();
        collection
            .add_item(
                CmwLabel::Str(RATSD_CLAIMS_KEY.to_string()),
                CmwEnum::Monad(claims_monad),
            )
            .unwrap();

        let leaf_monad = Monad::new_media_type(media_type.parse().unwrap(), value, None).unwrap();
        collection
            .add_item(
                CmwLabel::Str("mock-cca".to_string()),
                CmwEnum::Monad(leaf_monad),
            )
            .unwrap();

        let payload = collection.marshal_cbor().unwrap();
        let sign1 = CoseSign1Builder::new().payload(payload).build();
        sign1.to_tagged_vec().unwrap()
    }

    fn build_tsm_report_json(provider: &str, outblob: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "provider": provider,
            "outblob": general_purpose::URL_SAFE_NO_PAD.encode(outblob),
        }))
        .unwrap()
    }

    fn build_tsm_report_cbor(provider: &str, outblob: &[u8]) -> Vec<u8> {
        let map = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("outblob".into()),
                ciborium::Value::Bytes(outblob.to_vec()),
            ),
            (
                ciborium::Value::Text("provider".into()),
                ciborium::Value::Text(provider.to_string()),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&map, &mut buf).unwrap();
        buf
    }

    // -----------------------------------------------------------------------
    // CcaRatsdAttester construction and nonce validation
    // -----------------------------------------------------------------------

    #[test]
    fn cca_ratsd_attester_rejects_invalid_url() {
        assert!(CcaRatsdAttester::with_url("not a url").is_err());
    }

    #[test]
    fn cca_ratsd_attester_rejects_invalid_nonce() {
        // CCA requires exactly 64 bytes; the attester must enforce this
        // before making any HTTP call.
        let attester = CcaRatsdAttester::with_url("http://127.0.0.1").unwrap();
        let result = attester.get_evidence(b"short");
        assert!(matches!(result.unwrap_err(), CcaError::InvalidNonce(_)));
    }

    #[test]
    fn cca_ratsd_attester_get_evidence_round_trips_through_http() {
        // End-to-end: CcaRatsdAttester posts over HTTP, then extracts the
        // outblob from the v2 token in the response, not just the
        // extract_cca_token() unit tested below in isolation.
        let outblob = b"fake-cca-token-bytes".to_vec();
        let token = build_v2_token(
            RATSD_V2_PROFILE,
            RATSD_TSM_REPORT_JSON,
            build_tsm_report_json(CCA_PROVIDER, &outblob),
        );

        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST).path("/ratsd/chares");
            then.status(200)
                .header(
                    "Content-Type",
                    "application/cmw+cbor; cmwct=\"tag:github.com,2026:veraison/ratsd/v2\"",
                )
                .body(token);
        });

        let attester = CcaRatsdAttester::with_url(&server.base_url()).unwrap();
        let result = attester.get_evidence(&[0u8; 64]).unwrap();
        assert_eq!(result, outblob);
        mock.assert();
    }

    // -----------------------------------------------------------------------
    // extract_cca_token - success cases
    // -----------------------------------------------------------------------

    #[test]
    fn extract_cca_token_returns_outblob_for_tsm_report_json() {
        // A well-formed v2 token containing a tsm-report+json item with a
        // CCA provider must yield the decoded outblob bytes.
        let outblob = b"fake-cca-token-bytes".to_vec();
        let token = build_v2_token(
            RATSD_V2_PROFILE,
            RATSD_TSM_REPORT_JSON,
            build_tsm_report_json(CCA_PROVIDER, &outblob),
        );
        let result = extract_cca_token(&token).unwrap();
        assert_eq!(result, outblob);
    }

    #[test]
    fn extract_cca_token_returns_outblob_for_tsm_report_cbor() {
        // The tsm-report+cbor media type must also be accepted, with the
        // outblob as a raw byte string rather than base64url text.
        let outblob = b"fake-cca-token-bytes".to_vec();
        let token = build_v2_token(
            RATSD_V2_PROFILE,
            RATSD_TSM_REPORT_CBOR,
            build_tsm_report_cbor(CCA_PROVIDER, &outblob),
        );
        let result = extract_cca_token(&token).unwrap();
        assert_eq!(result, outblob);
    }

    // -----------------------------------------------------------------------
    // extract_cca_token - error cases
    // -----------------------------------------------------------------------

    #[test]
    fn extract_cca_token_propagates_ratsd_token_parse_errors() {
        // A malformed RATSD v2 token (invalid COSE_Sign1) must surface as
        // a RatsdError::ResponseParse; the specific RatsdToken parsing
        // failure modes are covered by attesters::ratsd::utils's tests.
        let err = extract_cca_token(b"not-a-cose-token").unwrap_err();
        assert!(
            matches!(err, RatsdError::ResponseParse(_)),
            "expected ResponseParse error, got {err:?}"
        );
    }

    #[test]
    fn extract_cca_token_returns_error_when_no_cca_provider_in_cmw() {
        // A well-formed token whose CMW contains only non-TSM items must
        // return a custom error, not a panic or a spurious success.
        let token = build_v2_token(
            RATSD_V2_PROFILE,
            "application/vnd.veraison.not-tsm+json",
            build_tsm_report_json(CCA_PROVIDER, b"x"),
        );
        let err = extract_cca_token(&token).unwrap_err();
        assert!(
            matches!(err, RatsdError::Custom(_)),
            "expected Custom error, got {err:?}"
        );
    }

    #[test]
    fn extract_cca_token_returns_error_on_non_cca_provider() {
        // A tsm-report item whose provider is not the CCA provider must
        // not yield evidence.
        let token = build_v2_token(
            RATSD_V2_PROFILE,
            RATSD_TSM_REPORT_JSON,
            build_tsm_report_json("some_other_provider", b"x"),
        );
        let err = extract_cca_token(&token).unwrap_err();
        assert!(
            matches!(err, RatsdError::Custom(_)),
            "expected Custom error, got {err:?}"
        );
    }
}
