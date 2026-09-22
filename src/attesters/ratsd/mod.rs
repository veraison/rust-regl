// Copyright 2026 Contributors to the Veraison project
// SPDX-License-Identifier: Apache-2.0

//! Generic RATSD attester - posts a challenge to a RATSD daemon and
//! returns the raw JSON response.
//!
//! This module handles only the HTTP transport layer. Attester-specific
//! parsing (e.g. CCA evidence extraction from a CMW envelope) lives in
//! the relevant submodule (e.g. `attesters::cca::ratsd`). Parsing of the
//! RATSD v2 token itself (COSE_Sign1 + CMW collection + claims) lives in
//! [`utils`].

use base64::{Engine, engine::general_purpose};
use mime::Mime;
use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use std::time::Duration;
use thiserror::Error;
use url::Url;

use super::Attester;

pub mod utils;

use utils::RATSD_V2_PROFILE;

const CHARES_PATH: &str = "/ratsd/chares";
const CHARES_CONTENT_TYPE: &str = "application/vnd.veraison.chares+json";
/// Expected response media type essence, per the same CDDL production.
const CHARES_RESPONSE_ESSENCE: &str = "application/cmw+cbor";
/// Request media type for the RATSD v2 token (ratsd-token.cddl): a CMW
/// collection wrapped in a COSE_Sign1, CBOR-only.
const CHARES_ACCEPT: &str = const_format::concatcp!(
    CHARES_RESPONSE_ESSENCE,
    "; cmwct=\"",
    RATSD_V2_PROFILE,
    "\""
);
/// Name of the media type parameter identifying the RATSD v2 token.
const CHARES_RESPONSE_CMWCT_PARAM: &str = "cmwct";
/// Media type for error responses per the RATSD API spec (RFC 7807).
const PROBLEM_JSON: &str = "application/problem+json";
/// Default HTTP timeout for RATSD requests.
const TIMEOUT_SECS: u64 = 30;

/// Errors that can arise from the RATSD HTTP transport layer.
#[derive(Debug, Error)]
pub enum RatsdError {
    #[error("RATSD request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),

    #[error("RATSD returned HTTP {status}: {body}")]
    HttpError { status: u16, body: String },

    #[error("failed to parse RATSD response: {0}")]
    ResponseParse(String),

    #[error("{0}")]
    Custom(String),
}

/// Generic RATSD attester. Returns the raw RATSD v2 token bytes
/// (COSE_Sign1-wrapped CMW collection) from the daemon. Callers that
/// need attester-specific parsing (e.g. extracting a CCA token) should
/// wrap this attester.
pub struct RatsdAttester {
    url: Url,
}

impl RatsdAttester {
    /// Construct an attester that posts to `url`.
    pub fn with_url(url: &str) -> Result<Self, RatsdError> {
        let url = Url::parse(url)
            .map_err(|e| RatsdError::ResponseParse(format!("invalid RATSD URL: {e}")))?;
        Ok(Self { url })
    }
}

impl Attester for RatsdAttester {
    type AttesterError = RatsdError;

    fn get_evidence(&self, challenge: &[u8]) -> Result<Vec<u8>, Self::AttesterError> {
        post_challenge(&self.url, challenge)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// POST a challenge nonce to the RATSD `/ratsd/chares` endpoint.
/// Returns the raw response body bytes (a RATSD v2 CBOR token on success).
fn post_challenge(base_url: &Url, nonce: &[u8]) -> Result<Vec<u8>, RatsdError> {
    let http = Client::builder()
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .build()?;

    let nonce_b64 = general_purpose::URL_SAFE_NO_PAD.encode(nonce);
    let body = serde_json::json!({ "nonce": nonce_b64 });

    let url = base_url
        .join(CHARES_PATH)
        .map_err(|e| RatsdError::ResponseParse(format!("invalid RATSD URL: {e}")))?;

    let resp = http
        .post(url.clone())
        .header(CONTENT_TYPE, CHARES_CONTENT_TYPE)
        .header(ACCEPT, CHARES_ACCEPT)
        .json(&body)
        .send()?;

    if !resp.status().is_success() {
        return Err(report_problem(resp));
    }

    // The Content-Type must be present, well-formed, and match the RATSD v2
    // token API: the essence must be application/cmw+cbor and the cmwct
    // parameter must identify the v2 profile.
    let content_type_header = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let resp_bytes = resp.bytes()?.to_vec();

    let content_type: Mime = content_type_header
        .as_deref()
        .unwrap_or("")
        .parse()
        .map_err(|e| RatsdError::ResponseParse(format!("invalid response Content-Type: {e}")))?;
    let matches_v2 = content_type.essence_str() == CHARES_RESPONSE_ESSENCE
        && content_type
            .get_param(CHARES_RESPONSE_CMWCT_PARAM)
            .is_some_and(|v| v == RATSD_V2_PROFILE);
    if !matches_v2 {
        return Err(RatsdError::ResponseParse(format!(
            "unexpected response media type: {content_type}"
        )));
    }

    Ok(resp_bytes)
}

/// Convert a non-success RATSD response into a client-facing error carrying
/// the HTTP status and the response body.
///
/// Per ratsd.yaml, errors are reported as application/problem+json (RFC 7807)
/// regardless of the negotiated success media type; the `detail` field is
/// extracted when present. A malformed or missing Content-Type must not mask
/// the status - the body is used verbatim unless it is well-formed
/// problem+json.
fn report_problem(resp: Response) -> RatsdError {
    let status = resp.status();
    let content_type_header = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let resp_bytes = match resp.bytes() {
        Ok(bytes) => bytes.to_vec(),
        Err(e) => return RatsdError::RequestFailed(e),
    };

    let problem_json = content_type_header
        .as_deref()
        .and_then(|v| v.parse::<Mime>().ok())
        .is_some_and(|ct| ct.essence_str() == PROBLEM_JSON);
    let body = if problem_json {
        match serde_json::from_slice::<serde_json::Value>(&resp_bytes) {
            Ok(json) => json
                .get("detail")
                .and_then(|d| d.as_str())
                .map(String::from)
                .unwrap_or_else(|| String::from_utf8_lossy(&resp_bytes).into_owned()),
            Err(e) => {
                return RatsdError::ResponseParse(format!("invalid problem+json error body: {e}"));
            }
        }
    } else {
        String::from_utf8_lossy(&resp_bytes).into_owned()
    };

    RatsdError::HttpError {
        status: status.as_u16(),
        body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;

    // -----------------------------------------------------------------------
    // Mock server - success path
    // -----------------------------------------------------------------------

    #[test]
    fn get_evidence_posts_challenge_and_returns_raw_bytes() {
        // Use with_url() to avoid touching global env-var state, which races
        // with other tests running in parallel.
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/ratsd/chares")
                .header("Content-Type", "application/vnd.veraison.chares+json");
            then.status(200)
                .header(
                    "Content-Type",
                    "application/cmw+cbor; cmwct=\"tag:github.com,2026:veraison/ratsd/v2\"",
                )
                .body([0xd2, 0x84, 0x40, 0xa0, 0x40, 0x41, 0x00]);
        });

        let evidence = RatsdAttester::with_url(&server.base_url())
            .unwrap()
            .get_evidence(&[0u8; 64])
            .unwrap();
        // The transport must return the response body byte-for-byte.
        assert_eq!(evidence, vec![0xd2, 0x84, 0x40, 0xa0, 0x40, 0x41, 0x00]);
        mock.assert();
    }

    #[test]
    fn get_evidence_returns_error_on_unexpected_success_media_type() {
        // A 200 response whose Content-Type does not match the negotiated
        // v2 media type must be rejected, not silently accepted.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/ratsd/chares");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(r#"{"unexpected":"body"}"#);
        });

        let err = RatsdAttester::with_url(&server.base_url())
            .unwrap()
            .get_evidence(&[0u8; 64])
            .unwrap_err();
        assert!(
            matches!(err, RatsdError::ResponseParse(_)),
            "expected ResponseParse error, got {err:?}"
        );
    }

    #[test]
    fn get_evidence_returns_error_on_mismatched_cmwct_param() {
        // The essence matching but the cmwct parameter identifying a
        // different profile must still be rejected.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/ratsd/chares");
            then.status(200)
                .header(
                    "Content-Type",
                    "application/cmw+cbor; cmwct=\"tag:example.com,2026:not-ratsd\"",
                )
                .body([0xd2, 0x84, 0x40, 0xa0, 0x40, 0x41, 0x00]);
        });

        let err = RatsdAttester::with_url(&server.base_url())
            .unwrap()
            .get_evidence(&[0u8; 64])
            .unwrap_err();
        assert!(
            matches!(err, RatsdError::ResponseParse(_)),
            "expected ResponseParse error, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Mock server - error path
    // -----------------------------------------------------------------------

    #[test]
    fn get_evidence_returns_http_error_on_non_2xx_response() {
        // A 500 from the server must produce RatsdError::HttpError with the
        // correct status code, not a panic or a success result.
        // Use with_url() to avoid global env-var races with parallel tests.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/ratsd/chares");
            then.status(500)
                .header("Content-Type", "text/plain")
                .body("internal server error");
        });

        let err = RatsdAttester::with_url(&server.base_url())
            .unwrap()
            .get_evidence(&[0u8; 64])
            .unwrap_err();
        assert!(
            matches!(err, RatsdError::HttpError { status: 500, .. }),
            "expected HttpError(500), got {err:?}"
        );
    }

    #[test]
    fn get_evidence_reports_status_when_content_type_missing_on_error_response() {
        // A response with no Content-Type header must still surface the HTTP
        // status: a missing header must not mask the status error, which is
        // more meaningful to the client.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/ratsd/chares");
            then.status(500).body("internal server error");
        });

        let err = RatsdAttester::with_url(&server.base_url())
            .unwrap()
            .get_evidence(&[0u8; 64])
            .unwrap_err();
        match err {
            RatsdError::HttpError { status, body } => {
                assert_eq!(status, 500);
                assert_eq!(body, "internal server error");
            }
            other => panic!("expected HttpError(500), got {other:?}"),
        }
    }

    #[test]
    fn get_evidence_reports_status_when_content_type_malformed_on_error_response() {
        // An unparseable Content-Type must be treated like a missing one:
        // the caller still gets an HttpError carrying the status and the
        // raw body, not a Content-Type parse error.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/ratsd/chares");
            then.status(503)
                .header("Content-Type", "not a valid media type")
                .body("service unavailable");
        });

        let err = RatsdAttester::with_url(&server.base_url())
            .unwrap()
            .get_evidence(&[0u8; 64])
            .unwrap_err();
        match err {
            RatsdError::HttpError { status, body } => {
                assert_eq!(status, 503);
                assert_eq!(body, "service unavailable");
            }
            other => panic!("expected HttpError(503), got {other:?}"),
        }
    }

    #[test]
    fn get_evidence_returns_error_on_invalid_problem_json_body() {
        // A response claiming to be problem+json but not valid JSON must
        // be rejected, not silently downgraded to a plain-text error body.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/ratsd/chares");
            then.status(400)
                .header("Content-Type", "application/problem+json")
                .body("not json");
        });

        let err = RatsdAttester::with_url(&server.base_url())
            .unwrap()
            .get_evidence(&[0u8; 64])
            .unwrap_err();
        assert!(
            matches!(err, RatsdError::ResponseParse(_)),
            "expected ResponseParse error, got {err:?}"
        );
    }

    #[test]
    fn get_evidence_extracts_detail_from_problem_json_error() {
        // Per ratsd.yaml, errors are application/problem+json (RFC 7807).
        // The detail field must surface in the error body.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/ratsd/chares");
            then.status(400)
                .header("Content-Type", "application/problem+json")
                .body(
                    r#"{"type":"tag:github.com,2024:veraison/ratsd:error:invalidrequest",
                        "title":"invalid request","status":400,"detail":"bad nonce"}"#,
                );
        });

        let err = RatsdAttester::with_url(&server.base_url())
            .unwrap()
            .get_evidence(&[0u8; 64])
            .unwrap_err();
        match err {
            RatsdError::HttpError { status, body } => {
                assert_eq!(status, 400);
                assert_eq!(body, "bad nonce");
            }
            other => panic!("expected HttpError, got {other:?}"),
        }
    }

    #[test]
    fn with_url_returns_error_on_invalid_url() {
        assert!(RatsdAttester::with_url("not a url").is_err());
    }
}
