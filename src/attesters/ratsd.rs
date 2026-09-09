// Copyright 2026 Contributors to the Veraison project
// SPDX-License-Identifier: Apache-2.0

//! Generic RATSD attester - posts a challenge to a RATSD daemon and
//! returns the raw JSON response.
//!
//! This module handles only the HTTP transport layer. Attester-specific
//! parsing (e.g. CCA evidence extraction from a CMW envelope) lives in
//! the relevant submodule (e.g. `attesters::cca::ratsd`).

use base64::{Engine, engine::general_purpose};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use std::time::Duration;
use thiserror::Error;
use url::Url;

use super::Attester;

const CHARES_PATH: &str = "/ratsd/chares";
const CHARES_CONTENT_TYPE: &str = "application/vnd.veraison.chares+json";
const CHARES_ACCEPT: &str =
    "application/eat-ucs+json; eat_profile=\"tag:github.com,2024:veraison/ratsd\"";
/// Response media type for the legacy chares API (ratsd.yaml).
const CHARES_RESPONSE_CONTENT_TYPE: &str =
    "application/eat-ucs+json; eat_profile=\"tag:github.com,2024:veraison/ratsd\"";
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

/// Generic RATSD attester. Returns the raw JSON response from the
/// daemon as bytes. Callers that need attester-specific parsing
/// (e.g. extracting a CCA token from a CMW envelope) should wrap
/// this attester.
pub struct RatsdAttester {
    url: Url,
}

impl RatsdAttester {
    /// Construct an attester that posts to `url`.
    pub fn with_url(url: Url) -> Self {
        Self { url }
    }
}

impl Attester for RatsdAttester {
    type AttesterError = RatsdError;

    fn get_evidence(&self, challenge: &[u8]) -> Result<Vec<u8>, Self::AttesterError> {
        let resp = post_challenge(&self.url, challenge)?;
        Ok(resp.into_bytes())
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// POST a challenge nonce to the RATSD `/ratsd/chares` endpoint.
/// Returns the response body as a string.
fn post_challenge(base_url: &Url, nonce: &[u8]) -> Result<String, RatsdError> {
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

    let status = resp.status();
    let full_content_type = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let resp_content_type = full_content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    let resp_body = resp.text()?;

    if !status.is_success() {
        // Per ratsd.yaml, errors are reported as application/problem+json
        // (RFC 7807). Extract the detail field when present.
        let body = if resp_content_type == PROBLEM_JSON {
            serde_json::from_str::<serde_json::Value>(&resp_body)
                .ok()
                .and_then(|v| v.get("detail").and_then(|d| d.as_str()).map(String::from))
                .unwrap_or(resp_body)
        } else {
            resp_body
        };
        return Err(RatsdError::HttpError {
            status: status.as_u16(),
            body,
        });
    }

    // Verify the response media type matches the legacy chares API.
    if full_content_type != CHARES_RESPONSE_CONTENT_TYPE {
        return Err(RatsdError::ResponseParse(format!(
            "unexpected response media type: {full_content_type}"
        )));
    }

    Ok(resp_body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;

    // -----------------------------------------------------------------------
    // Mock server - success path
    // -----------------------------------------------------------------------

    #[test]
    fn get_evidence_posts_challenge_and_returns_json_response() {
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
                    "application/eat-ucs+json; eat_profile=\"tag:github.com,2024:veraison/ratsd\"",
                )
                .body(r#"{"cmw":"eyJfX2Ntd2NfdCI6InRlc3QifQ=="}"#);
        });

        let evidence = RatsdAttester::with_url(Url::parse(&server.base_url()).unwrap())
            .get_evidence(&[0u8; 64])
            .unwrap();
        // Must return valid JSON.
        assert!(!evidence.is_empty());
        serde_json::from_slice::<serde_json::Value>(&evidence)
            .expect("response should be valid JSON");
        mock.assert();
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
            then.status(500).body("internal server error");
        });

        let err = RatsdAttester::with_url(Url::parse(&server.base_url()).unwrap())
            .get_evidence(&[0u8; 64])
            .unwrap_err();
        assert!(
            matches!(err, RatsdError::HttpError { status: 500, .. }),
            "expected HttpError(500), got {err:?}"
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

        let err = RatsdAttester::with_url(Url::parse(&server.base_url()).unwrap())
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
}
