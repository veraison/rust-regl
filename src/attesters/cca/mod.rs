// Copyright 2026 Contributors to the Veraison project
// SPDX-License-Identifier: Apache-2.0

use super::Attester;
use crate::tsm::linuxtsm::LinuxTsmReportBuilder;
use crate::tsm::{TsmError, TsmReport, TsmReportBuilder};
use thiserror::Error;

type Result<T> = std::result::Result<T, CcaError>;

pub mod utils;

mod ratsd;
mod simulated;

pub use ratsd::CcaRatsdAttester;
pub use simulated::CcaSimulatedAttester;
pub use utils::CcaTokenFormat;

/// Arm CCA nonce size in bytes, as required by the CCA specification
/// (https://datatracker.ietf.org/doc/draft-ffm-rats-cca-token/).
const NONCE_SIZE: usize = 64;

/// configfs-tsm provider a CCA TSM report must come from.
const CCA_TSM_PROVIDER: &str = "arm_cca_guest";

#[derive(Debug, Default)]
pub struct CcaTsmAttester {}

impl Attester for CcaTsmAttester {
    type AttesterError = CcaError;

    fn get_evidence(&self, challenge: &[u8]) -> Result<Vec<u8>> {
        if challenge.len() != NONCE_SIZE {
            return Err(CcaError::InvalidNonce(format!(
                "expected {NONCE_SIZE} bytes, got {}",
                challenge.len()
            )));
        }
        let builder = LinuxTsmReportBuilder::create()?;
        // A configfs-tsm report from a non-CCA provider (SEV-SNP, TDX, ...)
        // is not CCA evidence and must not be treated as such (NT_47).
        ensure_cca_provider(&builder.provider())?;
        let challenge = challenge.to_vec();
        Ok(get_tsm_report(builder, challenge)?.outblob)
    }
}

/// Reject configfs-tsm providers other than Arm CCA.
fn ensure_cca_provider(provider: &str) -> Result<()> {
    if provider != CCA_TSM_PROVIDER {
        return Err(CcaError::UnsupportedProvider(provider.to_string()));
    }
    Ok(())
}

fn get_tsm_report<B>(generator: B, inblob: Vec<u8>) -> Result<TsmReport>
where
    B: TsmReportBuilder,
{
    Ok(generator.inblob(inblob).get_report()?)
}

#[derive(Error, Debug)]
pub enum CcaError {
    #[error("TSM error")]
    Tsm(#[from] TsmError),

    #[error("unsupported TSM provider: {0} (expected arm_cca_guest)")]
    UnsupportedProvider(String),

    #[error("invalid nonce: {0}")]
    InvalidNonce(String),

    #[error("{0}")]
    Custom(String),

    #[error("RATSD error: {0}")]
    Ratsd(#[from] crate::attesters::ratsd::RatsdError),
}

impl CcaError {
    pub fn custom<T>(msg: T) -> Self
    where
        T: std::fmt::Display,
    {
        Self::Custom(msg.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attesters::Attester;

    // --- CcaTsmAttester nonce validation ---

    #[test]
    fn tsm_attester_rejects_short_nonce() {
        // CCA requires exactly 64 bytes; anything shorter must be rejected.
        let result = CcaTsmAttester::default().get_evidence(b"too-short");
        assert!(matches!(result.unwrap_err(), CcaError::InvalidNonce(_)));
    }

    #[test]
    fn tsm_attester_rejects_long_nonce() {
        // Nonces longer than 64 bytes must also be rejected.
        let long = vec![0u8; 65];
        let result = CcaTsmAttester::default().get_evidence(&long);
        assert!(matches!(result.unwrap_err(), CcaError::InvalidNonce(_)));
    }

    // --- Error propagation ---

    #[test]
    fn tsm_error_propagates_as_cca_tsm_variant() {
        // From<TsmError> for CcaError must produce CcaError::Tsm, not any
        // other variant, so callers can match on it specifically.
        let cca: CcaError = TsmError::Unsupported.into();
        assert!(matches!(cca, CcaError::Tsm(_)));
    }

    #[test]
    fn generic_ratsd_error_propagates_as_cca_ratsd_variant() {
        // From<RatsdError> for CcaError must produce CcaError::Ratsd,
        // so callers get a single CcaError type regardless of the error source.
        let generic = crate::attesters::ratsd::RatsdError::ResponseParse("test".into());
        let cca: CcaError = generic.into();
        assert!(matches!(cca, CcaError::Ratsd(_)));
    }

    #[test]
    fn cca_error_custom_wraps_message() {
        let err = CcaError::custom("something went wrong");
        let msg = format!("{err}");
        assert!(msg.contains("something went wrong"));
    }

    // --- Error display ---

    #[test]
    fn invalid_nonce_displays_message() {
        // Test that the Display impl formats the error with the expected and actual lengths.
        // Using a sample bad length of 5 bytes for a visual check; the real value is
        // generated at runtime based on the actual nonce passed by the caller.
        let err = CcaError::InvalidNonce(format!(
            "expected {} bytes, got {}",
            NONCE_SIZE,
            b"short".len()
        ));
        let msg = format!("{err}");
        assert!(msg.contains("invalid nonce"));
        assert!(msg.contains("64"));
        assert!(msg.contains("5"));
    }

    #[test]
    fn tsm_error_displays_message() {
        let err = CcaError::Tsm(TsmError::Unsupported);
        let msg = format!("{err}");
        assert!(msg.contains("TSM error"));
    }

    // --- configfs-tsm provider validation ---

    #[test]
    fn cca_provider_is_accepted() {
        assert!(ensure_cca_provider("arm_cca_guest").is_ok());
    }

    #[test]
    fn non_cca_provider_is_rejected_with_its_name() {
        let err = ensure_cca_provider("tdx_guest").unwrap_err();
        assert!(matches!(err, CcaError::UnsupportedProvider(_)));
        let msg = format!("{err}");
        assert!(
            msg.contains("tdx_guest") && msg.contains("arm_cca_guest"),
            "msg was: {msg}"
        );
    }

    #[test]
    fn ratsd_error_displays_message() {
        let err = CcaError::Ratsd(crate::attesters::ratsd::RatsdError::Custom(
            "bad response".into(),
        ));
        let msg = format!("{err}");
        assert!(msg.contains("RATSD error"));
        assert!(msg.contains("bad response"));
    }
}
