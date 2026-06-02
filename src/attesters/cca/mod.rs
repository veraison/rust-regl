use super::Attester;
use crate::tsm::linuxtsm::LinuxTsmReportBuilder;
use crate::tsm::{TsmError, TsmReport, TsmReportBuilder};
use thiserror::Error;

type Result<T> = std::result::Result<T, CcaError>;

pub mod utils;

mod ratsd;
mod simulated;

pub use ratsd::CcaRatsdAttester;
use simulated::FakeTsmBuilder;

/// Arm CCA nonce size in bytes, as required by the CCA specification
/// (https://datatracker.ietf.org/doc/draft-ffm-rats-cca-token/).
const NONCE_SIZE: usize = 64;

#[derive(Debug, Default)]
pub struct CcaTsmAttester {}

#[derive(Debug, Default)]
pub struct CcaSimulatedAttester {}

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
        let challenge = challenge.to_vec();
        Ok(get_tsm_report(builder, challenge)?.outblob)
    }
}

impl Attester for CcaSimulatedAttester {
    type AttesterError = CcaError;

    fn get_evidence(&self, challenge: &[u8]) -> Result<Vec<u8>> {
        if challenge.len() != NONCE_SIZE {
            return Err(CcaError::InvalidNonce(format!(
                "expected {NONCE_SIZE} bytes, got {}",
                challenge.len()
            )));
        }
        let builder = FakeTsmBuilder::default();
        let challenge = challenge.to_vec();
        Ok(get_tsm_report(builder, challenge)?.outblob)
    }
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
}
