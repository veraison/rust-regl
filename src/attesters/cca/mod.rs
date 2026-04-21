use super::Attester;
use crate::tsm::linuxtsm::LinuxTsmReportBuilder;
use crate::tsm::{TsmError, TsmReport, TsmReportBuilder};
use thiserror::Error;

type Result<T> = std::result::Result<T, CcaError>;

mod simulated;

use simulated::FakeTsmBuilder;

#[derive(Debug, Default)]
pub struct CcaTsmAttester {}

#[derive(Debug, Default)]
pub struct CcaSimulatedAttester {}

impl Attester for CcaTsmAttester {
    type AttesterError = CcaError;

    fn get_evidence(&self, challenge: &[u8]) -> Result<Vec<u8>> {
        let builder = LinuxTsmReportBuilder::create()?;
        let challenge = challenge.to_vec();
        Ok(get_tsm_report(builder, challenge)?.outblob)
    }
}

impl Attester for CcaSimulatedAttester {
    type AttesterError = CcaError;

    fn get_evidence(&self, challenge: &[u8]) -> Result<Vec<u8>> {
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
#[error("CCA attester failed")]
pub struct CcaError(
    #[source]
    #[from]
    TsmError,
);
