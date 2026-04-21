use crate::tsm::{TsmError, TsmReport, TsmReportBuilder};

#[derive(Debug, Default)]
pub struct FakeTsmBuilder {
    provider: String,
    inblob: Vec<u8>,
}

impl TsmReportBuilder for FakeTsmBuilder {
    fn provider(&self) -> String {
        self.provider.clone()
    }

    fn privlevel_floor(&self) -> u32 {
        0
    }

    fn inblob(mut self, blob: Vec<u8>) -> Self {
        self.inblob = blob;
        self
    }

    fn privlevel(self, _: u32) -> Self {
        self
    }

    fn service_provider(self, _: String) -> Self {
        self
    }

    fn service_guid(self, _: [u8; 16]) -> Self {
        self
    }

    fn get_report(self) -> Result<TsmReport, TsmError> {
        generate_simulated_evidence(self.inblob)
    }
}

fn generate_simulated_evidence(_challenge: Vec<u8>) -> Result<TsmReport, TsmError> {
    Ok(TsmReport {
        outblob: Vec::from(include_bytes!("data/evidence.cbor")),
        auxblob: Vec::new(),
        manifestblob: Vec::new(),
    })
}
