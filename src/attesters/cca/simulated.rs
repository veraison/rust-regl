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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attesters::Attester;
    use crate::attesters::cca::CcaSimulatedAttester;

    const VALID_NONCE: &[u8; 64] = &[0u8; 64];

    #[test]
    fn fake_tsm_builder_chain_produces_report() {
        let report = FakeTsmBuilder::default()
            .inblob(vec![0u8; 64])
            .privlevel(2)
            .service_provider("test-provider".into())
            .service_guid([0xAA; 16])
            .get_report()
            .unwrap();
        assert!(!report.outblob.is_empty());
        assert!(report.auxblob.is_empty());
        assert!(report.manifestblob.is_empty());
    }

    #[test]
    fn simulated_attester_returns_non_empty_evidence_for_valid_nonce() {
        let evidence = CcaSimulatedAttester::default()
            .get_evidence(VALID_NONCE)
            .unwrap();
        assert!(!evidence.is_empty());
    }
}
