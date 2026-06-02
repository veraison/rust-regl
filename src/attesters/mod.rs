pub mod cca;
pub mod ratsd;

pub trait Attester {
    type AttesterError: std::error::Error;

    fn get_evidence(&self, challenge: &[u8]) -> Result<Vec<u8>, Self::AttesterError>;
}
