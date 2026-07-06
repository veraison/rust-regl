mod error;
pub mod linuxtsm;
pub use error::TsmError;

#[derive(Debug, Default)]
pub struct TsmReport {
    /// outblob that contains the report
    pub outblob: Vec<u8>,
    /// auxblob containing auxiliary data
    pub auxblob: Vec<u8>,
    /// manifest blob
    pub manifestblob: Vec<u8>,
}

/// Trait implemented by builder of TsmReport.
///
/// The constructor of the builder does the mkdir of the report instance.
/// This trait contains methods for inspecting the report instance and
/// transforming it into the report (reading the information emitted by
/// TSM).
pub trait TsmReportBuilder {
    /// get the provider attribute
    fn provider(&self) -> String;

    /// get the privlevel_floor attribute
    fn privlevel_floor(&self) -> u32;

    /// set inblob. The actual write system call may not happen
    /// during this call, instead may happen during the get function
    /// call.
    fn inblob(self, blob: Vec<u8>) -> Self;

    /// set privlevel
    fn privlevel(self, lev: u32) -> Self;

    /// set service_provider
    fn service_provider(self, provider: String) -> Self;

    /// set service_guid
    fn service_guid(self, guid: [u8; 16]) -> Self;

    /// construct the report. This involves reading the blobs
    /// emitted by TSM
    fn get_report(self) -> Result<TsmReport, TsmError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tsm_report_default_has_empty_blobs() {
        // TsmReport::default() must initialise all three blobs to empty - a
        // non-empty default would silently carry stale data into callers.
        let report = TsmReport::default();
        assert!(report.outblob.is_empty());
        assert!(report.auxblob.is_empty());
        assert!(report.manifestblob.is_empty());
    }
}
