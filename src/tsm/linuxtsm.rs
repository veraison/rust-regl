use super::{TsmError, TsmReport, TsmReportBuilder};

use std::fs;
use std::path::PathBuf;
use tempfile::tempdir_in;

const TSM_REPORT_PATH: &str = "/sys/kernel/config/tsm/report";

type Result<T> = std::result::Result<T, TsmError>;

#[derive(Debug, Default)]
pub struct LinuxTsmReportBuilder {
    provider: String,
    privlevel_floor: u32,
    inblob: Vec<u8>,
    privlevel: Option<u32>,
    service_provider: Option<String>,
    service_guid: Option<[u8; 16]>,
    num_writes: u32,
    path: PathBuf,
}

impl LinuxTsmReportBuilder {
    pub fn create() -> Result<Self> {
        let s = fs::exists(TSM_REPORT_PATH)
            .map_err(|e| TsmError::from(e).context("failed to check if TSM dir exists"))?;
        if !s {
            return Err(TsmError::Unsupported);
        }
        let dir = tempdir_in(TSM_REPORT_PATH)
            .map_err(|e| TsmError::from(e).context("failed to create report instance"))?;
        let path = dir.keep();
        let mut builder = Self::default();
        builder.path = path;
        builder.provider = builder.read_to_string("provider", false)?;
        builder.privlevel_floor = builder.read_to_int("privlevel_floor")?;
        Ok(builder)
    }

    fn read_file(&self, file: &str) -> Result<Vec<u8>> {
        let path = self.path.clone().join(file);
        fs::read(&path)
            .map_err(|e| TsmError::from(e).context(format!("failed to read from {file:?}")))
    }

    fn read_file_opt(&self, file: &str) -> Result<Vec<u8>> {
        let path = self.path.clone().join(file);
        if path.exists() {
            fs::read(&path)
                .map_err(|e| TsmError::from(e).context(format!("failed to read from {file:?}")))
        } else {
            Ok(Vec::new())
        }
    }

    fn read_to_string(&self, file: &str, opt: bool) -> Result<String> {
        let read_fn = if opt {
            Self::read_file_opt
        } else {
            Self::read_file
        };
        String::from_utf8(read_fn(self, file)?)
            .map(|s| s.trim_end().to_owned())
            .map_err(|e| TsmError::from(e).context(format!("failed to read {file:?} as string")))
    }

    fn read_to_int(&self, file: &str) -> Result<u32> {
        self.read_to_string(file, false)?
            .parse()
            .map_err(|e| TsmError::from(e).context(format!("failed to convert {file} to integer")))
    }

    fn generation(&self) -> Result<u32> {
        self.read_to_int("generation")
    }

    fn write_file(&mut self, file: &str, data: &[u8]) -> Result<()> {
        let path = self.path.clone().join(file);
        fs::write(path, data)
            .map_err(|e| TsmError::from(e).context(format!("failed to write to {file:?}")))?;
        self.num_writes += 1;
        generation_err(self.num_writes, self.generation()?)
    }
}

impl Drop for LinuxTsmReportBuilder {
    fn drop(&mut self) {
        // note: fs::remove_dir calls the rmdir function. But
        // https://doc.rust-lang.org/std/fs/fn.remove_dir.html
        // says that this behaviour might change in future.
        fs::remove_dir(&self.path).unwrap_or(());
    }
}

impl TsmReportBuilder for LinuxTsmReportBuilder {
    fn provider(&self) -> String {
        self.provider.clone()
    }

    fn privlevel_floor(&self) -> u32 {
        self.privlevel_floor
    }

    fn inblob(mut self, blob: Vec<u8>) -> Self {
        self.inblob = blob;
        self
    }

    fn privlevel(mut self, lev: u32) -> Self {
        self.privlevel = Some(lev);
        self
    }

    fn service_provider(mut self, provider: String) -> Self {
        self.service_provider = Some(provider);
        self
    }

    fn service_guid(mut self, guid: [u8; 16]) -> Self {
        self.service_guid = Some(guid);
        self
    }

    fn get_report(mut self) -> Result<TsmReport> {
        if let Some(privlevel) = self.privlevel {
            self.write_file("privlevel", privlevel.to_string().as_bytes())?
        }
        if let Some(service_provider) = self.service_provider.take() {
            self.write_file("service_provider", service_provider.as_bytes())?
        }
        if let Some(service_guid) = self.service_guid.take() {
            self.write_file("service_guid", service_guid.as_slice())?
        }

        let inblob: Vec<u8> = std::mem::take(&mut self.inblob);
        self.write_file("inblob", inblob.as_slice())?;

        Ok(TsmReport {
            outblob: self.read_file("outblob")?,
            auxblob: self.read_file_opt("auxblob")?,
            manifestblob: self.read_file_opt("manifestblob")?,
        })
    }
}

fn generation_err(exp: u32, got: u32) -> Result<()> {
    if exp != got {
        Err(TsmError::GenerationError { exp, got })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_err_ok_when_exp_equals_got() {
        // No race: write count equals the kernel's generation counter.
        assert!(generation_err(0, 0).is_ok());
        assert!(generation_err(5, 5).is_ok());
    }

    #[test]
    fn generation_err_returns_error_with_correct_fields() {
        // A mismatch must surface the exact exp/got values so callers can report them.
        let err = generation_err(2, 5).unwrap_err();
        match err {
            TsmError::GenerationError { exp, got } => {
                assert_eq!(exp, 2);
                assert_eq!(got, 5);
            }
            other => panic!("expected GenerationError, got {other:?}"),
        }
    }
}
