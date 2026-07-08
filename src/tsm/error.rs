// Copyright 2026 Contributors to the Veraison project
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TsmError {
    #[error("TSM backend is unsupported")]
    Unsupported,
    #[error("{context}")]
    IOError {
        context: String,
        #[source]
        source: std::io::Error,
    },
    #[error("inblob write race detected: expected {exp} found {got}")]
    GenerationError { exp: u32, got: u32 },
    #[error("{context}")]
    BytesToStringError {
        context: String,
        #[source]
        source: std::string::FromUtf8Error,
    },
    #[error("{context}")]
    StringToIntError {
        context: String,
        #[source]
        source: std::num::ParseIntError,
    },
    #[error("TSM error: {0}")]
    Custom(String),
}

impl TsmError {
    pub fn custom<T>(msg: T) -> Self
    where
        T: std::fmt::Display,
    {
        Self::Custom(msg.to_string())
    }

    pub fn context<T>(self, ctx: T) -> Self
    where
        T: std::fmt::Display,
    {
        let context = ctx.to_string();
        match self {
            TsmError::IOError { source, .. } => TsmError::IOError { context, source },
            TsmError::BytesToStringError { source, .. } => {
                TsmError::BytesToStringError { context, source }
            }
            TsmError::StringToIntError { source, .. } => {
                TsmError::StringToIntError { context, source }
            }
            _ => self,
        }
    }
}

impl From<std::io::Error> for TsmError {
    fn from(value: std::io::Error) -> Self {
        Self::IOError {
            context: "I/O failed".to_owned(),
            source: value,
        }
    }
}

impl From<std::string::FromUtf8Error> for TsmError {
    fn from(value: std::string::FromUtf8Error) -> Self {
        Self::BytesToStringError {
            context: "error converting bytes to string".to_owned(),
            source: value,
        }
    }
}

impl From<std::num::ParseIntError> for TsmError {
    fn from(value: std::num::ParseIntError) -> Self {
        Self::StringToIntError {
            context: "error converting string to integer".to_owned(),
            source: value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_replaces_io_error_context_string() {
        // context() must update the displayed message for IOError.
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err = TsmError::from(io).context("opening tsm config");
        assert_eq!(format!("{err}"), "opening tsm config");
    }

    #[test]
    fn context_is_noop_for_unsupported_and_generation_error() {
        // context() should not alter variants it cannot enrich.
        let unsupported = TsmError::Unsupported.context("ignored");
        assert!(matches!(unsupported, TsmError::Unsupported));

        let gen_err = TsmError::GenerationError { exp: 1, got: 2 }.context("ignored");
        assert!(matches!(
            gen_err,
            TsmError::GenerationError { exp: 1, got: 2 }
        ));
    }

    #[test]
    fn generation_error_display_contains_both_counter_values() {
        // The display format must include both exp and got so callers can diagnose races.
        let err = TsmError::GenerationError { exp: 3, got: 7 };
        let msg = format!("{err}");
        assert!(msg.contains('3') && msg.contains('7'), "msg was: {msg}");
    }

    #[test]
    fn from_utf8_error_produces_bytes_to_string_variant() {
        let utf8_err = String::from_utf8(vec![0xff, 0xfe]).unwrap_err();
        let tsm: TsmError = utf8_err.into();
        assert!(matches!(tsm, TsmError::BytesToStringError { .. }));
    }

    #[test]
    fn from_parse_int_error_produces_string_to_int_variant() {
        let parse_err = "not-a-number".parse::<u32>().unwrap_err();
        let tsm: TsmError = parse_err.into();
        assert!(matches!(tsm, TsmError::StringToIntError { .. }));
    }

    #[test]
    fn from_io_error_produces_io_error_variant() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let tsm: TsmError = io.into();
        assert!(matches!(tsm, TsmError::IOError { .. }));
    }

    #[test]
    fn io_error_with_context_preserves_source() {
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let tsm: TsmError = io.into();
        let ctx = tsm.context("writing report");
        let msg = format!("{ctx}");
        assert!(msg.contains("writing report"));
    }

    #[test]
    fn context_on_bytes_to_string_error_updates_message() {
        let utf8_err = String::from_utf8(vec![0xff]).unwrap_err();
        let tsm: TsmError = utf8_err.into();
        let ctx = tsm.context("parsing outblob");
        assert!(format!("{ctx}").contains("parsing outblob"));
    }

    #[test]
    fn context_on_string_to_int_error_updates_message() {
        let parse_err = "abc".parse::<u32>().unwrap_err();
        let tsm: TsmError = parse_err.into();
        let ctx = tsm.context("reading generation counter");
        assert!(format!("{ctx}").contains("reading generation counter"));
    }

    #[test]
    fn custom_error_wraps_message() {
        let err = TsmError::custom("configuration missing");
        assert!(format!("{err}").contains("configuration missing"));
    }
}
