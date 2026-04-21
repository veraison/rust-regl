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
