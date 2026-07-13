use std::io;

pub const EX_USAGE: i32 = 64;
pub const EX_DATAERR: i32 = 65;
pub const EX_NOINPUT: i32 = 66;
pub const EX_SOFTWARE: i32 = 70;
pub const EX_IOERR: i32 = 74;

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("usage: {0}")]
    Usage(String),

    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("manifest: {0}")]
    Manifest(String),

    #[error("parse: {0}")]
    Parse(String),

    #[error("correlate: {0}")]
    Correlate(String),

    #[error("signing: {0}")]
    Signing(String),

    #[error("verify: {0}")]
    Verify(String),

    #[error("chain: {0}")]
    Chain(String),

    #[error("events: {0}")]
    Events(String),
}

impl AuditError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => EX_USAGE,
            Self::Io(_) => EX_IOERR,
            Self::Manifest(_) => EX_NOINPUT,
            Self::Parse(_) => EX_DATAERR,
            Self::Correlate(_) => EX_DATAERR,
            Self::Signing(_) => EX_SOFTWARE,
            Self::Verify(_) => EX_DATAERR,
            Self::Chain(_) => EX_IOERR,
            Self::Events(_) => EX_IOERR,
        }
    }
}
