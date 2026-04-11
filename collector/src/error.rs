use std::io;

pub const EX_USAGE: i32 = 64;
pub const EX_DATAERR: i32 = 65;
pub const EX_NOINPUT: i32 = 66;
pub const EX_UNAVAILABLE: i32 = 69;
pub const EX_SOFTWARE: i32 = 70;
pub const EX_IOERR: i32 = 74;
pub const EX_TEMPFAIL: i32 = 75;
pub const EX_CONFIG: i32 = 78;

#[derive(Debug, thiserror::Error)]
pub enum CollectorError {
    #[error("usage: {0}")]
    Usage(String),

    #[error("config: {0}")]
    Config(String),

    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("tls: {0}")]
    Tls(String),

    #[error("enroll: {0}")]
    Enroll(String),

    #[error("storage: {0}")]
    Storage(String),

    #[error("chain: {0}")]
    Chain(String),

    #[error("verify: {0}")]
    Verify(String),

    #[error("internal: {0}")]
    #[allow(dead_code)]
    Internal(String),
}

impl CollectorError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => EX_USAGE,
            Self::Config(_) => EX_CONFIG,
            Self::Io(_) => EX_IOERR,
            Self::Tls(_) => EX_UNAVAILABLE,
            Self::Enroll(_) => EX_DATAERR,
            Self::Storage(_) => EX_IOERR,
            Self::Chain(_) => EX_IOERR,
            Self::Verify(_) => EX_DATAERR,
            Self::Internal(_) => EX_SOFTWARE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_distinct() {
        assert_eq!(CollectorError::Usage("x".into()).exit_code(), EX_USAGE);
        assert_eq!(CollectorError::Config("x".into()).exit_code(), EX_CONFIG);
        assert_eq!(CollectorError::Verify("x".into()).exit_code(), EX_DATAERR);
        assert_eq!(CollectorError::Chain("x".into()).exit_code(), EX_IOERR);
    }
}
