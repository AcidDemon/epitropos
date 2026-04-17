use std::io;

pub const EX_USAGE: i32 = 64;
pub const EX_DATAERR: i32 = 65;
#[allow(dead_code)]
pub const EX_NOINPUT: i32 = 66;
pub const EX_SOFTWARE: i32 = 70;
pub const EX_IOERR: i32 = 74;
pub const EX_CONFIG: i32 = 78;

#[derive(Debug, thiserror::Error)]
pub enum SentinelError {
    #[error("usage: {0}")]
    Usage(String),

    #[error("config: {0}")]
    Config(String),

    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("rules: {0}")]
    Rules(String),

    #[error("decrypt: {0}")]
    Decrypt(String),

    #[error("signing: {0}")]
    Signing(String),

    #[error("verify: {0}")]
    Verify(String),

    #[error("chain: {0}")]
    Chain(String),

    #[error("events: {0}")]
    Events(String),

    #[error("internal: {0}")]
    #[allow(dead_code)]
    Internal(String),
}

impl SentinelError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => EX_USAGE,
            Self::Config(_) => EX_CONFIG,
            Self::Io(_) => EX_IOERR,
            Self::Rules(_) => EX_CONFIG,
            Self::Decrypt(_) => EX_DATAERR,
            Self::Signing(_) => EX_SOFTWARE,
            Self::Verify(_) => EX_DATAERR,
            Self::Chain(_) => EX_IOERR,
            Self::Events(_) => EX_IOERR,
            Self::Internal(_) => EX_SOFTWARE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_distinct() {
        assert_eq!(SentinelError::Usage("x".into()).exit_code(), EX_USAGE);
        assert_eq!(SentinelError::Config("x".into()).exit_code(), EX_CONFIG);
        assert_eq!(SentinelError::Rules("x".into()).exit_code(), EX_CONFIG);
        assert_eq!(SentinelError::Verify("x".into()).exit_code(), EX_DATAERR);
        assert_eq!(SentinelError::Chain("x".into()).exit_code(), EX_IOERR);
    }
}
