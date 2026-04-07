//! epitropos top-level error type. Maps every failure to a sysexits.h
//! exit code so sysadmins can triage without grepping syslog.
//!
//! `From<String>` auto-converts legacy `Result<_, String>` call sites into
//! `EpitroposError::Internal`, giving them `EX_SOFTWARE` (70). Call sites
//! that want a more specific exit code wrap explicitly with the relevant
//! variant constructor (e.g., `EpitroposError::Privilege(...)`).

use std::io;

// sysexits.h
pub const EX_USAGE: i32 = 64;
pub const EX_DATAERR: i32 = 65;
pub const EX_NOINPUT: i32 = 66;
pub const EX_UNAVAILABLE: i32 = 69;
pub const EX_SOFTWARE: i32 = 70;
pub const EX_IOERR: i32 = 74;
pub const EX_TEMPFAIL: i32 = 75;
pub const EX_NOPERM: i32 = 77;
pub const EX_CONFIG: i32 = 78;

#[derive(Debug, thiserror::Error)]
pub enum EpitroposError {
    #[error("usage: {0}")]
    Usage(String),

    #[error("validation: {0}")]
    Validation(String),

    #[error("config: {0}")]
    Config(String),

    #[error("missing input: {0}")]
    NoInput(String),

    #[error("privilege: {0}")]
    Privilege(String),

    #[error("nesting check failed: {0}")]
    Nesting(String),

    #[error("recording failed: {0}")]
    Recording(String),

    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("{0}")]
    Internal(String),
}

impl From<String> for EpitroposError {
    fn from(s: String) -> Self {
        Self::Internal(s)
    }
}

impl From<&str> for EpitroposError {
    fn from(s: &str) -> Self {
        Self::Internal(s.to_string())
    }
}

impl EpitroposError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => EX_USAGE,
            Self::Validation(_) => EX_DATAERR,
            Self::Config(_) => EX_CONFIG,
            Self::NoInput(_) => EX_NOINPUT,
            Self::Privilege(_) => EX_NOPERM,
            Self::Nesting(_) => EX_TEMPFAIL,
            Self::Recording(_) => EX_IOERR,
            Self::Io(_) => EX_IOERR,
            Self::Internal(_) => EX_SOFTWARE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nesting_failure_maps_to_tempfail() {
        assert_eq!(
            EpitroposError::Nesting("lock failed".into()).exit_code(),
            EX_TEMPFAIL
        );
    }

    #[test]
    fn config_failure_maps_to_ex_config() {
        assert_eq!(
            EpitroposError::Config("unknown field foo".into()).exit_code(),
            EX_CONFIG
        );
    }

    #[test]
    fn string_auto_converts_to_internal() {
        let e: EpitroposError = "oops".to_string().into();
        assert!(matches!(e, EpitroposError::Internal(_)));
        assert_eq!(e.exit_code(), EX_SOFTWARE);
    }
}
