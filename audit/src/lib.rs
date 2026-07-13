//! epitropos-audit — authoritative privilege-event feed. Correlates Linux
//! kernel audit records (sudo/su/doas) to session recordings via the
//! (host, boot_id, audit_session_id) tuple and emits a signed, hash-chained
//! `<recording>.privileges.json` sidecar that theatron reads as AUTHORITATIVE
//! (vs the sentinel's advisory content-scan markers).

pub mod analyze;
pub mod chain;
pub mod correlate;
pub mod error;
pub mod events;
pub mod manifest;
pub mod parse;
pub mod signing;
pub mod watch;
