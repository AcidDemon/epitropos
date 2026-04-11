use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::CollectorError;

const DEFAULT_STORAGE_DIR: &str = "/var/lib/epitropos-collector";
const DEFAULT_LISTEN_ADDRESS: &str = "0.0.0.0";
const DEFAULT_LISTEN_PORT: u16 = 8443;
const DEFAULT_MAX_UPLOAD_BYTES: u64 = 1 << 30; // 1 GiB
const DEFAULT_TOKEN_TTL_SECONDS: u64 = 900;
const DEFAULT_MAX_PENDING_TOKENS: usize = 1000;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Config {
    #[serde(default)]
    pub listen: Listen,
    #[serde(default)]
    pub storage: Storage,
    #[serde(default)]
    pub enrollment: Enrollment,
    #[serde(default)]
    pub tls: Tls,
    #[serde(default)]
    pub log: Log,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Listen {
    #[serde(default = "Listen::default_address")]
    pub address: String,
    #[serde(default = "Listen::default_port")]
    pub port: u16,
}

impl Listen {
    fn default_address() -> String {
        DEFAULT_LISTEN_ADDRESS.into()
    }
    fn default_port() -> u16 {
        DEFAULT_LISTEN_PORT
    }
}

impl Default for Listen {
    fn default() -> Self {
        Self {
            address: Self::default_address(),
            port: Self::default_port(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Storage {
    #[serde(default = "Storage::default_dir")]
    pub dir: PathBuf,
    #[serde(default = "Storage::default_max_upload")]
    pub max_upload_bytes: u64,
}

impl Storage {
    fn default_dir() -> PathBuf {
        PathBuf::from(DEFAULT_STORAGE_DIR)
    }
    fn default_max_upload() -> u64 {
        DEFAULT_MAX_UPLOAD_BYTES
    }
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            dir: Self::default_dir(),
            max_upload_bytes: Self::default_max_upload(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Enrollment {
    #[serde(default = "Enrollment::default_ttl")]
    pub token_ttl_seconds: u64,
    #[serde(default = "Enrollment::default_max_pending")]
    pub max_pending_tokens: usize,
}

impl Enrollment {
    fn default_ttl() -> u64 {
        DEFAULT_TOKEN_TTL_SECONDS
    }
    fn default_max_pending() -> usize {
        DEFAULT_MAX_PENDING_TOKENS
    }
}

impl Default for Enrollment {
    fn default() -> Self {
        Self {
            token_ttl_seconds: Self::default_ttl(),
            max_pending_tokens: Self::default_max_pending(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Tls {
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Log {
    #[serde(default = "Log::default_level")]
    pub level: String,
}

impl Log {
    fn default_level() -> String {
        "info".into()
    }
}

impl Default for Log {
    fn default() -> Self {
        Self {
            level: Self::default_level(),
        }
    }
}


#[allow(dead_code)]
impl Config {
    pub fn load(path: &Path) -> Result<Self, CollectorError> {
        let s = fs::read_to_string(path)
            .map_err(|e| CollectorError::Config(format!("read {}: {e}", path.display())))?;
        toml::from_str(&s).map_err(|e| CollectorError::Config(format!("parse: {e}")))
    }

    pub fn tls_cert_path(&self) -> PathBuf {
        self.tls
            .cert_path
            .clone()
            .unwrap_or_else(|| self.storage.dir.join("tls/cert.pem"))
    }

    pub fn tls_key_path(&self) -> PathBuf {
        self.tls
            .key_path
            .clone()
            .unwrap_or_else(|| self.storage.dir.join("tls/key.pem"))
    }

    pub fn enroll_secret_path(&self) -> PathBuf {
        self.storage.dir.join("tls/enroll.secret")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_apply_when_empty() {
        let cfg: Config = toml::from_str("").unwrap();
        assert_eq!(cfg.listen.port, DEFAULT_LISTEN_PORT);
        assert_eq!(cfg.storage.dir, PathBuf::from(DEFAULT_STORAGE_DIR));
        assert_eq!(cfg.enrollment.token_ttl_seconds, DEFAULT_TOKEN_TTL_SECONDS);
    }

    #[test]
    fn rejects_unknown_top_level() {
        let toml_str = r#"
[bogus]
key = 1
"#;
        assert!(toml::from_str::<Config>(toml_str).is_err());
    }

    #[test]
    fn rejects_unknown_subkey() {
        let toml_str = r#"
[storage]
dir = "/tmp/foo"
bogus = 1
"#;
        assert!(toml::from_str::<Config>(toml_str).is_err());
    }

    #[test]
    fn overrides_apply() {
        let toml_str = r#"
[listen]
port = 9999

[enrollment]
token_ttl_seconds = 60
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.listen.port, 9999);
        assert_eq!(cfg.enrollment.token_ttl_seconds, 60);
    }
}
