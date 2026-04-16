use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::SentinelError;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Config {
    #[serde(default)]
    pub storage: Storage,
    #[serde(default)]
    pub keys: Keys,
    #[serde(default)]
    pub rules: RulesCfg,
    #[serde(default)]
    pub cooldown: Cooldown,
    #[serde(default)]
    pub context: Context,
    #[serde(default)]
    pub journal: Journal,
    #[serde(default)]
    pub events_sidecar: EventsSidecar,
    #[serde(default)]
    pub chain: ChainCfg,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Storage {
    #[serde(default = "Storage::default_dir")]
    pub dir: PathBuf,
}
impl Storage {
    fn default_dir() -> PathBuf {
        PathBuf::from("/var/lib/epitropos-collector")
    }
}
impl Default for Storage {
    fn default() -> Self {
        Self {
            dir: Self::default_dir(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Keys {
    #[serde(default = "Keys::default_age")]
    pub age_identity: PathBuf,
    #[serde(default = "Keys::default_sign_key")]
    pub signing_key: PathBuf,
    #[serde(default = "Keys::default_sign_pub")]
    pub signing_pub: PathBuf,
}
impl Keys {
    fn default_age() -> PathBuf {
        PathBuf::from("/var/lib/epitropos-sentinel/sentinel.key")
    }
    fn default_sign_key() -> PathBuf {
        PathBuf::from("/var/lib/epitropos-sentinel/signing.key")
    }
    fn default_sign_pub() -> PathBuf {
        PathBuf::from("/var/lib/epitropos-sentinel/signing.pub")
    }
}
impl Default for Keys {
    fn default() -> Self {
        Self {
            age_identity: Self::default_age(),
            signing_key: Self::default_sign_key(),
            signing_pub: Self::default_sign_pub(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct RulesCfg {
    #[serde(default = "RulesCfg::default_path")]
    pub path: PathBuf,
    #[serde(default = "RulesCfg::default_reload")]
    pub reload_on_change: bool,
}
impl RulesCfg {
    fn default_path() -> PathBuf {
        PathBuf::from("/etc/epitropos-sentinel/rules.toml")
    }
    fn default_reload() -> bool {
        true
    }
}
impl Default for RulesCfg {
    fn default() -> Self {
        Self {
            path: Self::default_path(),
            reload_on_change: Self::default_reload(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Cooldown {
    #[serde(default = "Cooldown::default_secs")]
    pub per_rule_per_session_seconds: u64,
}
impl Cooldown {
    fn default_secs() -> u64 {
        30
    }
}
impl Default for Cooldown {
    fn default() -> Self {
        Self {
            per_rule_per_session_seconds: Self::default_secs(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Context {
    #[serde(default = "Context::default_before")]
    pub before_chars: usize,
    #[serde(default = "Context::default_after")]
    pub after_chars: usize,
}
impl Context {
    fn default_before() -> usize {
        200
    }
    fn default_after() -> usize {
        200
    }
}
impl Default for Context {
    fn default() -> Self {
        Self {
            before_chars: Self::default_before(),
            after_chars: Self::default_after(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Journal {
    #[serde(default = "Journal::default_on")]
    pub enabled: bool,
}
impl Journal {
    fn default_on() -> bool {
        true
    }
}
impl Default for Journal {
    fn default() -> Self {
        Self {
            enabled: Self::default_on(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct EventsSidecar {
    #[serde(default = "EventsSidecar::default_on")]
    pub enabled: bool,
}
impl EventsSidecar {
    fn default_on() -> bool {
        true
    }
}
impl Default for EventsSidecar {
    fn default() -> Self {
        Self {
            enabled: Self::default_on(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct ChainCfg {
    #[serde(default = "ChainCfg::default_head")]
    pub head_path: PathBuf,
}
impl ChainCfg {
    fn default_head() -> PathBuf {
        PathBuf::from("/var/lib/epitropos-sentinel/head.hash")
    }
}
impl Default for ChainCfg {
    fn default() -> Self {
        Self {
            head_path: Self::default_head(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            storage: Storage::default(),
            keys: Keys::default(),
            rules: RulesCfg::default(),
            cooldown: Cooldown::default(),
            context: Context::default(),
            journal: Journal::default(),
            events_sidecar: EventsSidecar::default(),
            chain: ChainCfg::default(),
        }
    }
}

impl Config {
    #[allow(dead_code)]
    pub fn load(path: &Path) -> Result<Self, SentinelError> {
        let s = fs::read_to_string(path)
            .map_err(|e| SentinelError::Config(format!("read {}: {e}", path.display())))?;
        toml::from_str(&s).map_err(|e| SentinelError::Config(format!("parse: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_apply_when_empty() {
        let cfg: Config = toml::from_str("").unwrap();
        assert_eq!(cfg.cooldown.per_rule_per_session_seconds, 30);
        assert_eq!(cfg.context.before_chars, 200);
        assert!(cfg.journal.enabled);
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
    fn overrides_apply() {
        let toml_str = r#"
[cooldown]
per_rule_per_session_seconds = 5
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.cooldown.per_rule_per_session_seconds, 5);
    }
}
