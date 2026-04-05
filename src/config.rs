use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub general: General,
    pub shell: Shell,
    pub encryption: Encryption,
    pub fail_policy: FailPolicy,
    #[serde(default)]
    pub limit: RateLimit,
    #[serde(default)]
    pub writers: Vec<WriterConfig>,
    #[serde(default)]
    pub notice: Notice,
    #[serde(default)]
    pub hooks: Hooks,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum WriterConfig {
    Syslog {
        #[serde(default = "WriterConfig::default_facility")]
        facility: String,
    },
    Journal {
        #[serde(default = "WriterConfig::default_ident")]
        identifier: String,
    },
    File {
        path: String,
    },
}

impl WriterConfig {
    fn default_facility() -> String {
        "authpriv".to_string()
    }
    fn default_ident() -> String {
        "epitropos".to_string()
    }
}

#[derive(Debug, Deserialize)]
pub struct RateLimit {
    #[serde(default = "RateLimit::default_rate")]
    pub rate: u64,
    #[serde(default = "RateLimit::default_burst")]
    pub burst: u64,
    #[serde(default)]
    pub action: RateLimitAction,
}

impl RateLimit {
    fn default_rate() -> u64 {
        16384
    }
    fn default_burst() -> u64 {
        32768
    }
}

impl Default for RateLimit {
    fn default() -> Self {
        RateLimit {
            rate: Self::default_rate(),
            burst: Self::default_burst(),
            action: RateLimitAction::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitAction {
    #[default]
    Pass,
    Delay,
    Drop,
}

#[derive(Debug, Deserialize)]
pub struct Notice {
    #[serde(default = "Notice::default_text")]
    pub text: String,
}

impl Notice {
    fn default_text() -> String {
        "\nATTENTION! Your session is being recorded!\n\n".to_string()
    }
}

impl Default for Notice {
    fn default() -> Self {
        Notice {
            text: Self::default_text(),
        }
    }
}

/// Shell configuration — maps users to their real shell.
/// epitropos replaces the user's login shell, so it needs to know
/// which shell to actually spawn.
#[derive(Debug, Deserialize)]
pub struct Shell {
    /// Default shell for all recorded users.
    pub default: String,
    /// Per-user shell overrides. Key = username, value = shell path.
    #[serde(default)]
    pub users: std::collections::HashMap<String, String>,
}

impl Shell {
    /// Resolve the real shell for a given username.
    pub fn resolve(&self, username: &str) -> &str {
        self.users
            .get(username)
            .map(|s| s.as_str())
            .unwrap_or(&self.default)
    }
}

#[derive(Debug, Deserialize)]
pub struct General {
    pub katagrapho_path: String,
    #[serde(default = "General::default_ns_exec_path")]
    pub ns_exec_path: String,
    #[serde(default)]
    pub record_input: bool,
    pub latency: Option<u64>,
}

impl General {
    fn default_ns_exec_path() -> String {
        "/run/wrappers/bin/epitropos-ns-exec".to_string()
    }
}

#[derive(Debug, Deserialize)]
pub struct Encryption {
    #[serde(default)]
    pub recipient_file: String,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct FailPolicy {
    pub default: FailMode,
    #[serde(default)]
    pub open_for_groups: Vec<String>,
    #[serde(default)]
    pub closed_for_groups: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FailMode {
    Closed,
    Open,
}

#[derive(Debug, Default, Deserialize)]
pub struct Hooks {
    #[serde(default)]
    pub on_recording_failure: String,
}

const CONFIG_PATH: &str = "/etc/epitropos/config.toml";

pub fn load() -> Result<Config, String> {
    load_from(CONFIG_PATH)
}

pub fn load_from(path: &str) -> Result<Config, String> {
    let contents =
        std::fs::read_to_string(path).map_err(|e| format!("cannot read config '{path}': {e}"))?;
    toml::from_str(&contents).map_err(|e| format!("invalid config '{path}': {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_config() {
        let toml = r#"
[general]
katagrapho_path = "/usr/local/bin/katagrapho"
ns_exec_path = "/usr/local/bin/epitropos-ns-exec"
session_proxy_user = "session-proxy"
session_proxy_group = "session-proxy"
record_input = true

[shell]
default = "/bin/bash"
[shell.users]
alice = "/bin/zsh"
bob = "/bin/fish"

[encryption]
enabled = true
recipient_file = "/etc/epitropos/recipients.txt"

[fail_policy]
default = "closed"
open_for_groups = ["wheel", "admins"]
closed_for_groups = ["guests"]

[hooks]
on_recording_failure = "/usr/local/bin/notify-failure"
"#;

        let cfg: Config = toml::from_str(toml).expect("should parse full config");

        assert_eq!(cfg.general.katagrapho_path, "/usr/local/bin/katagrapho");
        assert_eq!(cfg.general.ns_exec_path, "/usr/local/bin/epitropos-ns-exec");
        assert!(cfg.general.record_input);

        assert_eq!(cfg.shell.default, "/bin/bash");
        assert_eq!(cfg.shell.resolve("alice"), "/bin/zsh");
        assert_eq!(cfg.shell.resolve("bob"), "/bin/fish");
        assert_eq!(cfg.shell.resolve("unknown"), "/bin/bash");

        assert_eq!(
            cfg.encryption.recipient_file,
            "/etc/epitropos/recipients.txt"
        );

        assert_eq!(cfg.fail_policy.default, FailMode::Closed);
        assert_eq!(cfg.fail_policy.open_for_groups, vec!["wheel", "admins"]);
        assert_eq!(cfg.fail_policy.closed_for_groups, vec!["guests"]);

        assert_eq!(
            cfg.hooks.on_recording_failure,
            "/usr/local/bin/notify-failure"
        );
    }

    #[test]
    fn parse_minimal_config() {
        let toml = r#"
[general]
katagrapho_path = "/usr/bin/katagrapho"
session_proxy_user = "nobody"
session_proxy_group = "nogroup"

[shell]
default = "/bin/sh"

[encryption]
recipient_file = "/etc/epitropos/recipients.txt"

[fail_policy]
default = "open"

[nesting]
"#;

        let cfg: Config = toml::from_str(toml).expect("should parse minimal config");

        assert_eq!(cfg.general.katagrapho_path, "/usr/bin/katagrapho");
        assert_eq!(cfg.general.ns_exec_path, "/run/wrappers/bin/epitropos-ns-exec");
        assert!(!cfg.general.record_input);

        assert_eq!(cfg.shell.default, "/bin/sh");
        assert!(cfg.shell.users.is_empty());
        assert_eq!(cfg.shell.resolve("anyone"), "/bin/sh");

        assert_eq!(
            cfg.encryption.recipient_file,
            "/etc/epitropos/recipients.txt"
        );

        assert_eq!(cfg.fail_policy.default, FailMode::Open);
        assert!(cfg.fail_policy.open_for_groups.is_empty());
        assert!(cfg.fail_policy.closed_for_groups.is_empty());

        assert_eq!(cfg.hooks.on_recording_failure, "");
    }
}
