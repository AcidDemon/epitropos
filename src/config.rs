use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub general: General,
    pub encryption: Encryption,
    pub fail_policy: FailPolicy,
    pub nesting: Nesting,
    #[serde(default)]
    pub hooks: Hooks,
}

#[derive(Debug, Deserialize)]
pub struct General {
    pub katagrapho_path: String,
    pub session_proxy_user: String,
    pub session_proxy_group: String,
    #[serde(default)]
    pub record_input: bool,
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

#[derive(Debug, Deserialize)]
pub struct Nesting {
    #[serde(default)]
    pub always_record_services: Vec<String>,
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
session_proxy_user = "session-proxy"
session_proxy_group = "session-proxy"
record_input = true

[encryption]
enabled = true
recipient_file = "/etc/epitropos/recipients.txt"

[fail_policy]
default = "closed"
open_for_groups = ["wheel", "admins"]
closed_for_groups = ["guests"]

[nesting]
always_record_services = ["sshd", "login"]

[hooks]
on_recording_failure = "/usr/local/bin/notify-failure"
"#;

        let cfg: Config = toml::from_str(toml).expect("should parse full config");

        assert_eq!(cfg.general.katagrapho_path, "/usr/local/bin/katagrapho");
        assert_eq!(cfg.general.session_proxy_user, "session-proxy");
        assert_eq!(cfg.general.session_proxy_group, "session-proxy");
        assert!(cfg.general.record_input);

        assert_eq!(
            cfg.encryption.recipient_file,
            "/etc/epitropos/recipients.txt"
        );

        assert_eq!(cfg.fail_policy.default, FailMode::Closed);
        assert_eq!(cfg.fail_policy.open_for_groups, vec!["wheel", "admins"]);
        assert_eq!(cfg.fail_policy.closed_for_groups, vec!["guests"]);

        assert_eq!(cfg.nesting.always_record_services, vec!["sshd", "login"]);

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

[encryption]
recipient_file = "/etc/epitropos/recipients.txt"

[fail_policy]
default = "open"

[nesting]
"#;

        let cfg: Config = toml::from_str(toml).expect("should parse minimal config");

        assert_eq!(cfg.general.katagrapho_path, "/usr/bin/katagrapho");
        assert_eq!(cfg.general.session_proxy_user, "nobody");
        assert_eq!(cfg.general.session_proxy_group, "nogroup");
        assert!(!cfg.general.record_input);

        assert_eq!(
            cfg.encryption.recipient_file,
            "/etc/epitropos/recipients.txt"
        );

        assert_eq!(cfg.fail_policy.default, FailMode::Open);
        assert!(cfg.fail_policy.open_for_groups.is_empty());
        assert!(cfg.fail_policy.closed_for_groups.is_empty());

        assert!(cfg.nesting.always_record_services.is_empty());

        assert_eq!(cfg.hooks.on_recording_failure, "");
    }
}
