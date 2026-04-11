//! CLI subcommand parsing for epitropos-collector.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::error::CollectorError;

pub enum Command {
    Serve { config_path: PathBuf },
    Enroll { sender_name: String, ttl: Option<u64> },
    Revoke { sender_name: String, force: bool },
    List,
    Keygen,
    RotateCert,
    Verify { path: PathBuf },
    Version,
}

pub fn parse(args: &[String]) -> Result<Command, CollectorError> {
    if args.len() < 2 {
        return Err(CollectorError::Usage(usage()));
    }

    for arg in args.iter().skip(1) {
        if arg == "--version" || arg == "-V" {
            return Ok(Command::Version);
        }
    }

    match args[1].as_str() {
        "serve" => {
            let config_path = find_flag_value(args, "--config")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/etc/epitropos-collector/collector.toml"));
            Ok(Command::Serve { config_path })
        }
        "enroll" => {
            let sender_name = args
                .get(2)
                .ok_or_else(|| CollectorError::Usage("enroll requires <sender-name>".into()))?
                .clone();
            let ttl = find_flag_value(args, "--ttl-seconds").and_then(|s| s.parse().ok());
            Ok(Command::Enroll { sender_name, ttl })
        }
        "revoke" => {
            let sender_name = args
                .get(2)
                .ok_or_else(|| CollectorError::Usage("revoke requires <sender-name>".into()))?
                .clone();
            let force = args.iter().any(|a| a == "--force");
            Ok(Command::Revoke { sender_name, force })
        }
        "list" => Ok(Command::List),
        "keygen" => Ok(Command::Keygen),
        "rotate-cert" => Ok(Command::RotateCert),
        "verify" => {
            let path = args
                .get(2)
                .ok_or_else(|| CollectorError::Usage("verify requires <path>".into()))?;
            Ok(Command::Verify {
                path: PathBuf::from(path),
            })
        }
        "--help" | "-h" | "help" => Err(CollectorError::Usage(usage())),
        other => Err(CollectorError::Usage(format!("unknown subcommand: {other}\n{}", usage()))),
    }
}

fn find_flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

fn usage() -> String {
    "Usage: epitropos-collector <command> [options]\n\
     \n\
     Commands:\n\
       serve [--config PATH]        Run the HTTP server\n\
       enroll <sender-name>         Generate enrollment token\n\
       revoke <sender-name>         Remove sender from pinned set\n\
       list                         List enrolled senders\n\
       keygen                       Generate TLS cert + enroll secret (first boot)\n\
       rotate-cert                  Rotate the collector TLS certificate\n\
       verify <path>                Verify a manifest sidecar\n\
       --version                    Print version"
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_serve() {
        let cmd = parse(&args(&["bin", "serve"])).unwrap();
        assert!(matches!(cmd, Command::Serve { .. }));
    }

    #[test]
    fn parse_enroll() {
        let cmd = parse(&args(&["bin", "enroll", "alice"])).unwrap();
        assert!(matches!(cmd, Command::Enroll { sender_name, .. } if sender_name == "alice"));
    }

    #[test]
    fn parse_version() {
        let cmd = parse(&args(&["bin", "--version"])).unwrap();
        assert!(matches!(cmd, Command::Version));
    }

    #[test]
    fn parse_no_args_errors() {
        assert!(parse(&args(&["bin"])).is_err());
    }
}
