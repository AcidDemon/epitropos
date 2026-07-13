//! epitropos-audit CLI.
//!
//!   epitropos-audit keygen [--key <p>] [--pub <p>]
//!   epitropos-audit analyze <manifest.json> <audit-slice> [--key <p>] [--pub <p>]
//!                          [--chain-head <p>] [--out <p>]
//!   epitropos-audit serve  [--recordings <dir>] [--audit-log <p>] [--key <p>]
//!                          [--pub <p>] [--chain-head <p>]
//!   epitropos-audit verify <privileges.json> [--pub <p>]
//!
//! `serve` is the daemon: it watches the recordings tree and writes a signed
//! sidecar when each manifest lands. `analyze` is the one-shot form.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use epitropos_audit::analyze;
use epitropos_audit::error::AuditError;
use epitropos_audit::events::PrivilegeEventsSidecar;
use epitropos_audit::signing::KeyPair;
use epitropos_audit::watch::{self, WatchConfig};

const DEFAULT_KEY: &str = "/var/lib/epitropos-audit/signing.key";
const DEFAULT_PUB: &str = "/var/lib/epitropos-audit/signing.pub";
const DEFAULT_HEAD: &str = "/var/lib/epitropos-audit/head.hash";
const DEFAULT_RECORDINGS: &str = "/var/log/ssh-sessions";
const DEFAULT_AUDIT_LOG: &str = "/var/log/audit/audit.log";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("epitropos-audit: {e}");
            ExitCode::from(e.exit_code() as u8)
        }
    }
}

struct Opts {
    key: PathBuf,
    pub_: PathBuf,
    head: PathBuf,
    recordings: PathBuf,
    audit_log: PathBuf,
    out: Option<PathBuf>,
    positionals: Vec<String>,
}

fn parse_opts(mut args: impl Iterator<Item = String>) -> Opts {
    let mut o = Opts {
        key: PathBuf::from(DEFAULT_KEY),
        pub_: PathBuf::from(DEFAULT_PUB),
        head: PathBuf::from(DEFAULT_HEAD),
        recordings: PathBuf::from(DEFAULT_RECORDINGS),
        audit_log: PathBuf::from(DEFAULT_AUDIT_LOG),
        out: None,
        positionals: Vec::new(),
    };
    while let Some(a) = args.next() {
        match a.as_str() {
            "--key" => o.key = args.next().map(PathBuf::from).unwrap_or(o.key),
            "--pub" => o.pub_ = args.next().map(PathBuf::from).unwrap_or(o.pub_),
            "--chain-head" => o.head = args.next().map(PathBuf::from).unwrap_or(o.head),
            "--recordings" => o.recordings = args.next().map(PathBuf::from).unwrap_or(o.recordings),
            "--audit-log" => o.audit_log = args.next().map(PathBuf::from).unwrap_or(o.audit_log),
            "--out" => o.out = args.next().map(PathBuf::from),
            other => o.positionals.push(other.to_string()),
        }
    }
    o
}

fn run() -> Result<(), AuditError> {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_default();
    let o = parse_opts(args);

    match cmd.as_str() {
        "keygen" => {
            let kp = KeyPair::generate_to(&o.key, &o.pub_)?;
            println!("epitropos-audit: key_id {}", kp.key_id_hex());
            println!("  signing.key {}", o.key.display());
            println!("  signing.pub {}", o.pub_.display());
            Ok(())
        }
        "analyze" => {
            let [manifest, audit] = two(&o.positionals, "analyze <manifest.json> <audit-slice>")?;
            let key = KeyPair::load(&o.key, &o.pub_)?;
            let sc = analyze::run_once(Path::new(&manifest), Path::new(&audit), &key, &o.head, o.out)?;
            println!(
                "epitropos-audit: wrote {} events (ses {}) — {}",
                sc.events.len(),
                sc.audit_session_id,
                sc.this_events_hash
            );
            Ok(())
        }
        "serve" => {
            let key = KeyPair::load(&o.key, &o.pub_)?;
            let cfg = WatchConfig {
                recordings_dir: o.recordings,
                audit_log: o.audit_log,
                chain_head: o.head,
            };
            watch::serve(&cfg, &key)
        }
        "verify" => {
            let path = o
                .positionals
                .first()
                .ok_or_else(|| AuditError::Usage("verify <privileges.json>".into()))?;
            let sidecar = PrivilegeEventsSidecar::load_from(Path::new(path))?;
            sidecar.verify(&read_pub(&o.pub_)?)?;
            println!("epitropos-audit: ok — {} privilege events verified", sidecar.events.len());
            Ok(())
        }
        "" => Err(AuditError::Usage("keygen | analyze | serve | verify".into())),
        other => Err(AuditError::Usage(format!("unknown command {other:?}"))),
    }
}

fn read_pub(path: &Path) -> Result<[u8; 32], AuditError> {
    let bytes = std::fs::read(path)?;
    bytes.as_slice().try_into().map_err(|_| {
        AuditError::Verify(format!("{} is not a 32-byte ed25519 pubkey", path.display()))
    })
}

fn two(v: &[String], usage: &str) -> Result<[String; 2], AuditError> {
    match v {
        [a, b, ..] => Ok([a.clone(), b.clone()]),
        _ => Err(AuditError::Usage(usage.into())),
    }
}
