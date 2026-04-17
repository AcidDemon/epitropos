use epitropos_sentinel::chain::{self, ChainPaths};
use epitropos_sentinel::config::Config;
use epitropos_sentinel::engine::{self, AnalysisContext, ManifestHeader};
use epitropos_sentinel::error::SentinelError;
use epitropos_sentinel::events::EventsSidecar;
use epitropos_sentinel::rules::RuleSet;
use epitropos_sentinel::signing::KeyPair;
use epitropos_sentinel::watcher;
use std::path::{Path, PathBuf};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    for arg in args.iter().skip(1) {
        if arg == "--version" || arg == "-V" {
            println!(
                "epitropos-sentinel {} ({})",
                env!("CARGO_PKG_VERSION"),
                option_env!("EPITROPOS_SENTINEL_GIT_COMMIT").unwrap_or("unknown")
            );
            std::process::exit(0);
        }
    }

    if args.len() < 2 {
        print_usage();
        std::process::exit(64);
    }

    let result = match args[1].as_str() {
        "serve" => cmd_serve(&args[2..]),
        "keygen" => cmd_keygen(&args[2..]),
        "analyze" => cmd_analyze(&args[2..]),
        "list-rules" => cmd_list_rules(&args[2..]),
        "verify" => cmd_verify(&args[2..]),
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(())
        }
        other => Err(SentinelError::Usage(format!("unknown subcommand: {other}"))),
    };

    if let Err(e) = result {
        eprintln!("epitropos-sentinel: {e}");
        std::process::exit(e.exit_code());
    }
}

fn print_usage() {
    eprintln!(
        "Usage: epitropos-sentinel <command>\n\
         \n\
         Commands:\n\
           serve [--config PATH]\n\
           keygen [--config PATH] [--force]\n\
           analyze <manifest-path> [--config PATH] [--force]\n\
           list-rules [--config PATH]\n\
           verify <events-sidecar-path> [--config PATH]\n\
           --version"
    );
}

fn find_flag(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

fn config_path(args: &[String]) -> PathBuf {
    find_flag(args, "--config")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/epitropos-sentinel/sentinel.toml"))
}

fn load_config(args: &[String]) -> Result<Config, SentinelError> {
    let p = config_path(args);
    if p.exists() {
        Config::load(&p)
    } else {
        Ok(Config::default())
    }
}

fn load_age_identity(path: &Path) -> Result<String, SentinelError> {
    let s = std::fs::read_to_string(path)
        .map_err(|e| SentinelError::Decrypt(format!("read {}: {e}", path.display())))?;
    for line in s.lines() {
        let t = line.trim();
        if t.starts_with("AGE-SECRET-KEY-") {
            return Ok(t.to_string());
        }
    }
    Err(SentinelError::Decrypt(
        "no AGE-SECRET-KEY line found in identity file".into(),
    ))
}

// --- keygen ---

fn cmd_keygen(args: &[String]) -> Result<(), SentinelError> {
    let cfg = load_config(args)?;
    let force = args.iter().any(|a| a == "--force");

    if cfg.keys.age_identity.exists() && !force {
        return Err(SentinelError::Usage(format!(
            "age identity already at {}; pass --force to regenerate",
            cfg.keys.age_identity.display()
        )));
    }

    let identity = age::x25519::Identity::generate();
    use age::secrecy::ExposeSecret;
    let identity_str = identity.to_string().expose_secret().to_string();
    let recipient = identity.to_public();

    if let Some(parent) = cfg.keys.age_identity.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| SentinelError::Signing(format!("mkdir: {e}")))?;
    }
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o400)
        .open(&cfg.keys.age_identity)
        .map_err(|e| SentinelError::Signing(format!("open: {e}")))?;
    writeln!(f, "# created: sentinel keygen")
        .map_err(|e| SentinelError::Signing(format!("write: {e}")))?;
    writeln!(f, "# public key: {recipient}")
        .map_err(|e| SentinelError::Signing(format!("write: {e}")))?;
    writeln!(f, "{identity_str}")
        .map_err(|e| SentinelError::Signing(format!("write: {e}")))?;
    drop(f);

    let kp = KeyPair::generate_to(&cfg.keys.signing_key, &cfg.keys.signing_pub)?;

    eprintln!("Generated sentinel age identity: {}", cfg.keys.age_identity.display());
    eprintln!("Generated sentinel signing keypair: {}", cfg.keys.signing_key.display());
    eprintln!();
    eprintln!("Age public key (add to katagrapho recipient file):");
    eprintln!("  {recipient}");
    eprintln!();
    eprintln!("Signing key_id: {}", kp.key_id_hex());
    Ok(())
}

// --- list-rules ---

fn cmd_list_rules(args: &[String]) -> Result<(), SentinelError> {
    let cfg = load_config(args)?;
    let rs = RuleSet::load(&cfg.rules.path)?;
    println!(
        "Loaded {} rules from {} (sha256={})",
        rs.rules.len(),
        cfg.rules.path.display(),
        rs.source_sha256
    );
    for r in &rs.rules {
        println!(
            "  [{}] {} ({}) — {} pattern(s)",
            r.def.severity,
            r.def.id,
            r.def.category,
            r.regexes.len()
        );
    }
    Ok(())
}

// --- analyze ---

fn cmd_analyze(args: &[String]) -> Result<(), SentinelError> {
    let manifest_path = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .ok_or_else(|| SentinelError::Usage("analyze requires <manifest-path>".into()))?;
    let manifest_path = PathBuf::from(manifest_path);
    let force = args.iter().any(|a| a == "--force");

    let cfg = load_config(args)?;
    let rules = RuleSet::load(&cfg.rules.path)?;
    let identity = load_age_identity(&cfg.keys.age_identity)?;
    let signing = KeyPair::load(&cfg.keys.signing_key, &cfg.keys.signing_pub)?;

    let header = read_manifest_header(&manifest_path)?;
    let recording = strip_manifest_suffix(&manifest_path);
    if !recording.exists() {
        return Err(SentinelError::Events(format!(
            "recording not found at {}",
            recording.display()
        )));
    }

    let ctx = AnalysisContext {
        cfg: &cfg,
        rules: &rules,
        age_identity: &identity,
        signing: &signing,
        emit_journal: false,
    };
    let out = engine::analyze_recording(&ctx, &recording, &header, force)?;
    println!("analyzed -> {}", out.display());
    Ok(())
}

fn strip_manifest_suffix(p: &Path) -> PathBuf {
    let s = p.as_os_str().to_string_lossy().to_string();
    if let Some(t) = s.strip_suffix(".manifest.json") {
        PathBuf::from(t)
    } else {
        p.to_path_buf()
    }
}

fn read_manifest_header(path: &Path) -> Result<ManifestHeader, SentinelError> {
    let bytes = std::fs::read(path)
        .map_err(|e| SentinelError::Events(format!("read {}: {e}", path.display())))?;
    let v: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| SentinelError::Events(format!("parse: {e}")))?;
    Ok(ManifestHeader {
        session_id: v["session_id"].as_str().unwrap_or("").to_string(),
        user: v["user"].as_str().unwrap_or("").to_string(),
        host: v["host"].as_str().unwrap_or("").to_string(),
        part: v["part"].as_u64().unwrap_or(0) as u32,
    })
}

// --- verify ---

fn cmd_verify(args: &[String]) -> Result<(), SentinelError> {
    let path = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .ok_or_else(|| SentinelError::Usage("verify requires <sidecar-path>".into()))?;
    let cfg = load_config(args)?;
    let pub_bytes = std::fs::read(&cfg.keys.signing_pub)
        .map_err(|e| SentinelError::Verify(format!("read pub: {e}")))?;
    if pub_bytes.len() != 32 {
        return Err(SentinelError::Verify("pub key wrong length".into()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&pub_bytes);

    let sc = EventsSidecar::load_from(Path::new(path))?;
    sc.verify(&arr)?;
    println!("ok: {path}");
    Ok(())
}

// --- serve ---

fn cmd_serve(args: &[String]) -> Result<(), SentinelError> {
    let cfg = load_config(args)?;
    let rules = RuleSet::load(&cfg.rules.path)?;
    let identity = load_age_identity(&cfg.keys.age_identity)?;
    let signing = KeyPair::load(&cfg.keys.signing_key, &cfg.keys.signing_pub)?;

    let chain_paths = ChainPaths::new(cfg.chain.head_path.clone());
    if let Some(parent) = chain_paths.head.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| SentinelError::Chain(format!("mkdir: {e}")))?;
    }
    let _ = chain::read_head(&chain_paths)?;

    eprintln!(
        "epitropos-sentinel: watching {}",
        cfg.storage.dir.display()
    );
    eprintln!(
        "epitropos-sentinel: {} rules loaded",
        rules.rules.len()
    );
    watcher::watch_and_analyze(&cfg, &rules, &identity, &signing)?;
    Ok(())
}
