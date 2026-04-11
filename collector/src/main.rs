use epitropos_collector::cli::{self, Command};
use epitropos_collector::config::Config;
use epitropos_collector::enroll::{self, EnrollmentDir};
use epitropos_collector::error::CollectorError;
use epitropos_collector::server::{self, AppState};
use epitropos_collector::storage::{self, SenderDirs};
use epitropos_collector::tls::{self, PinnedCerts};
use std::path::Path;
use std::sync::Arc;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = match cli::parse(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("epitropos-collector: {e}");
            std::process::exit(e.exit_code());
        }
    };

    match cmd {
        Command::Version => {
            println!(
                "epitropos-collector {} ({})",
                env!("CARGO_PKG_VERSION"),
                option_env!("EPITROPOS_COLLECTOR_GIT_COMMIT").unwrap_or("unknown")
            );
        }
        Command::Keygen => {
            if let Err(e) = run_keygen() {
                eprintln!("epitropos-collector keygen: {e}");
                std::process::exit(e.exit_code());
            }
        }
        Command::Enroll { sender_name, ttl } => {
            if let Err(e) = run_enroll_generate(&sender_name, ttl) {
                eprintln!("epitropos-collector enroll: {e}");
                std::process::exit(e.exit_code());
            }
        }
        Command::List => {
            if let Err(e) = run_list() {
                eprintln!("epitropos-collector list: {e}");
                std::process::exit(e.exit_code());
            }
        }
        Command::Revoke { sender_name, force } => {
            if let Err(e) = run_revoke(&sender_name, force) {
                eprintln!("epitropos-collector revoke: {e}");
                std::process::exit(e.exit_code());
            }
        }
        Command::Serve { config_path } => {
            if let Err(e) = run_serve(&config_path) {
                eprintln!("epitropos-collector serve: {e}");
                std::process::exit(e.exit_code());
            }
        }
        Command::Verify { path } => {
            eprintln!("epitropos-collector verify: not yet implemented in Track C");
            std::process::exit(69);
        }
        Command::RotateCert => {
            eprintln!("epitropos-collector rotate-cert: not yet implemented in Track C");
            std::process::exit(69);
        }
    }
}

fn run_keygen() -> Result<(), CollectorError> {
    let cfg = Config::default();
    let cert_path = cfg.tls_cert_path();
    let key_path = cfg.tls_key_path();
    let secret_path = cfg.enroll_secret_path();

    if cert_path.exists() {
        eprintln!("TLS cert already exists at {}", cert_path.display());
        return Ok(());
    }

    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_else(|_| "localhost".into())
        .trim()
        .to_string();

    tls::generate_self_signed(&cert_path, &key_path, &hostname)?;
    enroll::generate_secret(&secret_path)?;

    let der = tls::read_cert_der(&cert_path)?;
    let fp = tls::fingerprint_hex(&der);
    eprintln!("Generated TLS cert: {}", cert_path.display());
    eprintln!("Fingerprint: SHA256:{fp}");
    eprintln!("Enrollment secret: {}", secret_path.display());
    Ok(())
}

fn run_enroll_generate(sender_name: &str, ttl: Option<u64>) -> Result<(), CollectorError> {
    let cfg = Config::default();
    let secret = enroll::load_secret(&cfg.enroll_secret_path())?;
    let ttl = ttl.unwrap_or(cfg.enrollment.token_ttl_seconds);
    let edir = EnrollmentDir::under(&cfg.storage.dir);
    edir.ensure_created()?;

    let gt = enroll::generate_token(&secret, sender_name, ttl)?;
    enroll::write_pending(&edir, &gt.token_hash_hex, sender_name, gt.expires_at)?;

    let cert_path = cfg.tls_cert_path();
    let der = tls::read_cert_der(&cert_path)?;
    let fp = tls::fingerprint_hex(&der);

    println!("Generated enrollment token (valid for {ttl} seconds, single use):\n");
    println!("  {}\n", gt.token);
    println!("Collector TLS fingerprint:\n  SHA256:{fp}\n");
    println!("Deploy this token to the sender and run:");
    println!(
        "  epitropos-forward enroll --collector <addr>:8443 \\\n      --token {} \\\n      --expect-fingerprint SHA256:{fp}",
        gt.token
    );
    Ok(())
}

fn run_list() -> Result<(), CollectorError> {
    let cfg = Config::default();
    let senders_dir = cfg.storage.dir.join("senders");
    let read = std::fs::read_dir(&senders_dir)
        .map_err(|e| CollectorError::Storage(format!("read senders: {e}")))?;

    println!("{:<25} {:<20} {}", "SENDER", "ENROLLED", "HEAD");
    for entry in read {
        let entry = entry.map_err(|e| CollectorError::Storage(format!("entry: {e}")))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let enrolled = std::fs::read_to_string(entry.path().join("enrolled_at"))
            .unwrap_or_else(|_| "unknown".into());
        let head = std::fs::read_to_string(entry.path().join("head.hash"))
            .unwrap_or_else(|_| "(genesis)".into());
        let head_short = if head.len() > 16 {
            &head[..16]
        } else {
            &head
        };
        println!("{:<25} {:<20} {}...", name, enrolled.trim(), head_short);
    }
    Ok(())
}

fn run_revoke(sender_name: &str, force: bool) -> Result<(), CollectorError> {
    let cfg = Config::default();
    let sender = SenderDirs::under(&cfg.storage.dir, sender_name)?;
    if !sender.root.exists() {
        return Err(CollectorError::Storage(format!(
            "sender {sender_name} not found"
        )));
    }
    if !force {
        eprintln!(
            "This will revoke sender {sender_name}. Recordings will be preserved.\n\
             Pass --force to confirm."
        );
        return Err(CollectorError::Usage("revoke requires --force".into()));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let revoked_dir = cfg
        .storage
        .dir
        .join("senders-revoked")
        .join(format!("{sender_name}.{now}"));
    std::fs::create_dir_all(revoked_dir.parent().unwrap())
        .map_err(|e| CollectorError::Storage(format!("mkdir revoked: {e}")))?;
    std::fs::rename(&sender.root, &revoked_dir)
        .map_err(|e| CollectorError::Storage(format!("rename: {e}")))?;
    eprintln!("Revoked {sender_name} → {}", revoked_dir.display());
    Ok(())
}

#[tokio::main]
async fn run_serve_async(cfg: Config) -> Result<(), CollectorError> {
    let cert_path = cfg.tls_cert_path();
    let key_path = cfg.tls_key_path();
    let secret = enroll::load_secret(&cfg.enroll_secret_path())?;
    let cert_pem = tls::read_cert_pem(&cert_path)?;
    let cert_der = tls::read_cert_der(&cert_path)?;
    let fp = tls::fingerprint_hex(&cert_der);

    // Load already-enrolled sender certs into the pinned set.
    let pinned = PinnedCerts::new();
    let senders_dir = cfg.storage.dir.join("senders");
    if senders_dir.exists() {
        if let Ok(read) = std::fs::read_dir(&senders_dir) {
            for entry in read.flatten() {
                let fp_file = entry.path().join("cert.fingerprint");
                if let Ok(fp_hex) = std::fs::read_to_string(&fp_file) {
                    pinned.add_hex(fp_hex.trim());
                }
            }
        }
    }

    let state = AppState {
        cfg: Arc::new(cfg.clone()),
        pinned: pinned.clone(),
        enroll_secret: Arc::new(secret),
        collector_cert_pem: Arc::new(cert_pem),
        collector_fingerprint_hex: Arc::new(fp),
    };

    let app = server::router(state);
    let addr = format!("{}:{}", cfg.listen.address, cfg.listen.port);
    eprintln!("epitropos-collector: listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| CollectorError::Tls(format!("bind {addr}: {e}")))?;
    axum::serve(listener, app)
        .await
        .map_err(|e| CollectorError::Tls(format!("serve: {e}")))?;
    Ok(())
}

fn run_serve(config_path: &Path) -> Result<(), CollectorError> {
    let cfg = if config_path.exists() {
        Config::load(config_path)?
    } else {
        eprintln!(
            "Config not found at {}; using defaults",
            config_path.display()
        );
        Config::default()
    };
    // NOTE: This runs without TLS for now. Task 14 adds the rustls
    // TLS acceptor. The PinnedClientVerifier from tls.rs will be
    // wired in there.
    run_serve_async(cfg)
}
