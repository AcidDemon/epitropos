//! epitropos-forward — ships recordings to a collector.
//!
//! Subcommands:
//!   enroll --collector <addr> --token <t> --expect-fingerprint <fp>
//!   push [--once]
//!   status

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const STATE_DIR: &str = "/var/lib/epitropos-forward";
const DEFAULT_HEAD_LOG: &str = "/var/lib/katagrapho/head.hash.log";
const DEFAULT_RECORDING_ROOT: &str = "/var/log/ssh-sessions";

fn main() {
    let args: Vec<String> = std::env::args().collect();

    for arg in args.iter().skip(1) {
        if arg == "--version" || arg == "-V" {
            println!(
                "epitropos-forward {} ({})",
                env!("CARGO_PKG_VERSION"),
                env!("EPITROPOS_GIT_COMMIT")
            );
            std::process::exit(0);
        }
    }

    if args.len() < 2 {
        print_usage();
        std::process::exit(64);
    }

    let result = match args[1].as_str() {
        "enroll" => cmd_enroll(&args[2..]),
        "push" => cmd_push(&args[2..]),
        "status" => cmd_status(&args[2..]),
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(())
        }
        other => {
            eprintln!("epitropos-forward: unknown subcommand: {other}");
            print_usage();
            std::process::exit(64);
        }
    };

    if let Err(e) = result {
        eprintln!("epitropos-forward: {e}");
        std::process::exit(1);
    }
}

fn print_usage() {
    eprintln!(
        "Usage: epitropos-forward <command>\n\
         \n\
         Commands:\n\
           enroll --collector <addr:port> --token <t> --expect-fingerprint <fp>\n\
           push   [--once]\n\
           status\n\
           --version"
    );
}

fn find_flag(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

// ---------------------------------------------------------------------------
// Enroll
// ---------------------------------------------------------------------------

fn cmd_enroll(args: &[String]) -> Result<(), String> {
    let collector =
        find_flag(args, "--collector").ok_or("--collector <addr:port> required")?;
    let token = find_flag(args, "--token").ok_or("--token required")?;
    let expect_fp =
        find_flag(args, "--expect-fingerprint").ok_or("--expect-fingerprint required")?;

    fs::create_dir_all(STATE_DIR).map_err(|e| format!("mkdir {STATE_DIR}: {e}"))?;

    // Generate sender TLS cert if it doesn't exist.
    let cert_path = PathBuf::from(STATE_DIR).join("cert.pem");
    let key_path = PathBuf::from(STATE_DIR).join("key.pem");
    if !cert_path.exists() {
        eprintln!("Generating sender TLS certificate...");
        let hostname = fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap_or_else(|_| "localhost".into())
            .trim()
            .to_string();
        generate_self_signed(&cert_path, &key_path, &hostname)?;
    }

    let tls_cert_pem = fs::read_to_string(&cert_path).map_err(|e| format!("read cert: {e}"))?;

    // Read katagrapho signing.pub.
    let signing_pub = fs::read("/var/lib/katagrapho/signing.pub")
        .map_err(|e| format!("read signing.pub: {e}"))?;
    if signing_pub.len() != 32 {
        return Err(format!("signing.pub must be 32 bytes, got {}", signing_pub.len()));
    }

    let sender_name = fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string();

    let url = format!("https://{collector}/v1/enroll");
    eprintln!("Connecting to {url}...");

    let body = serde_json::json!({
        "sender_name": sender_name,
        "token": token,
        "tls_cert_pem": tls_cert_pem,
        "signing_pub_hex": hex::encode(&signing_pub),
    });

    let resp = ureq::post(&url)
        .send_json(&body)
        .map_err(|e| format!("POST enroll: {e}"))?;

    let resp_status = resp.status();
    if resp_status != 200 {
        let body_str = resp.into_string().unwrap_or_default();
        return Err(format!("enroll failed (HTTP {resp_status}): {body_str}"));
    }

    let resp_json: serde_json::Value =
        resp.into_json().map_err(|e| format!("parse response: {e}"))?;

    // Verify fingerprint.
    let collector_fp = resp_json["collector_fingerprint_sha256"]
        .as_str()
        .unwrap_or("");
    let expect_fp_clean = expect_fp.strip_prefix("SHA256:").unwrap_or(&expect_fp);
    if collector_fp != expect_fp_clean {
        return Err(format!(
            "fingerprint mismatch! expected {expect_fp_clean}, got {collector_fp}"
        ));
    }

    // Pin collector cert.
    let collector_cert_pem = resp_json["collector_tls_cert_pem"].as_str().unwrap_or("");
    fs::write(PathBuf::from(STATE_DIR).join("collector.pem"), collector_cert_pem)
        .map_err(|e| format!("write collector.pem: {e}"))?;

    // Save collector address for push.
    fs::write(PathBuf::from(STATE_DIR).join("collector_addr"), &collector)
        .map_err(|e| format!("write collector_addr: {e}"))?;

    eprintln!("Enrolled as \"{sender_name}\".");
    Ok(())
}

fn generate_self_signed(cert_path: &Path, key_path: &Path, cn: &str) -> Result<(), String> {
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).map_err(|e| format!("keygen: {e}"))?;
    let mut params =
        rcgen::CertificateParams::new(vec![cn.to_string()]).map_err(|e| format!("params: {e}"))?;
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = params.not_before + time::Duration::days(365 * 10);
    let cert = params.self_signed(&key_pair).map_err(|e| format!("sign: {e}"))?;
    write_pem(key_path, key_pair.serialize_pem().as_bytes(), 0o400)?;
    write_pem(cert_path, cert.pem().as_bytes(), 0o444)?;
    Ok(())
}

fn write_pem(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
    }
    let tmp = path.with_extension("pem.tmp");
    let mut f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp)
        .map_err(|e| format!("open: {e}"))?;
    f.write_all(data).map_err(|e| format!("write: {e}"))?;
    f.sync_all().map_err(|e| format!("fsync: {e}"))?;
    drop(f);
    fs::rename(&tmp, path).map_err(|e| format!("rename: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Push
// ---------------------------------------------------------------------------

fn cmd_push(_args: &[String]) -> Result<(), String> {
    let head_log = PathBuf::from(DEFAULT_HEAD_LOG);
    let recording_root = PathBuf::from(DEFAULT_RECORDING_ROOT);
    let last_shipped_path = PathBuf::from(STATE_DIR).join("last_shipped.hash");

    if !PathBuf::from(STATE_DIR).join("collector.pem").exists() {
        return Err("not enrolled — run `epitropos-forward enroll` first".into());
    }
    if !head_log.exists() {
        eprintln!("No head.hash.log yet; nothing to ship.");
        return Ok(());
    }

    let last_shipped = if last_shipped_path.exists() {
        fs::read_to_string(&last_shipped_path)
            .map_err(|e| format!("read last_shipped: {e}"))?
            .trim()
            .to_string()
    } else {
        "0".repeat(64)
    };

    let log_content = fs::read_to_string(&head_log).map_err(|e| format!("read head log: {e}"))?;
    let lines: Vec<&str> = log_content.lines().collect();

    let start_idx = if last_shipped == "0".repeat(64) {
        0
    } else {
        lines
            .iter()
            .position(|l| l.ends_with(&last_shipped))
            .map(|i| i + 1)
            .unwrap_or(0)
    };

    let pending = &lines[start_idx..];
    if pending.is_empty() {
        eprintln!("Nothing to ship.");
        return Ok(());
    }
    eprintln!("{} pending entries.", pending.len());

    let collector_addr = fs::read_to_string(PathBuf::from(STATE_DIR).join("collector_addr"))
        .unwrap_or_else(|_| "localhost:8443".into())
        .trim()
        .to_string();

    let mut shipped = 0;
    for line in pending.iter().take(16) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let (user, session_id, part_str, manifest_hash) =
            (parts[1], parts[2], parts[3], parts[4]);
        let part: u32 = part_str.parse().unwrap_or(0);

        let rec_name = format!("{session_id}.part{part}.kgv1.age");
        let rec_path = recording_root.join(user).join(&rec_name);
        let sidecar_path = recording_root.join(user).join(format!("{rec_name}.manifest.json"));

        if !rec_path.exists() || !sidecar_path.exists() {
            eprintln!("Missing files for {session_id} part {part}; skipping");
            continue;
        }

        let sidecar_bytes = fs::read(&sidecar_path).map_err(|e| format!("read sidecar: {e}"))?;
        let recording_bytes = fs::read(&rec_path).map_err(|e| format!("read recording: {e}"))?;

        let manifest_len = sidecar_bytes.len() as u32;
        let mut body = Vec::with_capacity(4 + sidecar_bytes.len() + recording_bytes.len());
        body.extend_from_slice(&manifest_len.to_be_bytes());
        body.extend_from_slice(&sidecar_bytes);
        body.extend_from_slice(&recording_bytes);

        let url = format!("https://{collector_addr}/v1/sessions/{session_id}/parts/{part}");
        eprintln!("Pushing {session_id} part {part}...");

        match ureq::post(&url)
            .set("Content-Type", "application/octet-stream")
            .send_bytes(&body)
        {
            Ok(r) if r.status() == 200 || r.status() == 409 => {
                eprintln!("  OK ({})", r.status());
            }
            Ok(r) => {
                let st = r.status();
                let b = r.into_string().unwrap_or_default();
                return Err(format!("push failed (HTTP {st}): {b}"));
            }
            Err(e) => return Err(format!("push failed: {e}")),
        }

        let tmp = last_shipped_path.with_extension("tmp");
        fs::write(&tmp, manifest_hash).map_err(|e| format!("write: {e}"))?;
        fs::rename(&tmp, &last_shipped_path).map_err(|e| format!("rename: {e}"))?;
        shipped += 1;
    }

    eprintln!("Shipped {shipped} entries.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

fn cmd_status(_args: &[String]) -> Result<(), String> {
    let head_log = PathBuf::from(DEFAULT_HEAD_LOG);
    let last_shipped_path = PathBuf::from(STATE_DIR).join("last_shipped.hash");

    println!(
        "Enrollment:  {}",
        if PathBuf::from(STATE_DIR).join("collector.pem").exists() {
            "yes"
        } else {
            "no"
        }
    );

    let total = if head_log.exists() {
        fs::read_to_string(&head_log)
            .map(|s| s.lines().count())
            .unwrap_or(0)
    } else {
        0
    };

    let last = if last_shipped_path.exists() {
        fs::read_to_string(&last_shipped_path)
            .unwrap_or_default()
            .trim()
            .to_string()
    } else {
        "0".repeat(64)
    };

    let shipped = if last == "0".repeat(64) {
        0
    } else if head_log.exists() {
        let c = fs::read_to_string(&head_log).unwrap_or_default();
        c.lines().position(|l| l.ends_with(&last)).map(|i| i + 1).unwrap_or(0)
    } else {
        0
    };

    println!("Total:   {total}");
    println!("Shipped: {shipped}");
    println!("Pending: {}", total.saturating_sub(shipped));
    Ok(())
}
