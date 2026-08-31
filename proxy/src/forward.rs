//! epitropos-forward — ships recordings to a collector.
//!
//! Subcommands:
//!   enroll --collector <addr> --token <t> --expect-fingerprint <fp>
//!   push [--once]
//!   status

use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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

// --- mTLS client ---

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Pins the collector's (self-signed) server cert by SHA-256 fingerprint,
/// matching the enrollment `--expect-fingerprint` trust model.
#[derive(Debug)]
struct PinnedServerVerifier {
    expected_fp: String,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let fp = sha256_hex(end_entity.as_ref());
        if fp.eq_ignore_ascii_case(&self.expected_fp) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "collector cert fingerprint mismatch (expected {}, got {fp})",
                self.expected_fp
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a ureq agent that pins the collector cert to `expected_collector_fp`
/// (hex SHA-256) and presents this sender's client cert (mTLS), for both enroll
/// and push.
fn build_agent(expected_collector_fp: &str) -> Result<ureq::Agent, String> {
    let cert_pem = fs::read(PathBuf::from(STATE_DIR).join("cert.pem"))
        .map_err(|e| format!("read cert: {e}"))?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse cert: {e}"))?;
    let key_pem =
        fs::read(PathBuf::from(STATE_DIR).join("key.pem")).map_err(|e| format!("read key: {e}"))?;
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| format!("parse key: {e}"))?
        .ok_or("no private key in key.pem")?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinnedServerVerifier {
        expected_fp: expected_collector_fp.to_lowercase(),
        provider: provider.clone(),
    });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(certs, key)
        .map_err(|e| format!("client auth cert: {e}"))?;
    Ok(ureq::AgentBuilder::new()
        .tls_config(Arc::new(config))
        .build())
}

fn cmd_enroll(args: &[String]) -> Result<(), String> {
    let collector = find_flag(args, "--collector").ok_or("--collector <addr:port> required")?;
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
        return Err(format!(
            "signing.pub must be 32 bytes, got {}",
            signing_pub.len()
        ));
    }

    let sender_name = fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string();

    let expect_fp_clean = expect_fp
        .strip_prefix("SHA256:")
        .unwrap_or(&expect_fp)
        .to_string();
    let url = format!("https://{collector}/v1/enroll");
    eprintln!("Connecting to {url}...");

    let body = serde_json::json!({
        "sender_name": sender_name,
        "token": token,
        "tls_cert_pem": tls_cert_pem,
        "signing_pub_hex": hex::encode(&signing_pub),
    });

    // mTLS: pin the collector cert to the expected fingerprint and present our
    // client cert (the collector binds it as proof of possession).
    let agent = build_agent(&expect_fp_clean)?;
    let resp = agent
        .post(&url)
        .send_json(&body)
        .map_err(|e| format!("POST enroll: {e}"))?;

    let resp_status = resp.status();
    if resp_status != 200 {
        let body_str = resp.into_string().unwrap_or_default();
        return Err(format!("enroll failed (HTTP {resp_status}): {body_str}"));
    }

    let resp_json: serde_json::Value = resp
        .into_json()
        .map_err(|e| format!("parse response: {e}"))?;

    // Verify fingerprint.
    let collector_fp = resp_json["collector_fingerprint_sha256"]
        .as_str()
        .unwrap_or("");
    if collector_fp != expect_fp_clean.as_str() {
        return Err(format!(
            "fingerprint mismatch! expected {expect_fp_clean}, got {collector_fp}"
        ));
    }

    // Pin collector cert.
    let collector_cert_pem = resp_json["collector_tls_cert_pem"].as_str().unwrap_or("");
    fs::write(
        PathBuf::from(STATE_DIR).join("collector.pem"),
        collector_cert_pem,
    )
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
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("sign: {e}"))?;
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

    // Pin the collector cert saved at enrollment and present our client cert.
    let collector_pem = fs::read(PathBuf::from(STATE_DIR).join("collector.pem"))
        .map_err(|e| format!("read collector.pem: {e}"))?;
    let collector_certs: Vec<_> = rustls_pemfile::certs(&mut &collector_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse collector.pem: {e}"))?;
    let collector_der = collector_certs
        .first()
        .ok_or("collector.pem contains no certificate")?;
    let agent = build_agent(&sha256_hex(collector_der.as_ref()))?;

    let mut shipped = 0;
    for line in pending.iter().take(16) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let (user, session_id, part_str, manifest_hash) = (parts[1], parts[2], parts[3], parts[4]);
        let part: u32 = part_str.parse().unwrap_or(0);

        let rec_name = format!("{session_id}.part{part}.kgv1.age");
        let rec_path = recording_root.join(user).join(&rec_name);
        let sidecar_path = recording_root
            .join(user)
            .join(format!("{rec_name}.manifest.json"));

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

        match agent
            .post(&url)
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

        // Best-effort: ship the authoritative privilege-events sidecar if the
        // epitropos-audit daemon has already produced it. Timing: it is produced
        // on manifest arrival, so it usually exists by this tick. ponytail: no
        // re-ship if it lands after this entry advances — robust backfill deferred.
        let priv_path = recording_root
            .join(user)
            .join(format!("{rec_name}.privileges.json"));
        if priv_path.exists() {
            match fs::read(&priv_path) {
                Ok(priv_bytes) => {
                    let purl = format!(
                        "https://{collector_addr}/v1/sessions/{session_id}/parts/{part}/privileges"
                    );
                    match agent
                        .post(&purl)
                        .set("Content-Type", "application/json")
                        .send_bytes(&priv_bytes)
                    {
                        Ok(r) if r.status() == 200 => eprintln!("  privileges OK"),
                        Ok(r) => eprintln!("  privileges push HTTP {}", r.status()),
                        Err(e) => eprintln!("  privileges push failed: {e}"),
                    }
                }
                Err(e) => eprintln!("  read privileges sidecar: {e}"),
            }
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
        c.lines()
            .position(|l| l.ends_with(&last))
            .map(|i| i + 1)
            .unwrap_or(0)
    } else {
        0
    };

    println!("Total:   {total}");
    println!("Shipped: {shipped}");
    println!("Pending: {}", total.saturating_sub(shipped));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier;

    #[test]
    fn pinned_server_verifier_matches_only_expected_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("c.pem");
        let key = dir.path().join("k.pem");
        generate_self_signed(&cert, &key, "collector").unwrap();
        let pem = fs::read(&cert).unwrap();
        let certs: Vec<_> = rustls_pemfile::certs(&mut &pem[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let der = &certs[0];
        let fp = sha256_hex(der.as_ref());

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let sn = rustls::pki_types::ServerName::try_from("collector").unwrap();
        let now = rustls::pki_types::UnixTime::now();

        // Matching fingerprint -> accepted.
        let good = PinnedServerVerifier {
            expected_fp: fp,
            provider: provider.clone(),
        };
        assert!(good.verify_server_cert(der, &[], &sn, &[], now).is_ok());

        // Any other fingerprint -> rejected (a MITM's cert is refused).
        let bad = PinnedServerVerifier {
            expected_fp: "deadbeef".into(),
            provider,
        };
        assert!(bad.verify_server_cert(der, &[], &sn, &[], now).is_err());
    }
}
