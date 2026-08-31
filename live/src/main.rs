mod discover;
mod stream;

use std::sync::atomic::{AtomicBool, Ordering};

const DEFAULT_LIVE_DIR: &str = "/run/epitropos/live";

static CTRL_C_FLAG: AtomicBool = AtomicBool::new(false);

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!(
            "epitropos-live {} ({})",
            env!("CARGO_PKG_VERSION"),
            env!("EPITROPOS_GIT_COMMIT")
        );
        std::process::exit(0);
    }

    let subcmd = args.get(1).map(|s| s.as_str());
    match subcmd {
        Some("list") => cmd_list(&args[2..]),
        Some("watch") => cmd_watch(&args[2..]),
        _ => {
            eprintln!("Usage: epitropos-live <list|watch> [OPTIONS]");
            eprintln!();
            eprintln!("  list              Show active sessions");
            eprintln!("  watch <SESSION>   Stream a live session");
            eprintln!("  --version         Show version");
            std::process::exit(if subcmd.is_some() { 1 } else { 0 });
        }
    }
}

fn cmd_list(args: &[String]) {
    let mut dir = DEFAULT_LIVE_DIR.to_string();
    let mut identity_path: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-d" | "--dir" if i + 1 < args.len() => {
                i += 1;
                dir = args[i].clone();
            }
            "-i" | "--identity" if i + 1 < args.len() => {
                i += 1;
                identity_path = Some(args[i].clone());
            }
            "-h" | "--help" => {
                eprintln!("Usage: epitropos-live list [--dir DIR] [--identity KEYFILE]");
                std::process::exit(0);
            }
            other => {
                eprintln!("epitropos-live list: unknown option: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let identity = load_identity(identity_path);
    let sessions = discover::list_sessions(std::path::Path::new(&dir), &identity);
    if sessions.is_empty() {
        eprintln!("No active sessions.");
        return;
    }

    println!(
        "{:<20} {:<12} {:<16} {:<10}",
        "SESSION", "USER", "HOST", "TERMINAL"
    );
    for s in &sessions {
        println!(
            "{:<20} {:<12} {:<16} {}x{}",
            s.session_id, s.user, s.host, s.cols, s.rows,
        );
    }
}

fn cmd_watch(args: &[String]) {
    let mut dir = DEFAULT_LIVE_DIR.to_string();
    let mut session_id: Option<String> = None;
    let mut identity_path: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-d" | "--dir" if i + 1 < args.len() => {
                i += 1;
                dir = args[i].clone();
            }
            "-i" | "--identity" if i + 1 < args.len() => {
                i += 1;
                identity_path = Some(args[i].clone());
            }
            "-h" | "--help" => {
                eprintln!(
                    "Usage: epitropos-live watch [--dir DIR] [--identity KEYFILE] <SESSION_ID>"
                );
                std::process::exit(0);
            }
            other if !other.starts_with('-') => {
                session_id = Some(other.to_string());
            }
            other => {
                eprintln!("epitropos-live watch: unknown option: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let identity = load_identity(identity_path);

    let sid = match session_id {
        Some(s) => s,
        None => {
            eprintln!("epitropos-live watch: missing session ID argument");
            std::process::exit(1);
        }
    };

    let path = std::path::Path::new(&dir).join(format!("{sid}.age"));
    if !path.exists() {
        eprintln!("epitropos-live: session not found: {sid}");
        eprintln!("Use 'epitropos-live list' to see active sessions.");
        std::process::exit(1);
    }

    if let Some(info) = discover::list_sessions(std::path::Path::new(&dir), &identity)
        .into_iter()
        .find(|s| s.session_id == sid)
    {
        eprintln!(
            "Watching session {} (user={} host={} {}x{})",
            info.session_id, info.user, info.host, info.cols, info.rows,
        );
        eprintln!("Press Ctrl-C to detach.");
    }

    unsafe {
        libc::signal(
            libc::SIGINT,
            sigint_handler as *const () as libc::sighandler_t,
        );
    }

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    match stream::stream_session(&path, &mut out, &CTRL_C_FLAG, &identity) {
        Ok(result) => {
            eprintln!(
                "\nSession ended ({} output records).",
                result.records_played
            );
        }
        Err(e) => {
            eprintln!("\nepitropos-live: {e}");
            std::process::exit(1);
        }
    }
}

/// Load the operator age identity from `--identity <path>` or the
/// EPITROPOS_LIVE_IDENTITY env var. The identity is the capability to view live
/// sessions; it is never shipped in the Nix store and must be operator-managed.
/// Exits with a clear message if absent or invalid.
fn load_identity(flag: Option<String>) -> age::x25519::Identity {
    let path = flag
        .or_else(|| std::env::var("EPITROPOS_LIVE_IDENTITY").ok())
        .unwrap_or_else(|| {
            eprintln!(
                "epitropos-live: an age identity is required to decrypt live sessions\n\
                 provide it with --identity <path> or the EPITROPOS_LIVE_IDENTITY env var"
            );
            std::process::exit(1);
        });
    let contents = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("epitropos-live: cannot read identity {path}: {e}");
        std::process::exit(1);
    });
    let line = contents
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .unwrap_or("");
    line.parse().unwrap_or_else(|e| {
        eprintln!("epitropos-live: invalid age identity in {path}: {e}");
        std::process::exit(1);
    })
}

extern "C" fn sigint_handler(_: libc::c_int) {
    CTRL_C_FLAG.store(true, Ordering::Relaxed);
}
