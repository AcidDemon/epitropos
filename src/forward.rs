use inotify::{EventMask, Inotify, WatchMask};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

const DEFAULT_WATCH_DIR: &str = "/var/log/ssh-sessions";
const MARKER_SUFFIX: &str = ".forwarded";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut watch_dir = DEFAULT_WATCH_DIR.to_string();
    let mut dest: Option<String> = None;
    let mut dry_run = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-d" | "--dir" if i + 1 < args.len() => {
                i += 1;
                watch_dir = args[i].clone();
            }
            "--dest" if i + 1 < args.len() => {
                i += 1;
                dest = Some(args[i].clone());
            }
            "--dry-run" => dry_run = true,
            "-h" | "--help" => {
                eprintln!("Usage: epitropos-forward [OPTIONS]");
                eprintln!();
                eprintln!("  -d, --dir <PATH>    Watch directory (default: {DEFAULT_WATCH_DIR})");
                eprintln!("  --dest <URL>        Forwarding destination (not yet implemented)");
                eprintln!("  --dry-run           Hash and log but don't forward");
                eprintln!("  -h, --help          Show this help");
                std::process::exit(0);
            }
            other => {
                eprintln!("epitropos-forward: unknown option: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    if let Err(e) = run(&watch_dir, dest.as_deref(), dry_run) {
        eprintln!("epitropos-forward: {e}");
        std::process::exit(1);
    }
}

fn run(watch_dir: &str, dest: Option<&str>, dry_run: bool) -> Result<(), String> {
    eprintln!("epitropos-forward: watching {watch_dir}");
    if let Some(d) = dest {
        eprintln!("epitropos-forward: destination {d}");
    }

    // Process existing files first
    process_existing(watch_dir, dest, dry_run)?;

    // Watch for new files
    let mut inotify = Inotify::init().map_err(|e| format!("inotify init: {e}"))?;

    // Watch the base dir for new user directories
    inotify
        .watches()
        .add(watch_dir, WatchMask::CREATE | WatchMask::MOVED_TO)
        .map_err(|e| format!("watch {watch_dir}: {e}"))?;

    // Watch existing user subdirectories
    let mut watched_dirs: HashSet<PathBuf> = HashSet::new();
    if let Ok(entries) = fs::read_dir(watch_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                inotify
                    .watches()
                    .add(&path, WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO)
                    .map_err(|e| format!("watch {}: {e}", path.display()))?;
                watched_dirs.insert(path);
            }
        }
    }

    let mut buf = [0u8; 4096];
    loop {
        let events = inotify
            .read_events_blocking(&mut buf)
            .map_err(|e| format!("inotify read: {e}"))?;

        for event in events {
            if event.mask.contains(EventMask::ISDIR) {
                // New user directory — start watching it
                if let Some(name) = event.name {
                    let dir = PathBuf::from(watch_dir).join(name);
                    if !watched_dirs.contains(&dir) {
                        let _ = inotify
                            .watches()
                            .add(&dir, WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO);
                        watched_dirs.insert(dir);
                    }
                }
            } else if let Some(name) = event.name {
                let name_str = name.to_string_lossy();
                if is_recording(&name_str) {
                    // Find which watched dir this belongs to
                    for dir in &watched_dirs {
                        let path = dir.join(&*name_str);
                        if path.exists() {
                            process_file(&path, dest, dry_run);
                            break;
                        }
                    }
                }
            }
        }
    }
}

fn process_existing(watch_dir: &str, dest: Option<&str>, dry_run: bool) -> Result<(), String> {
    let entries = fs::read_dir(watch_dir).map_err(|e| format!("read {watch_dir}: {e}"))?;
    for entry in entries.flatten() {
        let user_dir = entry.path();
        if !user_dir.is_dir() {
            continue;
        }
        if let Ok(files) = fs::read_dir(&user_dir) {
            for file in files.flatten() {
                let path = file.path();
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                if is_recording(&name) && !has_marker(&path) {
                    process_file(&path, dest, dry_run);
                }
            }
        }
    }
    Ok(())
}

fn is_recording(name: &str) -> bool {
    name.ends_with(".cast") || name.ends_with(".cast.age")
}

fn has_marker(path: &Path) -> bool {
    let marker = format!("{}{MARKER_SUFFIX}", path.display());
    Path::new(&marker).exists()
}

fn write_marker(path: &Path) {
    let marker = format!("{}{MARKER_SUFFIX}", path.display());
    let _ = fs::write(&marker, "");
}

fn process_file(path: &Path, _dest: Option<&str>, dry_run: bool) {
    let hash = match hash_file(path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("epitropos-forward: hash {}: {e}", path.display());
            return;
        }
    };

    let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    eprintln!(
        "{{\"event\":\"recording_ready\",\"path\":\"{}\",\"sha256\":\"{hash}\",\"size\":{size}}}",
        path.display()
    );

    if dry_run {
        write_marker(path);
        return;
    }

    // TODO: forward to dest (S3, HTTP endpoint, scp, etc.)
    // For now, just log the hash commitment and mark as forwarded.
    write_marker(path);
}

fn hash_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|e| format!("{e}"))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf).map_err(|e| format!("{e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}
