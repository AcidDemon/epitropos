use std::io::{self, BufRead, Seek, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

enum Format {
    Kgv1,
    AsciicastV2,
    Unknown,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    for arg in args.iter().skip(1) {
        if arg == "--version" || arg == "-V" {
            println!(
                "epitropos-play {} ({})",
                env!("CARGO_PKG_VERSION"),
                env!("EPITROPOS_GIT_COMMIT")
            );
            std::process::exit(0);
        }
    }
    let mut speed = 1.0_f64;
    let mut file_path: Option<String> = None;
    let mut follow = false;
    let mut force = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-s" | "--speed" if i + 1 < args.len() => {
                i += 1;
                speed = args[i].parse().unwrap_or(1.0);
            }
            "-f" | "--follow" => follow = true,
            "--force" => force = true,
            "-h" | "--help" => {
                eprintln!("Usage: epitropos-play [OPTIONS] <FILE>");
                eprintln!();
                eprintln!("  -s, --speed <N>   Playback speed multiplier (default: 1.0)");
                eprintln!("  -f, --follow      Wait for new data (live session)");
                eprintln!("      --force       Play even if signature verification fails");
                eprintln!("  -h, --help        Show this help");
                std::process::exit(0);
            }
            other if !other.starts_with('-') => file_path = Some(other.to_string()),
            other => {
                eprintln!("epitropos-play: unknown option: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let path = match file_path {
        Some(p) => p,
        None => {
            eprintln!("epitropos-play: missing file argument");
            std::process::exit(1);
        }
    };

    // If a manifest sidecar exists for this recording, verify the
    // signature before playback. Shell out to katagrapho-verify; on
    // missing binary or sidecar, fall through with a note.
    verify_sidecar(&path, force);

    if let Err(e) = play(&path, speed, follow) {
        eprintln!("epitropos-play: {e}");
        std::process::exit(1);
    }
}

fn sidecar_path_for(recording: &str) -> PathBuf {
    let mut s = Path::new(recording).as_os_str().to_os_string();
    s.push(".manifest.json");
    PathBuf::from(s)
}

fn verify_sidecar(path: &str, force: bool) {
    let sidecar = sidecar_path_for(path);
    if !sidecar.exists() {
        // No sidecar: legacy recording or write-in-progress. Silent.
        return;
    }

    let status = std::process::Command::new("katagrapho-verify")
        .arg(&sidecar)
        .status();

    match status {
        Ok(s) if s.success() => {
            eprintln!("epitropos-play: signature verified");
        }
        Ok(s) => {
            if force {
                eprintln!(
                    "epitropos-play: WARNING signature verification failed (exit={:?}); \
                     --force in effect",
                    s.code()
                );
            } else {
                eprintln!(
                    "epitropos-play: signature verification failed (exit={:?}); \
                     pass --force to play anyway",
                    s.code()
                );
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!(
                "epitropos-play: katagrapho-verify not available ({e}); \
                 skipping signature check"
            );
        }
    }
}

fn detect_format(first_line: &str) -> Format {
    if first_line.contains("\"kind\":\"header\"") && first_line.contains("\"v\":\"katagrapho-v1\"")
    {
        Format::Kgv1
    } else if first_line.contains("\"version\":2") || first_line.contains("\"version\": 2") {
        Format::AsciicastV2
    } else {
        Format::Unknown
    }
}

fn play(path: &str, speed: f64, follow: bool) -> Result<(), String> {
    let mut file = std::fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?;

    // Peek the first line to detect the format.
    let mut first_line = String::new();
    {
        let mut peek_reader = io::BufReader::new(&file);
        peek_reader
            .read_line(&mut first_line)
            .map_err(|e| format!("read: {e}"))?;
    }
    file.seek(io::SeekFrom::Start(0))
        .map_err(|e| format!("seek: {e}"))?;

    let format = detect_format(first_line.trim());
    match format {
        Format::Kgv1 => play_kgv1(file, speed, follow),
        Format::AsciicastV2 => play_asciicast_v2(file, speed, follow),
        Format::Unknown => Err(format!(
            "unknown recording format (first line: {:?})",
            first_line.trim()
        )),
    }
}

fn play_kgv1(mut file: std::fs::File, speed: f64, follow: bool) -> Result<(), String> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut prev_time: f64 = 0.0;
    let mut first_line = true;
    let mut line_buf = String::new();

    loop {
        let mut reader = io::BufReader::new(&file);
        let mut got_data = false;

        loop {
            line_buf.clear();
            let n = reader
                .read_line(&mut line_buf)
                .map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                break;
            }
            got_data = true;
            let line = line_buf.trim();
            if line.is_empty() {
                continue;
            }

            let v: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let kind = v["kind"].as_str().unwrap_or("");
            if first_line {
                first_line = false;
                if kind == "header" {
                    let user = v["user"].as_str().unwrap_or("?");
                    let host = v["host"].as_str().unwrap_or("?");
                    let sid = v["session_id"].as_str().unwrap_or("?");
                    eprintln!("Recording: {sid} user={user} host={host}");
                    if let (Some(c), Some(r)) = (v["cols"].as_u64(), v["rows"].as_u64()) {
                        eprintln!("Terminal: {c}x{r}");
                    }
                    continue;
                }
            }

            match kind {
                "out" => {
                    let t = v["t"].as_f64().unwrap_or(0.0);
                    let delay = (t - prev_time) / speed;
                    if delay > 0.0 && delay < 30.0 {
                        std::thread::sleep(Duration::from_secs_f64(delay));
                    }
                    prev_time = t;
                    if let Some(b64) = v["b"].as_str()
                        && let Ok(bytes) = base64_decode(b64)
                    {
                        let _ = out.write_all(&bytes);
                        let _ = out.flush();
                    }
                }
                "chunk" | "resize" | "in" | "end" | "rotate" | "header" => {
                    // Non-displayable metadata records.
                }
                _ => {}
            }
        }

        let pos = reader.stream_position().unwrap_or(0);
        drop(reader);
        file.seek(io::SeekFrom::Start(pos))
            .map_err(|e| format!("seek: {e}"))?;

        if !follow {
            break;
        }
        if !got_data {
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    Ok(())
}

fn play_asciicast_v2(mut file: std::fs::File, speed: f64, follow: bool) -> Result<(), String> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut prev_time: f64 = 0.0;
    let mut first_line = true;
    let mut line_buf = String::new();

    loop {
        let mut reader = io::BufReader::new(&file);
        let mut got_data = false;

        loop {
            line_buf.clear();
            let n = reader
                .read_line(&mut line_buf)
                .map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                break;
            }
            got_data = true;
            let line = line_buf.trim();
            if line.is_empty() {
                continue;
            }

            let v: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };

            if first_line {
                first_line = false;
                if v.is_object() && v.get("version").is_some() {
                    if let Some(meta) = v.get("epitropos") {
                        let host = meta.get("host").and_then(|h| h.as_str()).unwrap_or("?");
                        let rec = meta.get("rec").and_then(|r| r.as_str()).unwrap_or("?");
                        eprintln!("Recording: {rec} on {host}");
                    }
                    if let (Some(w), Some(h)) = (v.get("width"), v.get("height")) {
                        eprintln!("Terminal: {}x{}", w, h);
                    }
                    continue;
                }
            }

            let arr = match v.as_array() {
                Some(a) if a.len() >= 3 => a,
                _ => continue,
            };
            let elapsed = arr[0].as_f64().unwrap_or(0.0);
            let event_type = arr[1].as_str().unwrap_or("");
            let data = arr[2].as_str().unwrap_or("");
            let delay = (elapsed - prev_time) / speed;
            if delay > 0.0 && delay < 30.0 {
                std::thread::sleep(Duration::from_secs_f64(delay));
            }
            prev_time = elapsed;
            if event_type == "o" {
                let _ = out.write_all(data.as_bytes());
                let _ = out.flush();
            }
        }

        let pos = reader.stream_position().unwrap_or(0);
        drop(reader);
        file.seek(io::SeekFrom::Start(pos))
            .map_err(|e| format!("seek: {e}"))?;

        if !follow {
            break;
        }
        if !got_data {
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    Ok(())
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Result<u8, String> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("invalid base64 char: {c}")),
        }
    }
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err("base64 length not multiple of 4".to_string());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().filter(|&&b| b == b'=').count();
        let v0 = val(chunk[0])?;
        let v1 = val(chunk[1])?;
        let v2 = if pad < 2 { val(chunk[2])? } else { 0 };
        let v3 = if pad < 1 { val(chunk[3])? } else { 0 };
        out.push((v0 << 2) | (v1 >> 4));
        if pad < 2 {
            out.push((v1 << 4) | (v2 >> 2));
        }
        if pad < 1 {
            out.push((v2 << 6) | v3);
        }
    }
    Ok(out)
}
