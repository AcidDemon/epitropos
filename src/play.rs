use std::io::{self, BufRead, Seek, Write};
use std::time::Duration;

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

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-s" | "--speed" if i + 1 < args.len() => {
                i += 1;
                speed = args[i].parse().unwrap_or(1.0);
            }
            "-f" | "--follow" => follow = true,
            "-h" | "--help" => {
                eprintln!("Usage: epitropos-play [OPTIONS] <FILE>");
                eprintln!();
                eprintln!("  -s, --speed <N>   Playback speed multiplier (default: 1.0)");
                eprintln!("  -f, --follow      Wait for new data (live session)");
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

    if let Err(e) = play(&path, speed, follow) {
        eprintln!("epitropos-play: {e}");
        std::process::exit(1);
    }
}

fn play(path: &str, speed: f64, follow: bool) -> Result<(), String> {
    let mut file = std::fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?;
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

        // Save position so we can resume after the BufReader is dropped.
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
