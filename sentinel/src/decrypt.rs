//! Streaming age decryption + kgv1 record iteration.

#![allow(dead_code)]

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::error::SentinelError;

pub struct KgvRecord {
    pub kind: String,
    pub t: f64,
    pub data: Option<String>,
    pub raw: serde_json::Value,
}

pub fn iterate_records<F>(
    path: &Path,
    identity_str: &str,
    mut f: F,
) -> Result<(), SentinelError>
where
    F: FnMut(&KgvRecord) -> Result<(), SentinelError>,
{
    let identity: age::x25519::Identity = identity_str
        .trim()
        .parse()
        .map_err(|e| SentinelError::Decrypt(format!("parse identity: {e}")))?;

    let file = File::open(path)
        .map_err(|e| SentinelError::Decrypt(format!("open {}: {e}", path.display())))?;

    let decryptor =
        age::Decryptor::new(file).map_err(|e| SentinelError::Decrypt(format!("age: {e}")))?;

    let reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| SentinelError::Decrypt(format!("decrypt: {e}")))?;

    let buf = BufReader::new(reader);
    for line in buf.lines() {
        let line = line.map_err(|e| SentinelError::Decrypt(format!("read: {e}")))?;
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let kind = v["kind"].as_str().unwrap_or("").to_string();
        let t = v["t"].as_f64().unwrap_or(0.0);
        let data = match kind.as_str() {
            "out" | "in" => v["b"]
                .as_str()
                .and_then(|b64| decode_base64(b64).ok())
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
            _ => None,
        };
        let rec = KgvRecord { kind, t, data, raw: v };
        f(&rec)?;
    }
    Ok(())
}

fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
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
        return Err("base64 len not multiple of 4".into());
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
