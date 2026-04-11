//! Writer for the katagrapho-v1 stream format. Each record is a JSON
//! object on its own line. Record kinds: header, out, in, resize, chunk.

use serde_json::{Value, json};
use std::io::Write;

use crate::auth_meta::AuthMeta;

pub const FORMAT_VERSION: &str = "katagrapho-v1";

pub struct HeaderFields<'a> {
    pub session_id: &'a str,
    pub user: &'a str,
    pub host: &'a str,
    pub boot_id: &'a str,
    pub part: u32,
    pub prev_manifest_hash_link: Option<&'a str>,
    pub started_unix: f64,
    pub cols: u16,
    pub rows: u16,
    pub shell: &'a str,
    pub epitropos_version: &'a str,
    pub epitropos_commit: &'a str,
    pub katagrapho_version: &'a str,
    pub katagrapho_commit: &'a str,
    pub audit_session_id: Option<u32>,
    pub auth: &'a AuthMeta,
}

pub fn write_header<W: Write>(w: &mut W, h: &HeaderFields) -> std::io::Result<()> {
    let v = json!({
        "kind": "header",
        "v": FORMAT_VERSION,
        "session_id": h.session_id,
        "user": h.user,
        "host": h.host,
        "boot_id": h.boot_id,
        "part": h.part,
        "prev_manifest_hash_link": h.prev_manifest_hash_link,
        "started": h.started_unix,
        "cols": h.cols,
        "rows": h.rows,
        "shell": h.shell,
        "epitropos_version": h.epitropos_version,
        "epitropos_commit": h.epitropos_commit,
        "katagrapho_version": h.katagrapho_version,
        "katagrapho_commit": h.katagrapho_commit,
        "audit_session_id": h.audit_session_id,
        "ppid": h.auth.ppid,
        "ssh_client": h.auth.ssh_client,
        "ssh_connection": h.auth.ssh_connection,
        "ssh_original_command": h.auth.ssh_original_command,
        "parent_comm": h.auth.parent_comm,
        "parent_cmdline": h.auth.parent_cmdline,
        "pam_rhost": h.auth.pam_rhost,
        "pam_service": h.auth.pam_service,
    });
    write_value(w, &v)
}

pub fn write_out<W: Write>(w: &mut W, t: f64, data: &[u8]) -> std::io::Result<()> {
    let v = json!({
        "kind": "out",
        "t": t,
        "b": base64(data),
    });
    write_value(w, &v)
}

pub fn write_in<W: Write>(w: &mut W, t: f64, data: &[u8]) -> std::io::Result<()> {
    let v = json!({
        "kind": "in",
        "t": t,
        "b": base64(data),
    });
    write_value(w, &v)
}

pub fn write_resize<W: Write>(w: &mut W, t: f64, cols: u16, rows: u16) -> std::io::Result<()> {
    let v = json!({
        "kind": "resize",
        "t": t,
        "cols": cols,
        "rows": rows,
    });
    write_value(w, &v)
}

pub fn write_chunk<W: Write>(
    w: &mut W,
    seq: u64,
    bytes: u64,
    messages: u64,
    elapsed: f64,
    sha256_hex: &str,
) -> std::io::Result<()> {
    let v = json!({
        "kind": "chunk",
        "seq": seq,
        "bytes": bytes,
        "messages": messages,
        "elapsed": elapsed,
        "sha256": sha256_hex,
    });
    write_value(w, &v)
}

fn write_value<W: Write>(w: &mut W, v: &Value) -> std::io::Result<()> {
    let s = serde_json::to_string(v)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    w.write_all(s.as_bytes())?;
    w.write_all(b"\n")
}

fn base64(input: &[u8]) -> String {
    const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
        out.push(ALPH[(b0 >> 2) as usize] as char);
        out.push(ALPH[((b0 & 0x03) << 4 | b1 >> 4) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPH[((b1 & 0x0F) << 2 | b2 >> 6) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPH[(b2 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_out_emits_one_line_with_correct_kind() {
        let mut buf = Vec::new();
        write_out(&mut buf, 0.5, b"hi").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.ends_with('\n'));
        let v: Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(v["kind"], "out");
        assert_eq!(v["t"], 0.5);
        assert_eq!(v["b"], "aGk=");
    }

    #[test]
    fn write_chunk_round_trips() {
        let mut buf = Vec::new();
        write_chunk(&mut buf, 7, 1024, 42, 3.5, "deadbeef").unwrap();
        let v: Value = serde_json::from_str(std::str::from_utf8(&buf).unwrap().trim()).unwrap();
        assert_eq!(v["kind"], "chunk");
        assert_eq!(v["seq"], 7);
        assert_eq!(v["sha256"], "deadbeef");
    }

    #[test]
    fn write_header_includes_auth_meta_fields() {
        let auth = AuthMeta {
            ssh_client: Some("1.2.3.4 5 6".to_string()),
            ppid: 99,
            ..AuthMeta::default()
        };
        let h = HeaderFields {
            session_id: "s",
            user: "u",
            host: "h",
            boot_id: "b",
            part: 0,
            prev_manifest_hash_link: None,
            started_unix: 1.0,
            cols: 80,
            rows: 24,
            shell: "/bin/sh",
            epitropos_version: "0",
            epitropos_commit: "0",
            katagrapho_version: "0",
            katagrapho_commit: "0",
            audit_session_id: None,
            auth: &auth,
        };
        let mut buf = Vec::new();
        write_header(&mut buf, &h).unwrap();
        let v: Value = serde_json::from_str(std::str::from_utf8(&buf).unwrap().trim()).unwrap();
        assert_eq!(v["v"], FORMAT_VERSION);
        assert_eq!(v["ssh_client"], "1.2.3.4 5 6");
        assert_eq!(v["ppid"], 99);
        assert_eq!(v["pam_rhost"], Value::Null);
    }
}
