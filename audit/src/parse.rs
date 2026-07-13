//! Parse Linux kernel audit records into privilege events. Handles the common
//! privilege-escalation shapes: a SYSCALL(+EXECVE) exec of sudo/su/doas, and a
//! USER_AUTH/USER_ACCT PAM record (captures denied attempts). Field scanner
//! understands `k=v`, `k="v"`, and nested `msg='… k="v" …'`.
//!
//! This produces raw `AuditEvent`s with numeric uids + absolute timestamps;
//! correlate.rs resolves uids to names, filters by session, and rebases time.

use std::collections::HashMap;

/// One privilege-relevant kernel audit event (pre-correlation).
#[derive(Debug, Clone, PartialEq)]
pub struct AuditEvent {
    pub ts: f64,
    pub ses: Option<u32>,
    /// sudo | su | doas
    pub kind: String,
    pub auid: Option<u32>,
    pub euid: Option<u32>,
    pub tty: String,
    /// full command (from EXECVE args) if captured, else the exe path.
    pub command: String,
    /// success | denied
    pub result: String,
    /// target account name from a PAM record (e.g. "root"), if any.
    pub acct: String,
}

struct Line {
    rtype: String,
    event_id: String,
    ts: f64,
    fields: HashMap<String, String>,
}

/// Parse one audit record line: its `type=`, `audit(TS:SERIAL)` id, and fields.
fn parse_line(line: &str) -> Option<Line> {
    let mut fields = HashMap::new();
    scan_fields(line, &mut fields);
    let rtype = fields.get("type")?.clone();
    let (event_id, ts) = parse_event_id(line)?;
    Some(Line { rtype, event_id, ts, fields })
}

/// Extract `audit(1712500007.100:500)` → ("1712500007.100:500", 1712500007.1).
fn parse_event_id(line: &str) -> Option<(String, f64)> {
    let start = line.find("audit(")? + "audit(".len();
    let rest = &line[start..];
    let end = rest.find(')')?;
    let id = &rest[..end]; // "TS:SERIAL"
    let ts: f64 = id.split(':').next()?.parse().ok()?;
    Some((id.to_string(), ts))
}

/// Scan `key=value` pairs. Values may be `"quoted"`, `'quoted'` (recursed into,
/// for nested PAM msg), or bare. Outer keys win over nested duplicates.
fn scan_fields(s: &str, out: &mut HashMap<String, String>) {
    let b = s.as_bytes();
    let n = b.len();
    let mut i = 0;
    while i < n {
        if !(b[i].is_ascii_alphanumeric() || b[i] == b'_') {
            i += 1;
            continue;
        }
        let ks = i;
        while i < n && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
            i += 1;
        }
        if i >= n || b[i] != b'=' {
            continue;
        }
        let key = s[ks..i].to_string();
        i += 1;
        if i >= n {
            break;
        }
        let value = if b[i] == b'"' {
            i += 1;
            let vs = i;
            while i < n && b[i] != b'"' {
                i += 1;
            }
            let v = s[vs..i].to_string();
            if i < n {
                i += 1;
            }
            v
        } else if b[i] == b'\'' {
            i += 1;
            let vs = i;
            while i < n && b[i] != b'\'' {
                i += 1;
            }
            let inner = &s[vs..i];
            if i < n {
                i += 1;
            }
            scan_fields(inner, out); // nested PAM msg fields (acct, res, …)
            inner.to_string()
        } else {
            let vs = i;
            while i < n && !b[i].is_ascii_whitespace() {
                i += 1;
            }
            s[vs..i].to_string()
        };
        out.entry(key).or_insert(value);
    }
}

fn tool_of(comm: Option<&String>, exe: Option<&String>) -> Option<&'static str> {
    let name = comm
        .map(|s| s.as_str())
        .or_else(|| exe.map(|s| s.rsplit('/').next().unwrap_or(s.as_str())))?;
    match name {
        "sudo" => Some("sudo"),
        "su" => Some("su"),
        "doas" => Some("doas"),
        _ => None,
    }
}

fn execve_command(fields: &HashMap<String, String>) -> Option<String> {
    let argc: usize = fields.get("argc")?.parse().ok()?;
    let mut parts = Vec::new();
    for i in 0..argc {
        if let Some(a) = fields.get(&format!("a{i}")) {
            parts.push(a.clone());
        }
    }
    (!parts.is_empty()).then(|| parts.join(" "))
}

/// Parse an audit log slice into privilege events, grouping records by their
/// `audit(TS:SERIAL)` id (a SYSCALL and its EXECVE share the id).
pub fn parse(text: &str) -> Vec<AuditEvent> {
    // group lines by event id, merging fields
    let mut groups: Vec<(String, Vec<Line>)> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for raw in text.lines() {
        let Some(line) = parse_line(raw) else { continue };
        match index.get(&line.event_id) {
            Some(&idx) => groups[idx].1.push(line),
            None => {
                index.insert(line.event_id.clone(), groups.len());
                groups.push((line.event_id.clone(), vec![line]));
            }
        }
    }

    let mut out = Vec::new();
    for (_, lines) in groups {
        // merge all fields; collect the set of record types. The decoded command
        // MUST come from the EXECVE record's own a0..aN: the SYSCALL record for
        // the same event also carries a0/a1/a2, but those are raw register values
        // (pointers), so a merged map would let them shadow the real argv.
        let mut fields: HashMap<String, String> = HashMap::new();
        let mut types = Vec::new();
        let mut ts = 0.0;
        let mut execve_command_str: Option<String> = None;
        for l in &lines {
            ts = l.ts;
            types.push(l.rtype.clone());
            if l.rtype == "EXECVE" {
                execve_command_str = execve_command(&l.fields);
            }
            for (k, v) in &l.fields {
                fields.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
        let Some(kind) = tool_of(fields.get("comm"), fields.get("exe")) else {
            continue;
        };
        let has_syscall = types.iter().any(|t| t == "SYSCALL");

        let result = if has_syscall {
            if fields.get("success").map(String::as_str) == Some("yes") { "success" } else { "denied" }
        } else if fields.get("res").map(String::as_str) == Some("success") {
            "success"
        } else {
            "denied"
        };

        // Emit successful execs (they carry the command + euid transition), and
        // denied PAM attempts (no exec happens). Skip successful USER_AUTH that
        // duplicates a SYSCALL exec.
        if !has_syscall && result == "success" {
            continue;
        }

        let command = execve_command_str
            .or_else(|| fields.get("exe").cloned())
            .unwrap_or_default();

        out.push(AuditEvent {
            ts,
            ses: fields.get("ses").and_then(|s| s.parse().ok()),
            kind: kind.to_string(),
            auid: fields.get("auid").and_then(|s| s.parse().ok()),
            euid: fields.get("euid").and_then(|s| s.parse().ok()),
            tty: normalize_tty(fields.get("tty").or_else(|| fields.get("terminal"))),
            command,
            result: result.to_string(),
            acct: fields.get("acct").cloned().unwrap_or_default(),
        });
    }
    out.sort_by(|a, b| a.ts.partial_cmp(&b.ts).unwrap_or(std::cmp::Ordering::Equal));
    out
}

fn normalize_tty(tty: Option<&String>) -> String {
    match tty {
        None => String::new(),
        Some(t) => {
            // auditd writes "pts0"; normalize to "pts/0"
            if let Some(rest) = t.strip_prefix("pts") {
                if rest.chars().all(|c| c.is_ascii_digit()) && !rest.is_empty() {
                    return format!("pts/{rest}");
                }
            }
            t.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = r#"type=USER_AUTH msg=audit(1712500007.050:499): pid=2000 uid=1000 auid=1000 ses=42 msg='op=PAM:authentication grantors=pam_unix acct="root" exe="/usr/bin/su" terminal=pts/0 res=success'
type=SYSCALL msg=audit(1712500007.100:500): arch=c000003e syscall=59 success=yes exit=0 auid=1000 uid=1000 euid=0 ses=42 comm="su" exe="/usr/bin/su" tty=pts0 key=(null)
type=EXECVE msg=audit(1712500007.100:500): argc=2 a0="su" a1="-"
type=USER_AUTH msg=audit(1712500009.000:510): pid=2100 uid=1000 auid=1000 ses=42 msg='op=PAM:authentication acct="root" exe="/usr/bin/sudo" terminal=pts/0 res=failed'
"#;

    #[test]
    fn parses_su_exec_with_command() {
        let events = parse(LOG);
        let su = events.iter().find(|e| e.kind == "su" && e.result == "success").expect("su exec");
        assert_eq!(su.command, "su -");
        assert_eq!(su.euid, Some(0));
        assert_eq!(su.auid, Some(1000));
        assert_eq!(su.ses, Some(42));
        assert_eq!(su.tty, "pts/0");
        // the exec event carries euid (→ target user), not a PAM acct
        assert_eq!(su.acct, "");
    }

    // Real SYSCALL records for execve carry a0/a1/a2 as raw register pointers.
    // The decoded command must come from the EXECVE record, not those pointers.
    #[test]
    fn command_from_execve_not_syscall_pointers() {
        let log = concat!(
            "type=SYSCALL msg=audit(1712500100.100:600): arch=c000003e syscall=59 success=yes ",
            "exit=0 a0=562e899fb0d0 a1=562e899fda80 a2=562e899ff600 auid=1000 uid=1000 euid=0 ",
            "ses=42 comm=\"sudo\" exe=\"/run/wrappers/bin/sudo\" tty=pts0 key=\"epitropos_privesc\"\n",
            "type=EXECVE msg=audit(1712500100.100:600): argc=3 a0=\"sudo\" a1=\"-n\" a2=\"id\"\n",
        );
        let events = parse(log);
        let sudo = events.iter().find(|e| e.kind == "sudo").expect("sudo exec");
        assert_eq!(sudo.command, "sudo -n id");
        assert_eq!(sudo.euid, Some(0));
    }

    #[test]
    fn captures_denied_sudo_attempt() {
        let events = parse(LOG);
        let denied = events.iter().find(|e| e.kind == "sudo").expect("denied sudo");
        assert_eq!(denied.result, "denied");
        assert_eq!(denied.acct, "root");
    }

    #[test]
    fn drops_successful_user_auth_dupe() {
        // the successful su USER_AUTH (499) must be dropped in favour of the SYSCALL exec
        let events = parse(LOG);
        let su_events: Vec<_> = events.iter().filter(|e| e.kind == "su").collect();
        assert_eq!(su_events.len(), 1, "only the SYSCALL su exec, not the USER_AUTH dupe");
    }

    #[test]
    fn nested_pam_msg_fields_parsed() {
        let mut f = HashMap::new();
        scan_fields(
            r#"pid=2000 uid=1000 msg='op=PAM acct="root" res=success'"#,
            &mut f,
        );
        assert_eq!(f.get("acct").unwrap(), "root");
        assert_eq!(f.get("res").unwrap(), "success");
        assert_eq!(f.get("uid").unwrap(), "1000");
    }
}
