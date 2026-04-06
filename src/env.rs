/// Capture vars the child shell needs before sanitize() strips them.
/// Must be called before sanitize().
pub fn stash_shell_vars() -> std::collections::HashMap<std::ffi::OsString, std::ffi::OsString> {
    let exact = ["DISPLAY", "LANGUAGE", "LC_ALL"];
    let prefixes = ["XDG_"];

    std::env::vars_os()
        .filter(|(k, _)| {
            let s = k.to_str().unwrap_or("");
            exact.contains(&s) || prefixes.iter().any(|p| s.starts_with(p))
        })
        .collect()
}

pub fn sanitize() {
    let saved: Vec<(String, String)> = std::env::vars()
        .filter(|(k, _)| is_safe_for_proxy(k))
        .collect();

    // Nuke everything
    for (k, _) in std::env::vars_os() {
        unsafe { std::env::remove_var(&k) };
    }

    // Restore only the allowlisted vars
    for (k, v) in saved {
        unsafe { std::env::set_var(&k, &v) };
    }
}

fn is_safe_for_proxy(key: &str) -> bool {
    matches!(
        key,
        "HOME" | "USER" | "LOGNAME" | "SHELL" | "TERM" | "PATH" | "LANG" | "TZ"
    ) || key.starts_with("SSH_")
        || key.starts_with("LC_")
}

pub fn build_shell_env(
    session_id: &str,
    stashed: &std::collections::HashMap<std::ffi::OsString, std::ffi::OsString>,
) -> Vec<(String, String)> {
    let exact = [
        "HOME", "USER", "LOGNAME", "SHELL", "TERM", "LANG", "LANGUAGE", "LC_ALL", "PATH",
        "DISPLAY", "TZ",
    ];
    let prefixes = ["SSH_", "XDG_", "LC_"];

    let mut env = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (key, value) in std::env::vars() {
        if exact.contains(&key.as_str()) || prefixes.iter().any(|p| key.starts_with(p)) {
            seen.insert(key.clone());
            env.push((key, value));
        }
    }
    // Re-inject vars that were stripped by sanitize()
    for (k, v) in stashed {
        if let (Some(ks), Some(vs)) = (k.to_str(), v.to_str())
            && !seen.contains(ks)
            && (exact.contains(&ks) || prefixes.iter().any(|p| ks.starts_with(p)))
        {
            env.push((ks.to_string(), vs.to_string()));
        }
    }
    env.push(("EPITROPOS_SESSION_ID".to_string(), session_id.to_string()));
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_removes_dangerous_vars() {
        unsafe {
            std::env::set_var("LD_PRELOAD", "/evil.so");
            std::env::set_var("GCONV_PATH", "/evil");
            std::env::set_var("TERM", "xterm");
        }
        sanitize();
        assert!(std::env::var("LD_PRELOAD").is_err());
        assert!(std::env::var("GCONV_PATH").is_err());
        assert_eq!(std::env::var("TERM").unwrap(), "xterm");
    }

    #[test]
    fn shell_env_includes_whitelist() {
        unsafe {
            std::env::set_var("HOME", "/home/test");
            std::env::set_var("EVIL", "nope");
        }
        let stashed = std::collections::HashMap::new();
        let env = build_shell_env("sid-1", &stashed);
        let map: std::collections::HashMap<_, _> = env.into_iter().collect();
        assert!(map.contains_key("HOME"));
        assert!(map.contains_key("EPITROPOS_SESSION_ID"));
        assert!(!map.contains_key("EVIL"));
    }
}
