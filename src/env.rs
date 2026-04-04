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
        || key == "EPITROPOS_SESSION_ID"
}

pub fn build_shell_env(session_id: &str) -> Vec<(String, String)> {
    let exact = [
        "HOME", "USER", "LOGNAME", "SHELL", "TERM", "LANG", "LANGUAGE", "LC_ALL", "PATH",
        "DISPLAY", "TZ",
    ];
    let prefixes = ["SSH_", "XDG_", "LC_"];

    let mut env = Vec::new();
    for (key, value) in std::env::vars() {
        if exact.contains(&key.as_str()) || prefixes.iter().any(|p| key.starts_with(p)) {
            env.push((key, value));
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
        let env = build_shell_env("sid-1");
        let map: std::collections::HashMap<_, _> = env.into_iter().collect();
        assert!(map.contains_key("HOME"));
        assert!(map.contains_key("EPITROPOS_SESSION_ID"));
        assert!(!map.contains_key("EVIL"));
    }
}
