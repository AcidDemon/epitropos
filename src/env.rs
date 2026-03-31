/// Removes dangerous environment variables that could be used for privilege escalation
/// or process manipulation (LD_* loader hooks, Rust runtime flags, etc.).
pub fn sanitize() {
    let dangerous_vars = [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "LD_DEBUG",
        "LD_PROFILE",
        "LD_SHOW_AUXV",
        "LD_DYNAMIC_WEAK",
        "RUST_BACKTRACE",
        "RUST_LOG",
    ];

    for key in &dangerous_vars {
        unsafe {
            std::env::remove_var(key);
        }
    }
}

/// Builds a filtered environment for the user's shell session.
///
/// Only passes through whitelisted environment variables to prevent information leakage
/// and ensure a predictable shell environment. Always injects EPITROPOS_SESSION_ID.
///
/// Whitelisted variables:
/// - Exact matches: HOME, USER, SHELL, TERM, LANG, LANGUAGE, LC_ALL, PATH, DISPLAY, TZ
/// - Prefix matches: SSH_*, XDG_*, LC_*
/// - Always added: EPITROPOS_SESSION_ID
pub fn build_shell_env(session_id: &str) -> Vec<(String, String)> {
    let exact_matches = [
        "HOME", "USER", "SHELL", "TERM", "LANG", "LANGUAGE", "LC_ALL", "PATH", "DISPLAY", "TZ",
    ];

    let prefixes = ["SSH_", "XDG_", "LC_"];

    let mut env = Vec::new();

    // Add whitelisted exact matches
    for key in &exact_matches {
        if let Ok(value) = std::env::var(key) {
            env.push((key.to_string(), value));
        }
    }

    // Add whitelisted prefix matches
    for (key, value) in std::env::vars() {
        for prefix in &prefixes {
            if key.starts_with(prefix) {
                // Avoid duplicates from exact matches that also have a prefix
                if !exact_matches.contains(&key.as_str()) {
                    env.push((key, value));
                }
                break;
            }
        }
    }

    // Always add session ID
    env.push(("EPITROPOS_SESSION_ID".to_string(), session_id.to_string()));

    env
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_removes_dangerous_vars() {
        // Set a dangerous variable
        unsafe {
            std::env::set_var("LD_PRELOAD", "/some/lib.so");
        }
        assert_eq!(
            std::env::var("LD_PRELOAD").ok(),
            Some("/some/lib.so".to_string())
        );

        // Call sanitize
        sanitize();

        // Verify it's gone
        assert!(std::env::var("LD_PRELOAD").is_err());
    }

    #[test]
    fn shell_env_includes_whitelist() {
        // Set whitelisted and non-whitelisted variables
        unsafe {
            std::env::set_var("HOME", "/home/testuser");
            std::env::set_var("TERM", "xterm-256color");
            std::env::set_var("SSH_CLIENT", "192.168.1.1 22 22");
            std::env::set_var("EVIL_VAR", "should_not_appear");
        }

        // Build shell environment
        let env = build_shell_env("test-session-123");

        // Convert to a map for easier testing
        let env_map: std::collections::HashMap<String, String> = env.into_iter().collect();

        // Verify whitelisted variables are present
        assert_eq!(
            env_map.get("HOME").map(|s| s.as_str()),
            Some("/home/testuser")
        );
        assert_eq!(
            env_map.get("TERM").map(|s| s.as_str()),
            Some("xterm-256color")
        );
        assert_eq!(
            env_map.get("SSH_CLIENT").map(|s| s.as_str()),
            Some("192.168.1.1 22 22")
        );

        // Verify EPITROPOS_SESSION_ID is always added
        assert_eq!(
            env_map.get("EPITROPOS_SESSION_ID").map(|s| s.as_str()),
            Some("test-session-123")
        );

        // Verify non-whitelisted variable is not present
        assert!(!env_map.contains_key("EVIL_VAR"));
    }
}
