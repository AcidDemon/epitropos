//! Rule compilation + streaming matcher + per-(rule, session) cooldown.

#![allow(dead_code)]

use regex::Regex;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::error::SentinelError;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDef {
    pub id: String,
    pub severity: String,
    pub category: String,
    pub description: String,
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesFile {
    rules: Vec<RuleDef>,
}

#[derive(Debug)]
pub struct CompiledRule {
    pub def: RuleDef,
    pub regexes: Vec<Regex>,
}

#[derive(Debug)]
pub struct RuleSet {
    pub rules: Vec<CompiledRule>,
    pub source_sha256: String,
}

impl RuleSet {
    pub fn load(path: &Path) -> Result<Self, SentinelError> {
        let bytes = fs::read(path)
            .map_err(|e| SentinelError::Rules(format!("read {}: {e}", path.display())))?;
        let mut h = Sha256::new();
        h.update(&bytes);
        let source_sha256 = hex::encode(h.finalize());

        let s = std::str::from_utf8(&bytes)
            .map_err(|e| SentinelError::Rules(format!("utf8: {e}")))?;
        let parsed: RulesFile =
            toml::from_str(s).map_err(|e| SentinelError::Rules(format!("parse: {e}")))?;

        let mut compiled = Vec::with_capacity(parsed.rules.len());
        for def in parsed.rules {
            let mut regexes = Vec::with_capacity(def.patterns.len());
            for pat in &def.patterns {
                let rx = Regex::new(pat).map_err(|e| {
                    SentinelError::Rules(format!("rule {}: pattern {:?}: {e}", def.id, pat))
                })?;
                regexes.push(rx);
            }
            compiled.push(CompiledRule { def, regexes });
        }
        Ok(RuleSet {
            rules: compiled,
            source_sha256,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Match {
    pub rule_id: String,
    pub severity: String,
    pub category: String,
    pub description: String,
    pub matched_text: String,
    pub context: String,
    pub session_time: f64,
}

/// Per-session matcher with cooldown. One instance per session.
pub struct SessionMatcher<'a> {
    rules: &'a RuleSet,
    cooldown: Duration,
    last_fired: HashMap<String, Instant>,
    before_chars: usize,
    after_chars: usize,
    rolling_buffer: String,
    max_buffer_bytes: usize,
}

impl<'a> SessionMatcher<'a> {
    pub fn new(
        rules: &'a RuleSet,
        cooldown_secs: u64,
        before_chars: usize,
        after_chars: usize,
    ) -> Self {
        Self {
            rules,
            cooldown: Duration::from_secs(cooldown_secs),
            last_fired: HashMap::new(),
            before_chars,
            after_chars,
            rolling_buffer: String::new(),
            max_buffer_bytes: before_chars.max(4096),
        }
    }

    /// Feed one decoded `out`/`in` record's text. Returns matches that fired.
    pub fn feed(&mut self, t: f64, text: &str) -> Vec<Match> {
        let mut out = Vec::new();
        let now = Instant::now();

        let combined = {
            let mut c = String::with_capacity(self.rolling_buffer.len() + text.len());
            c.push_str(&self.rolling_buffer);
            c.push_str(text);
            c
        };

        for rule in &self.rules.rules {
            if let Some(last) = self.last_fired.get(&rule.def.id)
                && now.duration_since(*last) < self.cooldown
            {
                continue;
            }

            for rx in &rule.regexes {
                if let Some(m) = rx.find(&combined) {
                    let match_start = m.start();
                    let match_end = m.end();
                    let context_start = match_start.saturating_sub(self.before_chars);
                    let context_end = (match_end + self.after_chars).min(combined.len());
                    let context_start = find_char_boundary(&combined, context_start);
                    let context_end = find_char_boundary(&combined, context_end);
                    let matched_text = combined[match_start..match_end].to_string();
                    let context = combined[context_start..context_end].to_string();

                    out.push(Match {
                        rule_id: rule.def.id.clone(),
                        severity: rule.def.severity.clone(),
                        category: rule.def.category.clone(),
                        description: rule.def.description.clone(),
                        matched_text,
                        context,
                        session_time: t,
                    });
                    self.last_fired.insert(rule.def.id.clone(), now);
                    break;
                }
            }
        }

        self.rolling_buffer.push_str(text);
        if self.rolling_buffer.len() > self.max_buffer_bytes {
            let drop_to = self.rolling_buffer.len() - self.max_buffer_bytes;
            let boundary = find_char_boundary(&self.rolling_buffer, drop_to);
            self.rolling_buffer.drain(..boundary);
        }

        out
    }
}

fn find_char_boundary(s: &str, idx: usize) -> usize {
    let mut i = idx.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_rules(contents: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "{}", contents).unwrap();
        f
    }

    #[test]
    fn compiles_valid_rules() {
        let f = write_rules(
            r#"
[[rules]]
id = "test"
severity = "high"
category = "test"
description = "Test"
patterns = ["\\bsudo\\s+"]
"#,
        );
        let rs = RuleSet::load(f.path()).unwrap();
        assert_eq!(rs.rules.len(), 1);
        assert_eq!(rs.rules[0].def.id, "test");
        assert_eq!(rs.source_sha256.len(), 64);
    }

    #[test]
    fn rejects_invalid_regex() {
        let f = write_rules(
            r#"
[[rules]]
id = "bad"
severity = "low"
category = "test"
description = "Bad"
patterns = ["(unclosed"]
"#,
        );
        let err = RuleSet::load(f.path()).unwrap_err();
        match err {
            SentinelError::Rules(msg) => {
                assert!(msg.contains("bad"));
            }
            _ => panic!("wrong error variant"),
        }
    }

    #[test]
    fn matcher_fires_on_pattern() {
        let f = write_rules(
            r#"
[[rules]]
id = "sudo"
severity = "high"
category = "priv"
description = "sudo"
patterns = ["\\bsudo\\s+"]
"#,
        );
        let rs = RuleSet::load(f.path()).unwrap();
        let mut m = SessionMatcher::new(&rs, 30, 100, 100);
        let hits = m.feed(1.0, "alice@host:~$ sudo ls\n");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "sudo");
        assert!(hits[0].matched_text.contains("sudo"));
    }

    #[test]
    fn matcher_cooldown_suppresses_duplicates() {
        let f = write_rules(
            r#"
[[rules]]
id = "sudo"
severity = "high"
category = "priv"
description = "sudo"
patterns = ["\\bsudo\\s+"]
"#,
        );
        let rs = RuleSet::load(f.path()).unwrap();
        let mut m = SessionMatcher::new(&rs, 3600, 100, 100);
        let hit1 = m.feed(1.0, "sudo ls\n");
        let hit2 = m.feed(2.0, "sudo ls\n");
        assert_eq!(hit1.len(), 1);
        assert_eq!(hit2.len(), 0);
    }

    #[test]
    fn near_miss_does_not_fire() {
        let f = write_rules(
            r#"
[[rules]]
id = "sudo"
severity = "high"
category = "priv"
description = "sudo"
patterns = ["\\bsudo\\s+"]
"#,
        );
        let rs = RuleSet::load(f.path()).unwrap();
        let mut m = SessionMatcher::new(&rs, 30, 100, 100);
        let hits = m.feed(1.0, "sudoku puzzle\n");
        assert_eq!(hits.len(), 0);
    }

    #[test]
    fn context_includes_surrounding_text() {
        let f = write_rules(
            r#"
[[rules]]
id = "sudo"
severity = "high"
category = "priv"
description = "sudo"
patterns = ["\\bsudo\\s+"]
"#,
        );
        let rs = RuleSet::load(f.path()).unwrap();
        let mut m = SessionMatcher::new(&rs, 30, 50, 50);
        let hits = m.feed(1.0, "prompt:~$ sudo -u root whoami\nroot\n");
        assert_eq!(hits.len(), 1);
        assert!(hits[0].context.contains("sudo"));
    }
}
