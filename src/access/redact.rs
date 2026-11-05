//! Personal-data redaction for results a person sees redacted.
//!
//! Separate from `policy::scrub`, which removes known secret VALUES from
//! every output for everyone. This removes personal-data SHAPES (emails,
//! phone numbers, account numbers) from redacted classes, so error
//! messages, stack traces, counts and timestamps survive.

use regex::Regex;

use super::config::AccessCfg;

struct Rule {
    name: String,
    re: Regex,
    /// Empty: every redacted class.
    classes: Vec<String>,
    /// Extra check on a match (Luhn for card numbers).
    check: Option<fn(&str) -> bool>,
}

pub struct Redactor {
    rules: Vec<Rule>,
}

type BuiltIn = (&'static str, &'static str, Option<fn(&str) -> bool>);

/// Name, pattern, extra check. Order matters: longer shapes first.
const BUILT_IN: &[BuiltIn] = &[
    ("jwt", r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", None),
    ("bearer", r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}", None),
    ("email", r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", None),
    ("iban", r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b", Some(iban_ok)),
    ("card", r"\b(?:\d[ -]?){12,18}\d\b", Some(luhn_ok)),
    ("phone", r"\+\d{1,3}[ -]?\(?\d{1,4}\)?(?:[ -]?\d){6,11}\b", None),
    ("uk_phone", r"\b0\d{2,4}[ -]\d{3,4}[ -]?\d{3,4}\b", None),
    ("uk_nino", r"\b[A-CEGHJ-PR-TW-Z]{2} ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b", None),
    ("us_ssn", r"\b\d{3}-\d{2}-\d{4}\b", None),
];

impl Redactor {
    pub fn new(cfg: &AccessCfg) -> crate::Result<Self> {
        let mut rules = Vec::new();
        for (name, pattern, check) in BUILT_IN {
            if cfg.disable_builtin_redaction.iter().any(|d| d == name) {
                continue;
            }
            rules.push(Rule {
                name: name.to_string(),
                re: Regex::new(pattern).expect("built-in pattern compiles"),
                classes: Vec::new(),
                check: *check,
            });
        }
        for r in &cfg.redact {
            let re = Regex::new(&r.pattern).map_err(|e| {
                crate::Error::Config(format!("access.redact {:?}: bad pattern: {e}", r.name))
            })?;
            rules.push(Rule { name: r.name.clone(), re, classes: r.classes.clone(), check: None });
        }
        Ok(Redactor { rules })
    }

    pub fn builtin_names() -> impl Iterator<Item = &'static str> {
        BUILT_IN.iter().map(|(n, _, _)| *n)
    }

    /// Replace every match with `<redacted:name>`.
    pub fn redact(&self, class: &str, text: &str) -> String {
        let mut out = text.to_string();
        for rule in &self.rules {
            if !rule.classes.is_empty() && !rule.classes.iter().any(|c| c == class) {
                continue;
            }
            let label = format!("<redacted:{}>", rule.name);
            out = rule
                .re
                .replace_all(&out, |caps: &regex::Captures<'_>| {
                    let m = &caps[0];
                    match rule.check {
                        Some(ok) if !ok(m) => m.to_string(),
                        _ => label.clone(),
                    }
                })
                .into_owned();
        }
        out
    }
}

fn digits(s: &str) -> Vec<u32> {
    s.chars().filter_map(|c| c.to_digit(10)).collect()
}

fn luhn_ok(s: &str) -> bool {
    let d = digits(s);
    if !(13..=19).contains(&d.len()) {
        return false;
    }
    let sum: u32 = d
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &n)| {
            if i % 2 == 1 {
                let x = n * 2;
                if x > 9 { x - 9 } else { x }
            } else {
                n
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// ISO 13616 mod-97 check, so upper-case ids don't get redacted.
fn iban_ok(s: &str) -> bool {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() < 15 {
        return false;
    }
    let (head, tail) = compact.split_at(4);
    let mut rem: u64 = 0;
    for c in tail.chars().chain(head.chars()) {
        let v = match c.to_digit(36) {
            Some(v) => v as u64,
            None => return false,
        };
        rem = if v >= 10 { (rem * 100 + v) % 97 } else { (rem * 10 + v) % 97 };
    }
    rem == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::config::RedactCfg;

    fn r() -> Redactor {
        Redactor::new(&AccessCfg::default()).unwrap()
    }

    #[test]
    fn personal_data_is_redacted_and_diagnostics_survive() {
        let line = "2026-11-04T10:00:00Z ERROR payment failed for jane.doe@example.com \
                    iban GB82 WEST 1234 5698 7654 32 card 4111 1111 1111 1111 \
                    tel +44 7700 900123 ni AB 12 34 56 C after 1500ms (order 123456789)";
        let out = r().redact("logs", line);
        assert!(out.contains("<redacted:email>"), "{out}");
        assert!(out.contains("<redacted:iban>"), "{out}");
        assert!(out.contains("<redacted:card>"), "{out}");
        assert!(out.contains("<redacted:phone>"), "{out}");
        assert!(out.contains("<redacted:uk_nino>"), "{out}");
        assert!(out.contains("2026-11-04T10:00:00Z ERROR payment failed"), "{out}");
        assert!(out.contains("1500ms (order 123456789)"), "{out}");
        assert!(!out.contains("jane.doe"), "{out}");
    }

    #[test]
    fn checks_avoid_false_positives() {
        let out = r().redact("logs", "build 4111111111111112 id ABCD12345678901234");
        assert!(!out.contains("redacted"), "{out}");
    }

    #[test]
    fn custom_rules_and_disabling() {
        let cfg = AccessCfg {
            redact: vec![RedactCfg {
                name: "employee_id".into(),
                pattern: r"\bEMP-\d{6}\b".into(),
                classes: vec!["logs".into()],
            }],
            disable_builtin_redaction: vec!["email".into()],
            ..Default::default()
        };
        let r = Redactor::new(&cfg).unwrap();
        assert_eq!(r.redact("logs", "EMP-123456 a@b.com"), "<redacted:employee_id> a@b.com");
        assert_eq!(r.redact("messages", "EMP-123456"), "EMP-123456");
    }
}
