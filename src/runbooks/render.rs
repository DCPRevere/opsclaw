//! Placeholder substitution: turn a step's `{placeholder}` command template
//! into the literal command that would run. A missing placeholder is always
//! a named error — never a silent blank, since a blank could turn
//! `kubectl delete pod {pod}` into `kubectl delete pod ` (all pods).

use std::collections::BTreeMap;

use crate::domain::FqTarget;
use crate::error::{Error, Result};

use super::steps::Step;

/// Build the substitution map for one run: CLI `--var k=v` overrides >
/// `default_vars` from front matter > auto-provided vars derived from the
/// target. Auto vars are inserted first so explicit vars/defaults can
/// override `target`/`namespace` if an author really wants to.
pub fn build_vars(
    target: Option<&FqTarget>,
    default_vars: &BTreeMap<String, String>,
    cli_vars: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut vars = BTreeMap::new();
    if let Some(t) = target {
        vars.insert("target".to_string(), t.target.clone());
        vars.insert("namespace".to_string(), t.env.clone());
    }
    for (k, v) in default_vars {
        vars.insert(k.clone(), v.clone());
    }
    for (k, v) in cli_vars {
        vars.insert(k.clone(), v.clone());
    }
    vars
}

/// Substitute every `{name}` in `command` from `vars`. Errors on the first
/// placeholder with no entry in `vars`, naming it exactly so the caller knows
/// what `--var` to add.
pub fn render(command: &str, vars: &BTreeMap<String, String>) -> Result<String> {
    let mut out = String::with_capacity(command.len());
    let bytes = command.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{'
            && let Some(close) = command[i..].find('}')
        {
            let name = &command[i + 1..i + close];
            let is_ident = !name.is_empty()
                && name.chars().next().is_some_and(|c| c.is_alphabetic() || c == '_')
                && name.chars().all(|c| c.is_alphanumeric() || c == '_');
            if is_ident {
                match vars.get(name) {
                    Some(v) => {
                        out.push_str(v);
                        i += close + 1;
                        continue;
                    }
                    None => {
                        return Err(Error::Config(format!(
                            "missing value for placeholder {{{name}}} — pass --var {name}=<value>"
                        )));
                    }
                }
            }
        }
        // Not a recognized placeholder start (or unmatched `{`): copy one
        // char through unchanged.
        let ch = command[i..].chars().next().expect("i < len");
        out.push(ch);
        i += ch.len_utf8();
    }
    Ok(out)
}

/// Render a step's command, if it has one. Steps with no command render to
/// `None` (a pure-prose step, e.g. "check the dashboard").
pub fn render_step(step: &Step, vars: &BTreeMap<String, String>) -> Result<Option<String>> {
    step.command.as_deref().map(|c| render(c, vars)).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn substitutes_known_placeholders() {
        let out = render(
            "kubectl exec {target} -n {namespace} -- check",
            &vars(&[("target", "web-1"), ("namespace", "prod")]),
        )
        .unwrap();
        assert_eq!(out, "kubectl exec web-1 -n prod -- check");
    }

    #[test]
    fn missing_placeholder_names_itself_in_error() {
        let err = render("kubectl delete pod {pod}", &vars(&[])).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("{pod}"), "{msg}");
        assert!(msg.contains("--var pod="), "{msg}");
    }

    #[test]
    fn never_produces_silent_blank() {
        // Regression guard for the exact danger case named in the spec: a
        // missing {pod} must error, not render as an empty segment that
        // turns a scoped delete into an unscoped one.
        let result = render("kubectl delete pod {pod} -n prod", &vars(&[]));
        assert!(result.is_err());
    }

    #[test]
    fn literal_braces_without_identifier_pass_through() {
        // `{}` and `{1}` are not valid placeholder identifiers (must start
        // with alpha/underscore) - so pass through unchanged rather than
        // erroring on "no value for placeholder".
        let out = render("echo {} and {1}", &vars(&[])).unwrap();
        assert_eq!(out, "echo {} and {1}");
    }

    #[test]
    fn build_vars_precedence_cli_over_default_over_auto() {
        let target = FqTarget::new("example", "prod", "web-1");
        let defaults = vars(&[("namespace", "from-default"), ("queue", "orders-dlq")]);
        let cli = vars(&[("namespace", "from-cli")]);
        let built = build_vars(Some(&target), &defaults, &cli);
        assert_eq!(built.get("target").map(String::as_str), Some("web-1"));
        assert_eq!(built.get("namespace").map(String::as_str), Some("from-cli"));
        assert_eq!(built.get("queue").map(String::as_str), Some("orders-dlq"));
    }

    #[test]
    fn build_vars_with_no_target_omits_auto_vars() {
        let built = build_vars(None, &BTreeMap::new(), &BTreeMap::new());
        assert!(!built.contains_key("target"));
        assert!(!built.contains_key("namespace"));
    }

    #[test]
    fn render_step_with_no_command_is_none() {
        let step = Step { text: "just look at the dashboard".into(), ..Default::default() };
        assert_eq!(render_step(&step, &BTreeMap::new()).unwrap(), None);
    }

    #[test]
    fn render_step_propagates_missing_placeholder_error() {
        let step = Step {
            command: Some("echo {missing}".into()),
            placeholders: vec!["missing".into()],
            ..Default::default()
        };
        assert!(render_step(&step, &BTreeMap::new()).is_err());
    }

    #[test]
    fn arbitrary_placeholder_names_supported() {
        let out = render(
            "resubmit --queue {queue} --strategy {strategy}",
            &vars(&[("queue", "orders-dlq"), ("strategy", "requeue")]),
        )
        .unwrap();
        assert_eq!(out, "resubmit --queue orders-dlq --strategy requeue");
    }
}
