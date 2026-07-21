//! The `runbook init` starter template — what `opsclaw-cli runbook init`
//! writes for an operator to fill in. Kept as a plain constant (not
//! generated) so the file an author gets literally matches what's documented
//! in `frontmatter.rs`.

/// Starter markdown for a new runbook. Valid front matter (parses cleanly)
/// with placeholder trigger/vars an author is expected to edit, plus one
/// example step of each kind (prose-only, and command-with-placeholders) so
/// the grammar is demonstrated in place rather than just described.
pub const INIT_TEMPLATE: &str = r#"+++
title = "Untitled runbook"

[trigger]
alert_categories = []
keywords = []
target_glob = "project::*::*"

[default_vars]
+++
<!--
  Steps are markdown list items. Each may carry one fenced ```sh command with
  {placeholders} ({target}, {namespace} are auto-filled from the matched
  target; add any others via --var or [default_vars] above), and an inline
  `(on-fail: abort|continue|retry)` marker (default: abort).
-->

- Confirm the signal before acting — state what you're checking and why.
- Run the diagnostic (on-fail: continue)
  ```sh
  echo "describe the read-only check here for {target}"
  ```
- Apply the fix (on-fail: abort)
  ```sh
  echo "describe the remediation command here for {target} in {namespace}"
  ```
- Verify the fix worked before closing out.
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runbooks::Runbook;

    #[test]
    fn init_template_parses_as_a_valid_runbook() {
        let rb = Runbook::parse(INIT_TEMPLATE).expect("init template must parse");
        assert_eq!(rb.front_matter.title, "Untitled runbook");
        assert!(!rb.steps.is_empty());
    }

    #[test]
    fn init_template_steps_have_expected_shape() {
        let rb = Runbook::parse(INIT_TEMPLATE).unwrap();
        // At least one step demonstrates a command with placeholders...
        assert!(rb.steps.iter().any(|s| s.command.is_some() && !s.placeholders.is_empty()));
        // ...and at least one is prose-only.
        assert!(rb.steps.iter().any(|s| s.command.is_none()));
    }
}
