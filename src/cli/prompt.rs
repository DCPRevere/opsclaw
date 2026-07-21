//! Interactive prompt I/O, kept behind a trait so wizards are testable
//! without a real terminal.
//!
//! No interactive-prompt crate (`dialoguer`/`inquire`/...) is declared in
//! `Cargo.toml`, and this crate deliberately avoids growing it casually —
//! `Cargo.toml` is the merge-conflict hotspot for parallel worktree agents
//! (see the top comment there). Gianna's own CLI has exactly one precedent
//! for interactive input (`remote/mod.rs`'s `prompt()`: `print!` + blocking
//! `stdin().read_line()`, no crate), so that's the pattern ported here,
//! wrapped in a trait so tests can script answers instead of driving a real
//! TTY. If a richer wizard (arrow-key select, inline validation) is wanted
//! later, that is a deliberate ask to add a dependency, not something to
//! reach for silently mid-implementation.

use std::io::Write;

use crate::Result;

/// Everything a wizard needs from the outside world: asking questions and
/// printing status. `StdioPrompter` drives a real terminal; `ScriptedPrompter`
/// (test-only, see below) drives a fixed answer queue so wizard logic is
/// exercised without spawning a subprocess or faking a PTY.
pub trait Prompter {
    /// Ask a free-text question. `default` is used verbatim if the operator
    /// enters an empty line (and is shown in the prompt as `[default]`).
    fn ask(&mut self, question: &str, default: Option<&str>) -> Result<String>;

    /// Ask a yes/no question. `default` picks what an empty answer means.
    fn confirm(&mut self, question: &str, default: bool) -> Result<bool>;

    /// Print an informational line (wizard narration, not a question).
    fn say(&mut self, line: &str);
}

/// Real terminal I/O: `print!` + blocking `stdin().read_line()`, gianna's
/// only precedent for interactive input in this codebase's family.
#[derive(Default)]
pub struct StdioPrompter;

impl StdioPrompter {
    pub fn new() -> Self {
        StdioPrompter
    }

    fn read_line(&self) -> Result<String> {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| crate::Error::other(format!("reading stdin: {e}")))?;
        Ok(line.trim().to_string())
    }
}

impl Prompter for StdioPrompter {
    fn ask(&mut self, question: &str, default: Option<&str>) -> Result<String> {
        match default {
            Some(d) if !d.is_empty() => print!("{question} [{d}]: "),
            _ => print!("{question}: "),
        }
        std::io::stdout().flush().ok();
        let line = self.read_line()?;
        if line.is_empty() { Ok(default.unwrap_or("").to_string()) } else { Ok(line) }
    }

    fn confirm(&mut self, question: &str, default: bool) -> Result<bool> {
        let hint = if default { "Y/n" } else { "y/N" };
        print!("{question} [{hint}]: ");
        std::io::stdout().flush().ok();
        let line = self.read_line()?;
        Ok(match line.to_ascii_lowercase().as_str() {
            "" => default,
            "y" | "yes" => true,
            "n" | "no" => false,
            _ => default,
        })
    }

    fn say(&mut self, line: &str) {
        println!("{line}");
    }
}

/// A fixed queue of scripted answers, consumed in call order. Panics on an
/// under-scripted wizard (an unscripted `ask`/`confirm` call) so a test that
/// forgets to script a step fails loudly instead of hanging on real stdin
/// the way an un-mocked interactive prompt would.
///
/// Not `#[cfg(test)]`-gated: plain `pub`, same as `db::memory::InMemoryDb` —
/// both unit tests (`src/cli/*.rs`) and integration tests (`tests/*.rs`, a
/// separate crate) need to reach it, and `#[cfg(test)]` items are invisible
/// across that boundary.
#[derive(Default)]
pub struct ScriptedPrompter {
    answers: std::collections::VecDeque<String>,
    pub said: Vec<String>,
}

impl ScriptedPrompter {
    pub fn new(answers: impl IntoIterator<Item = impl Into<String>>) -> Self {
        ScriptedPrompter {
            answers: answers.into_iter().map(Into::into).collect(),
            said: Vec::new(),
        }
    }
}

impl Prompter for ScriptedPrompter {
    fn ask(&mut self, question: &str, default: Option<&str>) -> Result<String> {
        let answer = self
            .answers
            .pop_front()
            .unwrap_or_else(|| panic!("ScriptedPrompter under-scripted at ask({question:?})"));
        if answer.is_empty() { Ok(default.unwrap_or("").to_string()) } else { Ok(answer) }
    }

    fn confirm(&mut self, question: &str, default: bool) -> Result<bool> {
        let answer = self
            .answers
            .pop_front()
            .unwrap_or_else(|| panic!("ScriptedPrompter under-scripted at confirm({question:?})"));
        Ok(match answer.to_ascii_lowercase().as_str() {
            "" => default,
            "y" | "yes" => true,
            "n" | "no" => false,
            other => panic!("ScriptedPrompter: bad confirm answer {other:?} for {question:?}"),
        })
    }

    fn say(&mut self, line: &str) {
        self.said.push(line.to_string());
    }
}
