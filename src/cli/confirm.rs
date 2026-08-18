//! The brake on destructive CLI commands.
//!
//! `config rm`, `secret rm`, `memory forget` and `account revoke-sessions`
//! all destroyed without asking, without previewing, and without a `--yes`
//! to make the intent explicit. `config rm <project>` dropped every
//! environment, target and resource beneath it in one word; `memory forget`
//! takes FREE TEXT and deletes every fact it matches, so the blast radius
//! was not even knowable from the command line.
//!
//! Three rules, and the third is the one that is easy to get wrong:
//!
//! 1. `--yes` proceeds. Scripts, CI and `docker compose exec -T` need a way
//!    through that is a deliberate statement rather than a defeated prompt.
//! 2. Otherwise, with a terminal, ask — defaulting to NO.
//! 3. Otherwise **refuse**. With no terminal there is nobody to answer, and
//!    both alternatives are wrong: reading EOF as "yes" destroys data nobody
//!    confirmed, and reading it as "no" turns a piped command into a silent
//!    no-op that exits 0 while the operator believes it worked. This is not
//!    a corner case here — the documented way to reach this CLI is
//!    `docker compose exec -T`, which never has a TTY.

use std::io::IsTerminal;

use crate::Result;

/// Gate a destructive action.
///
/// `preview` is printed first and should name exactly what is about to be
/// destroyed — a count is not enough when the selector is free text. Returns
/// `Ok(())` to proceed; every other case is an error the caller propagates,
/// so a refusal exits non-zero rather than looking like a completed run.
pub fn destructive(preview: &str, yes: bool) -> Result<()> {
    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        return Err(crate::Error::Config(format!(
            "{preview}\n\nrefusing to do this without confirmation, and there is no terminal to \
             ask on — re-run with --yes if you are sure.\n(`docker compose exec -T` has no \
             terminal; drop -T for an interactive prompt.)"
        )));
    }
    print!("{preview}\n\nproceed? [y/N]: ");
    flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| crate::Error::other(format!("reading confirmation: {e}")))?;
    match line.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Ok(()),
        // Anything else is a no, including a typo: this is the branch where
        // guessing generously destroys data.
        _ => Err(crate::Error::Config("cancelled — nothing was changed".into())),
    }
}

fn flush() {
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yes_proceeds_without_asking() {
        // Must hold regardless of whether the test runner has a terminal.
        assert!(destructive("would delete everything", true).is_ok());
    }

    #[test]
    fn without_a_terminal_it_refuses_rather_than_guessing() {
        // `cargo test` runs with stdin not a terminal, which is the same
        // shape as `docker compose exec -T` — the documented way to reach
        // this CLI. Reading EOF as "yes" would destroy unconfirmed data;
        // reading it as "no" would exit 0 having done nothing, which reads
        // as success. Refusing is the only honest third answer.
        assert!(
            !std::io::stdin().is_terminal(),
            "this test asserts the no-TTY branch; it needs stdin to not be a terminal"
        );
        let err = destructive("would delete example", false).unwrap_err().to_string();
        assert!(err.contains("--yes"), "must name the way through: {err}");
        assert!(err.contains("would delete example"), "the preview must survive: {err}");
        assert!(err.contains("-T"), "name the trap the operator is actually in: {err}");
    }
}
