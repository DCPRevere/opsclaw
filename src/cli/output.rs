//! `--json` output convention: every read command builds one `serde_json`
//! value, then either prints it pretty (`--json`) or destructures it into a
//! human-formatted table/lines (default) — gianna's CLI pattern
//! (`commands.rs`'s `doctor`), ported because it keeps the two output modes
//! from drifting (one value, two renderings) rather than building the human
//! and machine paths independently.
//!
//! No table-formatting crate (`comfy-table`/`tabled`) is declared in
//! `Cargo.toml`; human tables here are hand-aligned with `{:<width$}` — fine
//! at the row counts these commands ever print (incidents/targets/audit
//! pages, not spreadsheets).

use serde::Serialize;

/// Print `value` as pretty JSON (the `--json` path). Infallible in practice
/// (the values passed here are always plain serializable structs), but
/// surfaces a clear message instead of panicking if serialization ever does
/// fail.
pub fn print_json<T: Serialize>(value: &T) {
    match serde_json::to_string_pretty(value) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("opsclaw-cli: failed to serialize output: {e}"),
    }
}

/// A minimal left-aligned table for human output: a header row, then data
/// rows, columns sized to the widest cell (including the header) per column.
/// Every row must have the same number of cells as `headers`.
pub fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    if rows.is_empty() {
        println!("(none)");
        return;
    }
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if let Some(w) = widths.get_mut(i) {
                *w = (*w).max(cell.len());
            }
        }
    }
    let header_line: Vec<String> =
        headers.iter().enumerate().map(|(i, h)| format!("{:<width$}", h, width = widths[i])).collect();
    println!("{}", header_line.join("  "));
    let rule: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    println!("{}", rule.join("  "));
    for row in rows {
        let line: Vec<String> =
            row.iter().enumerate().map(|(i, c)| format!("{:<width$}", c, width = widths[i])).collect();
        println!("{}", line.join("  "));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_empty_says_none() {
        // Just exercises the no-panic path; stdout isn't captured here.
        print_table(&["a", "b"], &[]);
    }

    #[test]
    fn table_widths_expand_to_content() {
        // Smoke test: must not panic on ragged-but-consistent input.
        print_table(
            &["name", "state"],
            &[vec!["a-very-long-target-name".into(), "ok".into()], vec!["x".into(), "degraded".into()]],
        );
    }
}
