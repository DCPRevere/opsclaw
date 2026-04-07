# Runbook executor has bare `.unwrap()` in production code

`ops/runbooks.rs:364` calls `steps_completed.last_mut().unwrap()` during retry logic. If `steps_completed` is ever empty (edge case), this panics. Guard with an `if let Some(last)` or bail.
