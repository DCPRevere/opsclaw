# `ops/context.rs` has no tests

`OpsClawContext::ssh_runner_for()` does non-trivial validation (target type, missing fields) that should have unit tests to prevent regressions.
