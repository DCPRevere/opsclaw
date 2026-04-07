# `ops_cli.rs` has zero test coverage

All 13 public handler functions (`handle_monitor`, `handle_scan`, `handle_logs`, `handle_probe`, etc.) have no unit or integration tests. The underlying ops modules are tested, but the orchestration layer is not. Add at least smoke tests with a mock config and mock SSH runner.
