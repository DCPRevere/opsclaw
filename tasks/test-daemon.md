# `ops/daemon.rs` has no tests

The daemon spawns monitor, watch, and digest tasks per-target but has no test verifying task lifecycle or graceful shutdown. At minimum, test that an empty-targets config runs the ZeroClaw runtime only.
