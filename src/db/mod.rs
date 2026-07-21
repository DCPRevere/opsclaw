//! Persistence: trait-per-repo (gianna pattern), SQLite impl + in-memory
//! fake, one parity suite over both with SQLite as the spec.
//!
//! Wave 1 builds the implementations, the migrations, and the parity suite,
//! and adds the remaining repos whose domain types are gianna ports
//! (`JobRepo` with `Schedule`/`Job`, `RunbookRunRepo`). Targets/resources are
//! NOT here — config declares them (brief invariant #4); the DB holds runtime
//! state only.

pub mod repo;
