# Digest command silently drops errors

`ops_cli.rs:1476-1490` swallows `Err(_)` when loading incidents and anomalies for digest generation, returning empty vecs. At minimum, emit a `tracing::warn!` so operators know data was missing.
