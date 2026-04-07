# Daemon doesn't restart failed monitor tasks

`ops/daemon.rs:39-44` logs an error if a per-target monitor exits, but the task is never restarted. Add retry-with-backoff so a transient SSH failure doesn't permanently stop monitoring for that target.
