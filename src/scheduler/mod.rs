//! The heartbeat (Wave 3). Ported skeleton from gianna's scheduler:
//! supervised loops with panic-respawn, phase isolation, watchdog atomics
//! (lag vs stall — the dead-man's switch), claim-before-send exactly-once,
//! bounded compose concurrency, retry/backoff/dead-letter. OpsClaw phases:
//! scan jobs (adaptive tick), escalation chain, approval-timeout sweep,
//! external dead-man heartbeat ping, housekeeping.
