//! Runbooks (Wave 3): markdown + TOML front matter, trigger matching (alert
//! categories, keywords, target glob), `{placeholder}` steps, per-step
//! failure handling, execution history + success-rate tracking. A runbook
//! match is the pre-approval that unlocks `act_on_known` (brief §7).
