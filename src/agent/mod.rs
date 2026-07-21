//! The agent loop (Wave 3). Ported from gianna's tool loop skeleton — step
//! cap + wall-clock deadline, tool-error splitting, duplicate-call guard,
//! prefix-cache-ordered prompt, token-budgeted replay — with the dispatch
//! changed from act-then-announce to classify-then-gate through
//! `policy::execute` (DESIGN §3).
