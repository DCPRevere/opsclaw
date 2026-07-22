//! Embed a PER-BUILD identity for cache busting. `CARGO_PKG_VERSION` alone
//! ("0.1.0") is identical across every local build, which pinned the PWA
//! service worker's cache forever: sw.js only updates when its BYTES change,
//! its bytes only changed with the version string, and the version string
//! never changed — so browsers kept serving whatever /app modules the worker
//! first cached, however many releases ago (found live 2026-07-22: a stale
//! format.js without new exports broke the whole chat module graph).
//!
//! The build id is the git short hash (+ "-dirty" when the tree has
//! uncommitted changes), falling back to "nogit" outside a repository.
//! Rerun-if-changed on HEAD/index means a new commit or a staged change
//! re-runs this script; same-tree rebuilds stay reproducible.

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    let hash = git(&["rev-parse", "--short=10", "HEAD"]).unwrap_or_else(|| "nogit".into());
    // `status --porcelain` output is non-empty iff the working tree differs
    // from HEAD — a dirty build must not impersonate the commit's identity.
    let dirty = git(&["status", "--porcelain"]).map(|s| !s.is_empty()).unwrap_or(false);
    let id = if dirty { format!("{hash}-dirty") } else { hash };
    println!("cargo:rustc-env=OPSCLAW_BUILD_ID={id}");
}
