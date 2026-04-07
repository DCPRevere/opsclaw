# SkillForge not reachable from CLI

The full Scout→Evaluate→Integrate pipeline is implemented in `skillforge/` but no CLI command invokes `SkillForge::forge()`. Add `opsclaw skills forge [--dry-run]` or similar so operators can trigger a discovery run on demand.
