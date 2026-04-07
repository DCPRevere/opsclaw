# `opsclaw postmortem` CLI command

`PostMortem::generate()` and `PostMortem::render_markdown()` exist in `ops/postmortem.rs` but there is no CLI subcommand to invoke them. Wire a `Commands::Postmortem { incident_id }` that loads the incident, gathers health-check timeline entries, generates the report, and prints/saves it.
