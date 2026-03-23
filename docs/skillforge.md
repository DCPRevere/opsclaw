# SkillForge

SkillForge is OpsClaw's skill auto-discovery engine. It scans repositories on GitHub, ClawHub, and HuggingFace, evaluates their quality, and integrates the best ones into your OpsClaw installation.

## What is a skill?

A skill is a user-defined capability — a tool or script that the agent can call. Skills extend what OpsClaw can do beyond its built-in operations.

Manage your current skills:

```bash
opsclaw skills                  # List installed skills
```

## SkillForge pipeline

```
Scout → Evaluate → Integrate
```

1. **Scout** — searches configured sources for skill repositories
2. **Evaluate** — scores each candidate on quality criteria
3. **Integrate** — writes approved skills to your output directory as TOML manifests

## Configuration

```toml
[skillforge]
enabled = false                 # Disabled by default
auto_integrate = true           # Automatically add skills above min_score
sources = ["github", "clawhub"]  # Sources to scan
scan_interval_hours = 24        # How often to run the pipeline
min_score = 0.7                 # Quality threshold (0.0–1.0)
github_token = "ghp_..."        # Optional: increases GitHub rate limits
output_dir = "~/.opsclaw/skills"
```

## Sources

| Source | Description |
|---|---|
| `github` | GitHub repository search |
| `clawhub` | Anthropic's skill registry |
| `huggingface` | HuggingFace Hub |

## Scoring

SkillForge scores each candidate on:

- Documentation completeness
- Code quality and test coverage
- Community signals (stars, downloads, issue activity)
- Manifest completeness and schema validity
- Performance benchmarks (if available)

Skills scoring below `min_score` are skipped. Skills in the marginal range (just below threshold) are flagged for manual review rather than discarded.

## Running the pipeline manually

```bash
opsclaw skills --forge           # Run a discovery scan now
```

## Output format

Integrated skills are written to `output_dir` as TOML:

```toml
[[skills]]
name = "web_scraper"
description = "Scrape and summarise web pages"
version = "1.0.0"
provider = "github"
source_url = "https://github.com/example/opsclaw-web-scraper"
```

## Manual review

Skills flagged for manual review are listed with their scores:

```bash
opsclaw skills --pending
```

Accept or reject a pending skill:

```bash
opsclaw skills --accept web_scraper
opsclaw skills --reject web_scraper
```
