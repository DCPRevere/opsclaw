# Memory

OpsClaw persists conversations, incidents, and learned knowledge across sessions. The memory system is pluggable — choose a backend that fits your setup.

## Backends

### SQLite (default)

No external dependencies. Stores everything in `~/.opsclaw/memory.db`.

```toml
[memory]
backend = "sqlite"
```

Supports full-text search (FTS5) out of the box.

### PostgreSQL

For teams sharing a single memory store, or for larger deployments:

```toml
[memory]
backend = "postgres"

[memory.postgres]
url = "postgresql://opsclaw:password@localhost:5432/opsclaw"
```

Requires the `memory-postgres` feature flag at build time.

### Lucid

Hybrid mode: writes to SQLite locally and replicates to PostgreSQL asynchronously. Useful if you want local-first performance with a shared store for backup or team access.

```toml
[memory]
backend = "lucid"

[memory.lucid]
sqlite_path = "~/.opsclaw/memory.db"
postgres_url = "postgresql://..."
sync_interval_secs = 60
```

### Qdrant

Vector database for pure semantic (embedding-based) search. Requires a running Qdrant instance.

```toml
[memory]
backend = "qdrant"

[memory.qdrant]
url = "http://localhost:6333"
collection = "opsclaw"
api_key = ""            # Optional: Qdrant Cloud API key
```

### Markdown

Snapshots memory to markdown files in `~/.opsclaw/memory/`. Human-readable and versionable.

```toml
[memory]
backend = "markdown"
```

### None

Disables persistence entirely. All context is lost when the session ends.

```toml
[memory]
backend = "none"
```

## Retention

```toml
[memory]
archive_after_days = 7          # Move to archive after this many days
purge_after_days = 30           # Delete archived entries after this many days
conversation_retention_days = 30  # SQLite row pruning threshold
```

## Semantic search

Enable embedding-based search to find relevant memories by meaning rather than keywords:

```toml
[memory]
embedding_provider = "openai"   # none | openai | custom:URL
embedding_model = "text-embedding-3-small"
embedding_dimensions = 1536
vector_weight = 0.7             # Weight for semantic similarity
keyword_weight = 0.3            # Weight for BM25 keyword match
min_relevance_score = 0.4       # Memories below this are excluded from results
embedding_cache_size = 10000    # In-memory embedding cache (entries)
chunk_max_tokens = 512          # Max tokens per memory chunk
```

`vector_weight` and `keyword_weight` should sum to 1.0. Increasing `keyword_weight` favours exact term matches; increasing `vector_weight` favours semantic similarity.

## Response cache

Deduplicates identical LLM requests to reduce API costs during repeated monitoring cycles:

```toml
[memory]
response_cache_enabled = true
response_cache_ttl_minutes = 60
response_cache_max_entries = 5000
response_cache_hot_entries = 256  # Hot tier kept in-memory
```

## Snapshots

Export the full memory store to markdown for backup or auditing:

```toml
[memory]
snapshot_enabled = true
snapshot_on_hygiene = true      # Snapshot automatically during hygiene passes
auto_hydrate = true             # Load snapshots into memory on startup
```

## CLI commands

```bash
opsclaw memory stats            # Storage size, entry counts, cache hit rate
opsclaw memory list             # List stored memories
opsclaw memory get <id>         # Retrieve a specific memory
opsclaw memory clear            # Wipe all memory (prompts for confirmation)
```

## How memory is used

During diagnosis, OpsClaw searches memory for similar past incidents. If it finds a match, it includes the previous resolution steps in its context — this is the main mechanism by which OpsClaw gets faster at recurring problems over time.

Memory entries are also written for:
- User preferences and instructions given during chat
- Target context inferred during scans
- Runbook outcomes (what worked, what didn't)
