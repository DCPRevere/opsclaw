# Multi-stage build for the opsclaw daemon (DESIGN.md §5: "the standard
# install is a docker-compose file: the opsclaw image (glibc-pinned
# two-stage build — gianna pins builder and runtime to the same Debian
# release)").
#
# Build context is the repo root: docker build -f deploy/Dockerfile .
#
# Stage 1: build a release binary.
FROM rust:1.96-slim AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends pkg-config && rm -rf /var/lib/apt/lists/*

# Cache dependencies: copy manifests first, build a dummy main/lib so
# dependencies compile and cache in their own layer before the real source
# ever invalidates it.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin/cli \
    && echo "fn main() {}" > src/main.rs \
    && echo "fn main() {}" > src/bin/cli/main.rs \
    && echo "" > src/lib.rs
RUN cargo build --release --bin opsclaw --bin opsclaw-cli || true
RUN rm -rf src

# Now the real source.
COPY . .
# Host file mtimes can be older than the dummy build above, which would let
# Cargo skip the "real" rebuild and ship the dummy stub instead (gianna hit
# exactly this with include_dir!-embedded trees — see gianna.chat/Dockerfile).
# opsclaw has no include_dir!/include_str! embed yet (the web UI isn't built
# out — DESIGN.md §2 http/), but touching src/migrations unconditionally
# costs nothing and avoids re-discovering the same bug the day one lands.
RUN find src migrations -type f -exec touch {} +
RUN cargo build --release --bin opsclaw --bin opsclaw-cli

# Stage 2: a slim runtime image. MUST track the builder's Debian release
# (rust:1.96-slim is trixie-based, confirmed via /etc/os-release
# VERSION_CODENAME) — a binary built against a newer glibc will not run on an
# older runtime image. Bump both FROM lines together, never one alone
# (gianna's lockstep-pinning rule, DESIGN.md §5).
FROM debian:trixie-slim AS runtime
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/opsclaw /usr/local/bin/opsclaw
COPY --from=builder /app/target/release/opsclaw-cli /usr/local/bin/opsclaw-cli
# sqlx runs migrations at startup (DESIGN.md §3 Persistence: "boot-time
# auto-migration").
COPY migrations ./migrations

ENV OPSCLAW_LISTEN=0.0.0.0:8484
EXPOSE 8484

# Non-root, matching gianna and the Helm chart's podSecurityContext
# (deploy/helm/values.yaml: runAsUser 10001).
RUN useradd -m -u 10001 opsclaw \
    && mkdir -p /home/opsclaw/.opsclaw \
    && chown -R opsclaw:opsclaw /app /home/opsclaw
USER opsclaw
ENV OPSCLAW_HOME=/home/opsclaw/.opsclaw

# /ready is the daemon's minimal boot healthcheck today (src/http/server.rs).
# start-period 30s: migrations run synchronously before the server binds;
# failing checks in that window don't count against retries.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:8484/ready" || exit 1

CMD ["opsclaw"]
