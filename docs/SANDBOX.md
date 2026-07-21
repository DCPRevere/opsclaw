# Running OpsClaw against the remundo sandbox cluster

Daemon runs LOCALLY (the sandbox AKS API is public:
`aks-sandbox-spoke05-clus01-dns-2xvgt1h4.hcp.uksouth.azmk8s.io`); the
cluster is a remote target. Everything below is one-time setup except
step 4 (port-forward) and step 6 (start).

Cluster facts (verified 2026-07-21): ECK Elasticsearch CR `coresearch`
v8.15.0 in namespace `logs` (svc `coresearch-es-http:9200`, HTTPS,
password secret `coresearch-es-elastic-user`); workload namespaces
`prod-backend` (~70 pods) and `sandbox-backend`; ArgoCD, Dapr, APISIX,
monitoring present. Sandbox is wiped monthly — re-run steps 1–3 after a
wipe.

## 1. Cluster credential (your AAD kubectl, once)

```sh
kubectl --context aks-sandbox-spoke05-clus01 apply -f deploy/sandbox-rbac.yaml
deploy/gen-opsclaw-kubeconfig.sh
# smoke test as the scoped SA:
kubectl --kubeconfig ~/.opsclaw/sandbox-kubeconfig.yaml get pods -A --no-headers | head
```

The ClusterRole is read-only + `pods/portforward`, and deliberately has
NO `secrets` access — opsclaw can never pull cluster credentials into
LLM context.

## 2. Secrets into the encrypted store

```sh
openssl rand -base64 48 | opsclaw-cli secret set jwt-secret
printf '%s' "$HOME/.opsclaw/sandbox-kubeconfig.yaml" | opsclaw-cli secret set sandbox-kubeconfig
kubectl --context aks-sandbox-spoke05-clus01 -n logs get secret coresearch-es-elastic-user \
  -o jsonpath='{.data.elastic}' | base64 -d | opsclaw-cli secret set es-password
```

Never paste a secret into chat — chat enters LLM context before the
scrubber can know the value. `secret set` is the sanctioned path.

## 3. Config

```sh
cp deploy/config.sandbox.example.toml ~/.opsclaw/config.toml
export OPENROUTER_API_KEY=...   # or via the daemon's unit environment
opsclaw-cli config validate
```

Autonomy ships pinned `observe` for the sandbox env: reads run, mutations
land in the dry-run log, nothing executes. Promote to `suggest` in
config after reviewing `opsclaw-cli dry-run-log`.

## 4. Port-forwards: Elasticsearch + Prometheus (per session)

One supervised script, using opsclaw's OWN kubeconfig (the SA has the
portforward verb); each forward auto-restarts when its backing pod cycles:

```sh
deploy/sandbox-portforwards.sh
# localhost:9201 -> logs/coresearch-es-http:9200                      (ES, HTTPS)
# localhost:9202 -> monitoring/prometheus-stack-kube-prom-prometheus:9090 (Prometheus, HTTP)
```

The ES resource is declared `insecure_tls = true` because the ECK cert's
SANs are the in-cluster DNS names — a localhost hop can never match.
Prometheus (kube-prometheus-stack) is plain HTTP with no auth in-cluster;
Grafana is only a UI over the same data, so opsclaw talks PromQL to
Prometheus directly via its `prometheus_*` tools.
Verify by hand: `curl -sk -u "elastic:…" https://localhost:9201/_cluster/health`
and `curl -s 'http://localhost:9202/api/v1/query?query=up' | head -c 200`.

## 5. Hindsight (memory) + first operator

```sh
# Hindsight on :8888 (docker) — live mode refuses to boot without it.
opsclaw-cli account create you@example.com --name you
```

## 6. Run

```sh
opsclaw-cli doctor           # every check green before first start
opsclaw-cli daemon           # or the deploy/opsclaw.service unit
# web UI: http://localhost:8484
```

First-contact validation, in order:

```sh
opsclaw-cli scan remundo::sandbox::cluster   # one diagnose cycle, report printed
opsclaw-cli dry-run-log                      # what observe-mode refused
opsclaw-cli audit verify                     # chain intact
```

Then leave it soaking in `observe` and read the incident list before
any autonomy promotion. The daily LLM spend cap is `$5`
(`limits.max_cost_per_day_cents = 500`) — when it trips, the daemon
keeps ticking but stops calling the model until UTC midnight, and says
so on every channel once per day.
