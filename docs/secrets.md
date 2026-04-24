# Secrets

OpsClaw stores credentials (API keys, SSH keys, tokens, passwords) as *references* in `opsclaw.toml`. The binary resolves the reference to a plaintext value at startup. Four reference schemes are supported.

| Scheme | Example | When to use |
| --- | --- | --- |
| `enc2:` | `api_key = "enc2:1a2b3c…"` | Default. Local laptops, single-host deploys. Encrypted at rest with ChaCha20-Poly1305. |
| `env:` | `api_key = "env:PAGERDUTY_TOKEN"` | Containers, CI, anything driven by env vars. |
| `k8s:` | `api_key = "k8s:ops/creds/pd_token"` | In-cluster deployments. Reads a mounted Secret volume. |
| *(plaintext)* | `api_key = "sk-real-secret"` | Not recommended; kept for backward compatibility. |

All four can be mixed freely across fields.

## `env:`

```toml
[pagerduty]
api_key = "env:PAGERDUTY_TOKEN"
```

The process reads `$PAGERDUTY_TOKEN` at startup. A missing or empty env var is a hard error — the tool that needs it is skipped with a warning, but the others start normally.

## `k8s:<namespace>/<secret-name>/<key>`

Addresses a key inside a Kubernetes Secret:

```toml
[pagerduty]
api_key = "k8s:ops/opsclaw-creds/pagerduty_token"

[github]
token = "k8s:ops/opsclaw-creds/github_token"
```

Two lookup paths, tried in order:

### 1. Mounted Secret volume (preferred)

Mount the Secret in your Deployment and OpsClaw reads it as a plain file. This is the cheap path — no RBAC for Secret reads, no API round-trip, kubelet handles rotation.

```yaml
volumes:
  - name: opsclaw-creds
    secret:
      secretName: opsclaw-creds
volumeMounts:
  - name: opsclaw-creds
    mountPath: /var/run/secrets/ops/opsclaw-creds
    readOnly: true
```

OpsClaw looks for `<mount-root>/<namespace>/<secret-name>/<key>`. The mount root defaults to `/var/run/secrets` and is overridable with:

```
OPSCLAW_K8S_SECRETS_ROOT=/path/to/custom/root
```

A single trailing newline is trimmed from the file contents — this matches how PEM/cert values are typically written — but internal newlines are preserved.

### 2. API fallback

If the mounted file is absent, OpsClaw falls back to `kube::Api::<Secret>::namespaced(ns).get(name)` and reads `.data[key]`. The ServiceAccount needs `get` on Secrets in that namespace. A missing *key* inside an otherwise-readable Secret is a hard error (likely a typo); a missing Secret surfaces the upstream API error.

The API path requires a kubeconfig or in-cluster credentials. On laptops without one, only the mounted-file path works.

## `enc2:` (encrypted store)

The default when you enter a secret through the CLI or setup wizard. The plaintext is encrypted with a random 256-bit key stored at `~/.opsclaw/.secret_key` (mode `0600`) and written back to `opsclaw.toml` as `enc2:<hex>`. Never commit your `.secret_key` — anyone with the file can decrypt the config.

Legacy `enc:` (XOR) values are auto-upgraded to `enc2:` on next save.

## Choosing a scheme

- **Developer laptop / single host** → `enc2:` (the default).
- **Docker container, CI job, systemd unit** → `env:`. Drive the values from the platform's secret injection (GitHub Actions secrets, `systemd-creds`, Vault agent, etc.).
- **Kubernetes deployment** → `k8s:` with a mounted volume. You get rotation and RBAC for free.

## Skip-on-failure behaviour

If a resolver can't satisfy its reference (env var unset, file missing and API fallback unavailable, ciphertext corrupt), the *tool* that needs that secret is skipped with a `tracing::warn!`. The agent still starts with the tools whose secrets did resolve. This keeps partial configs usable — if the GitHub token is missing but PagerDuty works, you still get the PagerDuty tool.

SSH key resolution follows the same rule per project: one project's broken key doesn't disable the others.
