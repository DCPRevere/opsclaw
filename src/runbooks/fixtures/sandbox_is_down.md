+++
title = "Sandbox is down (expected-state short-circuit)"

[trigger]
alert_categories = ["target_unreachable"]
keywords = ["sandbox", "nxdomain", "unreachable"]
target_glob = "example::sandbox::*"
+++
The reference sandbox cluster (`example-sandbox`) is normally stopped
and wiped monthly by design — its API FQDN going NXDOMAIN is a state, not an
outage. This runbook exists to short-circuit the alert before anyone
diagnoses a healthy absence as a fault (DESIGN.md's `ExpectedState`).

- Check the configured expected state for this target before doing anything
  else
  ```sh
  opsclaw_config show --target {target}
  ```
- If expected state is `stopped` or `ephemeral`, confirm the monthly reset
  window rather than assuming a fault (on-fail: continue)
  ```sh
  az aks show --name example-sandbox --resource-group rg-sandbox --query powerState
  ```
- Only if the cluster is expected `running` and still unreachable, escalate
  as a real incident (on-fail: abort)
  ```sh
  az aks start --name example-sandbox --resource-group rg-sandbox
  ```
- Record the finding so the next alert on this target short-circuits faster.
