+++
title = "Synchroniser lag"

[trigger]
alert_categories = ["read_model_staleness", "synchroniser_lag"]
keywords = ["synchroniser", "stale", "lag", "projection"]
target_glob = "remundo::*::*"
+++
Remundo.Synchroniser runs ~55 catch-up subscriptions projecting KurrentDB
events into Elasticsearch read models, with replicas=1 — a crash-loop stalls
every projection at once, and the UI goes silently stale with no error
anywhere. Detect by comparing projection position to stream head, not by
trusting the pod's own health.

- Compare projection position to stream head to confirm real lag, not a
  momentary blip
  ```sh
  kubectl exec deploy/remundo-synchroniser -n {namespace} -- synchroniser status --service {service}
  ```
- Check the pod isn't crash-looping (replicas=1, so this alone can explain
  total staleness) (on-fail: continue)
  ```sh
  kubectl get pods -n {namespace} -l app=remundo-synchroniser
  ```
- Restart the deployment (on-fail: abort)
  ```sh
  kubectl rollout restart deploy/remundo-synchroniser -n {namespace}
  ```
- Verify catch-up rate is closing the gap, not just that the pod is Running
  (on-fail: retry)
  ```sh
  kubectl exec deploy/remundo-synchroniser -n {namespace} -- synchroniser status --service {service}
  ```
