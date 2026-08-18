+++
title = "DLQ backlog triage"

[trigger]
alert_categories = ["dlq_backlog"]
keywords = ["dlq", "poison", "reprocessor"]
target_glob = "example::*::*"

[default_vars]
queue = "orders-dlq"
+++
replay job is a daily CronJob (`Forbid` concurrency policy) that
resubmits poison messages by strategy. Backlog growth means either the job is
failing outright, or messages are genuinely dead and recycling on the
retry-count config — the two require different fixes, so classify before
acting.

- Peek the queue to see what's actually in it
  ```sh
  az servicebus queue peek --queue {queue} --target {target} --count 20
  ```
- Check whether the Reprocessor CronJob is running at all (on-fail: continue)
  ```sh
  kubectl get cronjob example-reprocessor -n {namespace} -o wide
  ```
- Classify: transient failures are safe to resubmit, true poison should be
  parked rather than recycled forever.
- Resubmit transient failures via the Reprocessor strategy (on-fail: abort)
  ```sh
  kubectl create job --from=cronjob/example-reprocessor reprocessor-manual-{target} -n {namespace}
  ```
- Verify backlog is draining before closing out (on-fail: retry)
  ```sh
  az servicebus queue show --queue {queue} --target {target} --query messageCount
  ```
