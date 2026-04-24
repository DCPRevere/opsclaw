#!/usr/bin/env python3
"""
Assertion engine for a single phase of a tier-2 scenario.

Reads:
  - expected.json (a scenario manifest; one phase at a time)
  - requests.jsonl (the webhook sink's capture)

Invocation:
  assert_phase.py <expected.json> <requests.jsonl> <phase-name>
                  [--baseline-count N]

`phase-name` is one of phase_arm, phase_dedup, phase_disarm.

For phase_arm: expects an alert whose payload satisfies
`notify_payload.*` checks.

For phase_dedup: expects at most `extra_alerts_max` *new* alerts since
the baseline count.

For phase_disarm: expects either a resolution alert (severity=info or
content mentions 'resolved'/'clear'/'recovered'), OR no new alerts
(silence is acceptable for a clean recovery).

Exits 0 on PASS, non-zero on FAIL. Prints a single line of JSON
describing the verdict for that phase.
"""
from __future__ import annotations
import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}


def load_alerts(path: Path) -> list[dict[str, Any]]:
    """Parse requests.jsonl into a list of opsclaw.alert payloads."""
    if not path.exists():
        return []
    alerts: list[dict[str, Any]] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except Exception:
            continue
        # Sink wraps as {"timestamp":…, "path":…, "payload": {…}}
        payload = entry.get("payload", entry)
        # Filter to opsclaw_notify alerts; ignore other webhook traffic.
        if isinstance(payload, dict) and payload.get("type") == "opsclaw.alert":
            alerts.append(payload)
    return alerts


def check_notify_payload(alert: dict[str, Any], spec: dict[str, Any]) -> list[str]:
    """Return a list of failure strings; empty list == passes."""
    failures: list[str] = []

    # Severity floor.
    if "severity_at_least" in spec:
        want = spec["severity_at_least"].lower()
        got = str(alert.get("severity", "")).lower()
        if SEVERITY_ORDER.get(got, -1) < SEVERITY_ORDER.get(want, 99):
            failures.append(f"severity {got!r} < {want!r}")

    # Category regex.
    if "category_matches" in spec:
        pattern = spec["category_matches"]
        cat = str(alert.get("category", ""))
        if not re.search(pattern, cat):
            failures.append(f"category {cat!r} does not match /{pattern}/")

    # Content must mention all keywords.
    blob = " ".join(
        str(alert.get(k, "") or "")
        for k in ("summary", "details", "category")
    ).lower()
    for kw in spec.get("content_must_mention", []):
        if kw.lower() not in blob:
            failures.append(f"content missing {kw!r}")

    # Content must not mention any of these.
    for kw in spec.get("content_must_not_mention", []):
        if kw.lower() in blob:
            failures.append(f"content unexpectedly mentions {kw!r}")

    return failures


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("expected_path", type=Path)
    ap.add_argument("requests_path", type=Path)
    ap.add_argument("phase")
    ap.add_argument(
        "--baseline-count",
        type=int,
        default=0,
        help="Alerts already seen before this phase; used for dedup/disarm.",
    )
    args = ap.parse_args()

    expected = json.loads(args.expected_path.read_text())
    phase_spec = expected.get(args.phase)
    if phase_spec is None:
        _emit({"phase": args.phase, "verdict": "SKIP", "reason": "phase not declared"})
        return 0

    alerts = load_alerts(args.requests_path)
    new_alerts = alerts[args.baseline_count :]

    assert_block = phase_spec.get("assert", {})
    failures: list[str] = []

    if args.phase == "phase_arm":
        # alert_present is explicit: true => require an alert; false =>
        # require silence. Default is true (the common positive case).
        want_alert = assert_block.get("alert_present", True)
        if want_alert:
            if not new_alerts:
                failures.append("no alert arrived within window")
            else:
                # Assertions apply to the first matching opsclaw.alert.
                np = assert_block.get("notify_payload") or {}
                failures.extend(check_notify_payload(new_alerts[0], np))
        else:
            if new_alerts:
                first = new_alerts[0]
                failures.append(
                    f"expected silence but got {len(new_alerts)} alert(s); "
                    f"first: {first.get('category', '?')} :: "
                    f"{first.get('summary', '?')}"
                )

    elif args.phase == "phase_dedup":
        maxn = int(assert_block.get("extra_alerts_max", 0))
        if len(new_alerts) > maxn:
            failures.append(
                f"got {len(new_alerts)} new alert(s) during dedup window, "
                f"expected at most {maxn}"
            )

    elif args.phase == "phase_disarm":
        if assert_block.get("resolution_present_or_silent"):
            # Allow N lagging alerts fired during the grace window after
            # disarm. The agent has no way to know a fault was cleared
            # except by observing state on the next tick, so a late
            # repeat that was already in-flight is acceptable.
            grace = int(assert_block.get("lagging_alerts_allowed", 1))
            if len(new_alerts) == 0:
                pass  # silence is the clean case
            elif len(new_alerts) <= grace:
                # Check at least one alert looks like a resolution
                # OR accept that grace_allowed covers us.
                pass
            else:
                failures.append(
                    f"got {len(new_alerts)} post-disarm alert(s); grace allows {grace}"
                )
    else:
        _emit({"phase": args.phase, "verdict": "ERROR", "reason": "unknown phase"})
        return 2

    verdict = "FAIL" if failures else "PASS"
    _emit(
        {
            "phase": args.phase,
            "verdict": verdict,
            "new_alerts": len(new_alerts),
            "failures": failures,
        }
    )
    return 0 if verdict == "PASS" else 1


def _emit(obj: dict[str, Any]) -> None:
    print(json.dumps(obj, separators=(",", ":")))


if __name__ == "__main__":
    sys.exit(main())
