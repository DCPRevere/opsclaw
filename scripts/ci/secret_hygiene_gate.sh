#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

python3 - <<'PY'
from pathlib import Path
import re
import sys

ROOT = Path.cwd()
SKIP_DIRS = {'.git', '.claude/worktrees', 'target', 'target-release', 'web/node_modules'}
OPENAI_KEY = re.compile(r'OPENAI_API_KEY\s*=\s*(["\']?)(sk-(?:proj-)?[A-Za-z0-9_\-]{20,})\1')
STATIC_SHARED_SECRETS = (
    'webhook_secret = "' + 'mytoken' + '123"',
    'secret = "' + 'mytoken' + '123"',
)
failures: list[str] = []

for path in ROOT.rglob('*'):
    rel = path.relative_to(ROOT).as_posix()
    if not path.is_file():
        continue
    if any(rel == d or rel.startswith(d + '/') for d in SKIP_DIRS):
        continue
    try:
        if path.stat().st_size > 1_000_000:
            continue
    except OSError:
        continue
    try:
        text = path.read_text(errors='ignore')
    except OSError:
        continue
    if OPENAI_KEY.search(text):
        failures.append(f'{rel}: contains a real-looking OPENAI_API_KEY assignment')
    for needle in STATIC_SHARED_SECRETS:
        if needle in text:
            failures.append(f'{rel}: contains a static shared secret placeholder that must be blank or user-supplied')

if failures:
    print('secret hygiene gate failed:', file=sys.stderr)
    for failure in failures:
        print(f'  - {failure}', file=sys.stderr)
    sys.exit(1)
PY
