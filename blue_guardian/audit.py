"""A tamper-evident audit log. Each line carries the hash of the line before it, so editing, deleting or reordering any past
entry breaks the chain from that point on, and `blue-guardian verify-log` says where.

It proves the log wasn't quietly changed; it can't stop someone deleting the whole file, so ship it to storage the agent
can't write to (a SIEM, a write-once bucket) when that matters.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

GENESIS = "0" * 64


def entry_hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def last_hash(path: Path) -> str:
    """The hash of the last line, so a restarted process continues the same chain."""
    if not path.exists() or path.stat().st_size == 0:
        return GENESIS
    with path.open("rb") as f:
        f.seek(max(0, path.stat().st_size - 65536))
        lines = f.read().splitlines()
    for line in reversed(lines):
        try:
            return json.loads(line)["hash"]
        except (ValueError, KeyError):
            continue
    return GENESIS


def verify_log(path: str | Path) -> tuple[bool, str]:
    prev = GENESIS
    with Path(path).open(encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                e = json.loads(line)
            except ValueError:
                return False, f"line {n} is not valid JSON"
            if e.get("prev") != prev:
                return False, f"line {n} does not follow line {n - 1} (a line was removed, added or reordered)"
            if e.get("hash") != entry_hash(e):
                return False, f"line {n} was changed after it was written"
            prev = e["hash"]
    return True, "the chain is intact"
