"""Finds secrets (API keys, tokens, private keys, database URLs with passwords) in text, so Blue Guardian can stop an agent
from sending them out and keep them out of its own audit log.

Strong patterns have a fixed, recognisable shape (a provider's key prefix, a PEM header) and almost never match normal text,
so they can block an action. Weak patterns (password = ...) only redact, because they also match harmless config examples.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# (kind, strong, pattern). Order matters: the more specific Anthropic pattern runs before the generic sk- one.
PATTERNS = [
    ("private-key", True, r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)"),
    ("aws-access-key", True, r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("github-token", True, r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    ("anthropic-key", True, r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    ("openai-key", True, r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}"),
    ("huggingface-token", True, r"\bhf_[A-Za-z0-9]{30,}\b"),
    ("slack-token", True, r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    ("stripe-key", True, r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}"),
    ("google-api-key", True, r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("jwt", True, r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("database-url", True, r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@]+:[^\s@/]+@[^\s'\"]+"),
    ("password-assignment", False, r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token)\b\s*[:=]\s*['\"]?[^\s'\"]{8,}"),
]
_COMPILED = [(k, s, re.compile(p)) for k, s, p in PATTERNS]


@dataclass
class Secret:
    kind: str
    start: int
    end: int
    strong: bool


def find_secrets(text: str) -> list[Secret]:
    found: list[Secret] = []
    for kind, strong, rx in _COMPILED:
        for m in rx.finditer(text):
            if not any(f.start <= m.start() < f.end for f in found):      # an earlier, more specific match wins
                found.append(Secret(kind, m.start(), m.end(), strong))
    return sorted(found, key=lambda s: s.start)


def redact(text: str) -> str:
    """Replaces every secret with [REDACTED:kind]."""
    out, last = [], 0
    for s in find_secrets(text):
        out += [text[last:s.start], f"[REDACTED:{s.kind}]"]
        last = s.end
    return "".join(out) + text[last:]
