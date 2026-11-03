"""The rules half of Blue Guardian: plain code that decides allow / block / ask for every action an AI agent wants to take.
No model is involved here, so nothing an attacker writes can talk it out of a rule.

A policy is a dict, a JSON file or a YAML file (YAML needs `pip install pyyaml`):
{
  "default": "block",                                   # unknown tools are blocked
  "tools": {
    "read_file":  {"paths": ["./workspace/**"]},
    "write_file": {"paths": ["./workspace/**"], "ask": true},
    "http_get":   {"domains": ["api.github.com", "*.wikipedia.org"]},
    "shell":      {"deny": ["rm\\s+-rf", "curl[^|]*\\|\\s*(ba)?sh"], "ask": true},
    "send_email": {"allow": false}
  },
  "egress_tools": ["http_get", "send_email", "http_post"],   # tools that can move data out
  "limits": {"actions_per_minute": 30, "usd_per_day": 5},
  "mode": "enforce",                                    # or "monitor": log what would happen, block nothing
  "secrets": "block",                                   # a secret in a data-moving tool's arguments: block | ask | allow
  "on_injection": "block",                              # MCP proxy: withhold (block) or flag (warn) tool output that looks like an injection
  "tests": [{"tool": "shell", "args": {"cmd": "rm -rf /"}, "expect": "block"}]   # checked by `blue-guardian test-policy`
}
"""
from __future__ import annotations

import fnmatch
import json
import re
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

ALLOW, BLOCK, ASK = "allow", "block", "ask"


@dataclass
class Decision:
    verdict: str                 # allow | block | ask
    reason: str
    rule: str = ""
    request_id: str = ""         # set on "ask": the approval request a human answers

    @property
    def allowed(self) -> bool:
        return self.verdict == ALLOW


@dataclass
class Policy:
    tools: dict = field(default_factory=dict)
    default: str = BLOCK
    egress_tools: list = field(default_factory=lambda: ["http_get", "http_post", "send_email", "upload"])
    limits: dict = field(default_factory=dict)
    mode: str = "enforce"
    secrets: str = BLOCK
    on_injection: str = BLOCK
    tests: list = field(default_factory=list)
    _actions: deque = field(default_factory=deque, repr=False)
    _spend: list = field(default_factory=list, repr=False)       # (timestamp, usd)

    @classmethod
    def load(cls, source: str | dict) -> "Policy":
        if isinstance(source, dict):
            data = source
        elif str(source).lower().endswith((".yaml", ".yml")):
            try:
                import yaml
            except ImportError as e:
                raise RuntimeError("YAML policies need pyyaml: pip install blue-guardian[yaml]") from e
            data = yaml.safe_load(Path(source).read_text("utf-8")) or {}
        else:
            data = json.loads(Path(source).read_text("utf-8"))
        for key, allowed in (("default", (BLOCK, ASK)), ("mode", ("enforce", "monitor")), ("secrets", (BLOCK, ASK, ALLOW)),
                             ("on_injection", (BLOCK, "warn"))):
            if key in data and data[key] not in allowed:
                raise ValueError(f"policy '{key}' must be one of {allowed}, not {data[key]!r}")
        return cls(tools=data.get("tools", {}), default=data.get("default", BLOCK),
                   egress_tools=data.get("egress_tools", cls().egress_tools), limits=data.get("limits", {}),
                   mode=data.get("mode", "enforce"), secrets=data.get("secrets", BLOCK),
                   on_injection=data.get("on_injection", BLOCK), tests=data.get("tests", []))

    def fresh(self) -> "Policy":
        """Same rules, empty rate and spending counters (for policy tests)."""
        return Policy(tools=self.tools, default=self.default, egress_tools=self.egress_tools, limits=self.limits,
                      mode=self.mode, secrets=self.secrets, on_injection=self.on_injection, tests=self.tests)

    # ---------------------------------------------------------------- the checks
    def check(self, tool: str, args: dict | None = None, cost_usd: float = 0.0, now: float | None = None) -> Decision:
        args = args or {}
        now = time.time() if now is None else now
        rule = self.tools.get(tool)
        if rule is None:
            return Decision(BLOCK if self.default == BLOCK else ASK, f"'{tool}' is not in the policy", "default")
        if rule.get("allow") is False:
            return Decision(BLOCK, f"'{tool}' is switched off", f"tools.{tool}.allow")

        if "paths" in rule:
            for key in ("path", "src", "dst", "file"):
                if key in args and not self._path_ok(str(args[key]), rule["paths"]):
                    return Decision(BLOCK, f"{key} '{args[key]}' is outside the allowed folders", f"tools.{tool}.paths")
        if "domains" in rule and "url" in args:
            host = (urlparse(str(args["url"])).hostname or "").lower()
            if not any(fnmatch.fnmatch(host, d.lower()) for d in rule["domains"]):
                return Decision(BLOCK, f"'{host or args['url']}' is not an allowed website", f"tools.{tool}.domains")
        for pattern in rule.get("deny", []):
            text = " ".join(str(v) for v in args.values())
            if re.search(pattern, text, re.I):
                return Decision(BLOCK, f"matches a forbidden pattern ({pattern})", f"tools.{tool}.deny")

        lim = self.limits
        if lim.get("actions_per_minute"):
            while self._actions and now - self._actions[0] > 60:
                self._actions.popleft()
            if len(self._actions) >= lim["actions_per_minute"]:
                return Decision(BLOCK, f"more than {lim['actions_per_minute']} actions in a minute", "limits.actions_per_minute")
        if lim.get("usd_per_day") is not None and cost_usd:
            spent = sum(c for t, c in self._spend if now - t < 86400)
            if spent + cost_usd > lim["usd_per_day"]:
                return Decision(BLOCK, f"would pass the US${lim['usd_per_day']} daily spending cap", "limits.usd_per_day")

        self._actions.append(now)
        if cost_usd:
            self._spend.append((now, cost_usd))
        if rule.get("ask"):
            return Decision(ASK, f"'{tool}' needs a human to approve it", f"tools.{tool}.ask")
        return Decision(ALLOW, "within policy", f"tools.{tool}")

    @staticmethod
    def _path_ok(path: str, allowed: list[str]) -> bool:
        """Normalise ../ and backslashes before matching, so 'workspace/../.env' cannot slip through."""
        p = PurePosixPath(path.replace("\\", "/"))
        parts: list[str] = []
        for part in p.parts:
            if part == "..":
                if not parts or parts[-1] in ("/", "."):
                    return False                     # climbs above the starting point
                parts.pop()
            elif part != ".":
                parts.append(part)
        norm = "/".join(parts).replace("//", "/")
        return any(fnmatch.fnmatch(norm, a.lstrip("./").replace("\\", "/")) or fnmatch.fnmatch("./" + norm, a) for a in allowed)
