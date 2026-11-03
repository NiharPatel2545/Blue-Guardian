"""Blue Guardian: one object an agent framework calls at two moments.

  g.inspect(text, source)        before the agent reads untrusted text (a web page, an email, a file, a tool's output)
  g.authorize(tool, args, cost)  before the agent runs a tool

It never acts on its own: it only answers allow / block / ask. It cannot run commands, send anything or change its own
rules, so it has nothing to "go rogue" with. Every answer is appended to a hash-chained audit log (see audit.py).

Taint: once untrusted text that looks like an injection has been read in this session, every tool that can move data out
(egress_tools in the policy) needs a human's approval, even if the policy would normally allow it. This is what stops the
classic attack where a web page tells the agent to send your files somewhere.

Secrets: a data-moving tool whose arguments contain an API key, token, private key or database password is blocked (or sent
for approval, per the policy's "secrets" setting), and secrets never reach the audit log.

Approvals: an "ask" answer carries a request_id. A human approves that id (approvals.py), and the agent retries with
approval=request_id. The approval fits only that exact tool and arguments, works once and expires. It can lift an "ask",
never a "block".
"""
from __future__ import annotations

import json
import time
from functools import wraps
from pathlib import Path

from blue_guardian.approvals import Approvals
from blue_guardian.audit import entry_hash, last_hash
from blue_guardian.detect import Detection, HeuristicDetector
from blue_guardian.policy import ALLOW, ASK, BLOCK, Decision, Policy
from blue_guardian.secret_scan import find_secrets, redact

UNTRUSTED = {"web", "email", "file", "tool_output", "tool_description", "document", "unknown"}


class Blocked(Exception):
    def __init__(self, decision: Decision):
        super().__init__(decision.reason)
        self.decision = decision


class Guardian:
    def __init__(self, policy: Policy | dict | str, detector=None, audit_log: str | None = None, kill_switch: str | None = None,
                 agent_id: str = "agent", approval_ttl: float = 300):
        self.policy = policy if isinstance(policy, Policy) else Policy.load(policy)
        self.detector = detector or HeuristicDetector()
        self.audit_log = Path(audit_log) if audit_log else None
        self.kill_switch = Path(kill_switch) if kill_switch else None
        self.agent_id = agent_id
        self.approvals = Approvals(approval_ttl)
        self.tainted_by: list[str] = []          # sources that delivered a suspected injection this session
        self._prev = last_hash(self.audit_log) if self.audit_log else None

    def inspect(self, text: str, source: str = "unknown") -> Detection:
        d = self.detector.score(text)
        if d.flagged and source in UNTRUSTED:
            self.tainted_by.append(source)
        self._log("inspect", {"source": source, "score": d.score, "flagged": d.flagged, "reasons": d.reasons, "chars": len(text)})
        return d

    def authorize(self, tool: str, args: dict | None = None, cost_usd: float = 0.0, approval: str | None = None) -> Decision:
        if self.kill_switch and self.kill_switch.exists():
            d = Decision(BLOCK, "kill switch is on: every action is stopped", "kill_switch")
        else:
            d = self._decide(tool, args, cost_usd)
            if d.verdict == ASK and approval:
                ok, why = self.approvals.consume(approval, tool, args)
                d = Decision(ALLOW, why, "approval") if ok else Decision(BLOCK, why, "approval")
            elif d.verdict == ASK:
                d.request_id = self.approvals.request(tool, args, self.agent_id)
        verdict = d.verdict
        if self.policy.mode == "monitor" and d.rule != "kill_switch" and verdict != ALLOW:
            d = Decision(ALLOW, f"monitor mode, would have been {verdict}: {d.reason}", d.rule)
        self._log("authorize", {"tool": tool, "args": {k: redact(str(v))[:200] for k, v in (args or {}).items()},
                                "verdict": d.verdict, "would_be": verdict, "reason": d.reason, "rule": d.rule,
                                "request_id": d.request_id})
        return d

    def _decide(self, tool: str, args: dict | None, cost_usd: float) -> Decision:
        d = self.policy.check(tool, args, cost_usd)
        if d.verdict == BLOCK or tool not in self.policy.egress_tools:
            return d
        leaked = sorted({s.kind for v in (args or {}).values() for s in find_secrets(str(v)) if s.strong})
        if leaked and self.policy.secrets != ALLOW:
            why = f"would send a secret out ({', '.join(leaked)})"
            return Decision(BLOCK if self.policy.secrets == BLOCK else ASK, why, "secrets")
        if d.verdict == ALLOW and self.tainted_by:
            return Decision(ASK, f"this session read a suspected injection (from {self.tainted_by[-1]}), so sending data out needs approval", "taint")
        return d

    def approve(self, request_id: str, by: str) -> tuple[bool, str]:
        """A human (not the agent) approves one pending request."""
        ok, why = self.approvals.approve(request_id, by)
        self._log("approve", {"request_id": request_id, "by": by, "ok": ok, "reason": why})
        return ok, why

    def guard(self, tool: str, approve=None, cost_usd: float = 0.0):
        """Decorator for a tool function: blocked calls raise Blocked; 'ask' calls go to approve(tool, args, decision) -> bool,
        a callback that must reach a human (a dialog, a chat message), never the agent itself."""
        def wrap(fn):
            @wraps(fn)
            def inner(**kwargs):
                d = self.authorize(tool, kwargs, cost_usd)
                if d.verdict == ASK and approve and approve(tool, kwargs, d):
                    ok = self.approve(d.request_id, by="human")[0] and self.approvals.consume(d.request_id, tool, kwargs)[0]
                    d = Decision(ALLOW, "approved by a human", "approval") if ok else d
                if d.verdict != ALLOW:
                    raise Blocked(d)
                return fn(**kwargs)
            return inner
        return wrap

    def _log(self, kind: str, data: dict) -> None:
        if self.audit_log:
            self.audit_log.parent.mkdir(parents=True, exist_ok=True)
            entry = {"t": round(time.time(), 3), "kind": kind, **data, "prev": self._prev}
            entry["hash"] = self._prev = entry_hash(entry)
            with self.audit_log.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def run_policy_tests(policy: Policy) -> list[str]:
    """Runs the 'tests' listed in a policy file; returns one line per failure (empty = all pass). For CI."""
    failures = []
    for i, t in enumerate(policy.tests, 1):
        got = Guardian(policy.fresh()).authorize(t["tool"], t.get("args"), t.get("cost_usd", 0.0))
        if got.verdict != t["expect"]:
            failures.append(f"test {i} ({t['tool']} {t.get('args', {})}): expected {t['expect']}, got {got.verdict} ({got.reason})")
    return failures
