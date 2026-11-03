"""Human approvals that can't be reused or stretched.

An approval is bound to one exact action (the tool and a hash of its arguments), expires after a few minutes, works once,
and can't come from the agent that asked for it. So an agent that got "yes" to send one email can't use that yes to send a
different email, or the same one twice, or approve itself.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass


def action_hash(tool: str, args: dict | None) -> str:
    return hashlib.sha256(json.dumps({"tool": tool, "args": args or {}}, sort_keys=True, default=str).encode()).hexdigest()


@dataclass
class Request:
    action: str                 # action_hash of the tool call
    requester: str
    expires: float
    approved_by: str = ""
    used: bool = False


class Approvals:
    def __init__(self, ttl_seconds: float = 300):
        self.ttl = ttl_seconds
        self._requests: dict[str, Request] = {}

    def request(self, tool: str, args: dict | None, requester: str = "agent", now: float | None = None) -> str:
        now = time.time() if now is None else now
        rid = uuid.uuid4().hex
        self._requests[rid] = Request(action_hash(tool, args), requester, now + self.ttl)
        return rid

    def approve(self, request_id: str, by: str, now: float | None = None) -> tuple[bool, str]:
        now = time.time() if now is None else now
        r = self._requests.get(request_id)
        if r is None:
            return False, "no such approval request"
        if by == r.requester:
            return False, "the agent that asked can't approve its own request"
        if now > r.expires:
            return False, "the approval request has expired"
        if r.used:
            return False, "this request was already used"
        r.approved_by = by
        return True, f"approved by {by}"

    def consume(self, request_id: str, tool: str, args: dict | None, now: float | None = None) -> tuple[bool, str]:
        """Checks an approval at the moment the action runs, and uses it up."""
        now = time.time() if now is None else now
        r = self._requests.get(request_id)
        if r is None:
            return False, "no such approval request"
        if not r.approved_by:
            return False, "the request has not been approved"
        if r.used:
            return False, "this approval was already used"
        if now > r.expires:
            return False, "the approval has expired"
        if r.action != action_hash(tool, args):
            return False, "the approval was for a different action"
        r.used = True
        return True, f"approved by {r.approved_by}"
