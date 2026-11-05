"""blue-guardian command line.

    blue-guardian mcp-proxy --policy policy.yaml [--audit-log audit.jsonl] -- <mcp server command...>
    blue-guardian test-policy policy.yaml          # runs the policy's own tests; exit code 1 on any failure (for CI)
    blue-guardian verify-log audit.jsonl           # checks the hash chain; exit code 1 if anything was changed
    blue-guardian scan [file]                      # scores a file (or stdin) for prompt injection
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys


def make_detector(name: str):
    os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")       # keep library logs and progress bars off the screen
    os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
    logging.getLogger("torch.distributed.elastic.multiprocessing.redirects").setLevel(logging.ERROR)   # harmless Windows note
    from blue_guardian.detect import DEFAULT_MODEL, HeuristicDetector, ModelDetector
    if name == "heuristic":
        return HeuristicDetector()
    if name == "auto":
        try:
            return ModelDetector()
        except Exception as e:                        # no torch / no download: the rules still work
            print(f"blue-guardian: model detector unavailable ({e}); using the heuristic detector", file=sys.stderr)
            return HeuristicDetector()
    return ModelDetector(DEFAULT_MODEL if name == "model" else name)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="blue-guardian")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("mcp-proxy", help="guard one MCP server over stdio")
    p.add_argument("--policy", required=True)
    p.add_argument("--detector", default="auto", help="auto | heuristic | model | a model folder or Hugging Face id")
    p.add_argument("--audit-log")
    p.add_argument("--kill-switch", help="if this file exists, every tool call is blocked")
    p.add_argument("--ask", choices=["dialog", "deny"], default="dialog", help="how 'ask' decisions reach the owner")
    p.add_argument("--repin", action="store_true", help="forget pinned tool descriptions (after you reviewed a change)")
    p.add_argument("--no-redact", action="store_true", help="don't redact secrets in tool output")
    p.add_argument("server", nargs=argparse.REMAINDER, help="-- then the MCP server command")
    t = sub.add_parser("test-policy")
    t.add_argument("policy")
    v = sub.add_parser("verify-log")
    v.add_argument("log")
    s = sub.add_parser("scan")
    s.add_argument("file", nargs="?")
    s.add_argument("--text", help="text to score, instead of a file or stdin")
    s.add_argument("--detector", default="auto")
    a = ap.parse_args(argv)

    if a.cmd == "test-policy":
        from blue_guardian.gateway import run_policy_tests
        from blue_guardian.policy import Policy
        pol = Policy.load(a.policy)
        fails = run_policy_tests(pol)
        print("\n".join(fails) or f"all {len(pol.tests)} policy tests pass")
        return 1 if fails or not pol.tests else 0
    if a.cmd == "verify-log":
        from blue_guardian.audit import verify_log
        ok, why = verify_log(a.log)
        print(why)
        return 0 if ok else 1
    if a.cmd == "scan":
        text = a.text if a.text is not None else open(a.file, encoding="utf-8", errors="replace").read() if a.file else sys.stdin.read()
        d = make_detector(a.detector).score(text)
        print(json.dumps({"score": d.score, "flagged": d.flagged, "reasons": d.reasons}))
        return 1 if d.flagged else 0

    from blue_guardian.gateway import Guardian
    from blue_guardian.mcp import MCPProxy, ask_dialog
    server = a.server[1:] if a.server[:1] == ["--"] else a.server
    if not server:
        ap.error("give the MCP server command after --")
    g = Guardian(a.policy, detector=make_detector(a.detector), audit_log=a.audit_log, kill_switch=a.kill_switch, agent_id="mcp-client")
    proxy = MCPProxy(g, server, ask=ask_dialog if a.ask == "dialog" else (lambda *_: False), redact_output=not a.no_redact)
    if a.repin:
        proxy.pins = {}
    return proxy.run()


if __name__ == "__main__":
    sys.exit(main())
