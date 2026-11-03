# Reporting a security problem

Found a way past Blue Guardian (a bypass of the policy, the approval checks, the audit chain or the MCP proxy) or a bug in
it? Please report it privately first, through GitHub: the repository's **Security** tab, then **Report a vulnerability**.
Don't open a public issue for it.

What helps: what you did, what you expected, what happened, and the smallest example that shows it.

What happens next: an answer within 7 days, a fix as fast as the problem deserves, and credit in the release notes if you
want it. Once a fix is out, the problem is described publicly.

Detector misses are a bit different: the classifier is known to miss some attacks (see [PASS_MARKS.md](PASS_MARKS.md) and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)). Examples it misses are still very welcome, as a public issue, unless the
example also defeats the policy layer.
