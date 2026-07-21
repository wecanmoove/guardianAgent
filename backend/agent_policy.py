"""AI-agent execution policy engine.

The XPRIZE rule is: the business must be *operated by AI agents*. Those agents
are actors, so every tool call they request is evaluated here BEFORE it runs:
ALLOW (scoped), SANDBOX (shadow first), ESCALATE (human approval), or DENY.

This is the enforcement point that makes "agents run the company" safe.
"""
import re
from dataclasses import dataclass


@dataclass
class PolicyResult:
    outcome: str      # Executed | Sandboxed | Awaiting approval | Denied
    policy: str       # policy id + reason
    risk: float
    cls: str          # UI badge class


# Ordered: first match wins. Each is (id, matcher, outcome, risk, reason, badge)
POLICIES = [
    ("POL-AGT-011", lambda t, a: bool(re.search(r"run_shell|bash\s+-i|/bin/sh|subprocess", t, re.I)),
     "Denied", 0.96, "no interactive shell / raw subprocess from an agent", "b-crit"),
    ("POL-AGT-014", lambda t, a: bool(re.search(r"commit.*\bmain\b|commit.*protected|push.*protected", t + " " + a, re.I)),
     "Denied", 0.74, "protected ref requires a human author", "b-crit"),
    ("POL-AGT-021", lambda t, a: bool(re.search(r"delete.*audit|drop table audit|truncate audit", t + " " + a, re.I)),
     "Denied", 0.99, "audit records are immutable", "b-crit"),
    ("POL-AGT-030", lambda t, a: bool(re.search(r"s3\.put_object\(ext|external bucket|egress|exfil", t + " " + a, re.I)),
     "Awaiting approval", 0.89, "cross-boundary egress needs human approval", "b-med"),
    ("POL-AGT-045", lambda t, a: bool(re.search(r"rotate_secret|vault\.|delete_key", t, re.I)),
     "Executed", 0.42, "privileged but in runbook - executed with audit artifact", "b-ok"),
    ("POL-AGT-050", lambda t, a: bool(re.search(r"close|bulk.?close|auto.?close|resolve", t + " " + a, re.I)),
     "Sandboxed", 0.58, "state-changing triage runs in shadow mode first", "b-quar"),
]

DEFAULT = ("POL-AGT-000", "Executed", 0.15, "read/comment scope - no privileged effect", "b-ok")


def evaluate(agent: str, action: str, tool: str) -> PolicyResult:
    for pid, match, outcome, risk, reason, cls in POLICIES:
        if match(tool, action):
            return PolicyResult(outcome, f"{outcome.upper()} -  {pid} {reason}", risk, cls)
    pid, outcome, risk, reason, cls = DEFAULT
    return PolicyResult(outcome, f"{outcome.upper()} -  {pid} {reason}", risk, cls)
