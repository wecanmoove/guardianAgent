"""Deterministic multi-layer static analysis engine.

This is the fast, explainable first pass. It mirrors the DNA of the original
guard-agent-test (secrets, dependency confusion, obfuscation, exfiltration)
and extends it with CI-policy drift and AI-agent-safety layers.

Gemini 2.5 Flash (see gemini.py) runs as a *second* semantic pass on top of
these deterministic findings — reasoning about intent, not just keywords.
"""
import re
from dataclasses import dataclass, asdict, field


@dataclass
class Rule:
    id: str
    cat: str
    name: str
    sev: str          # critical | high | medium | low
    weight: int
    desc: str
    pattern: str | None = None
    mitre: list[str] = field(default_factory=list)


# Lexical typosquat targets (canonical -> squats seen in the wild)
TYPOSQUATS = {
    "python-dateutils": "python-dateutil", "reqeusts": "requests", "urlib3": "urllib3",
    "beutifulsoup4": "beautifulsoup4", "djago": "django", "flaskk": "flask",
    "numpi": "numpy", "pandass": "pandas", "crypto-utils-py": "cryptography",
    "discord-py-slash": "discord.py", "re-act": "react",
}

RULES = [
    Rule("SEC-001", "code", "GitLab personal access token", "critical", 35,
         "A GitLab PAT is embedded in the content. Treat as compromised: rotate immediately and purge history.",
         r"glpat-[0-9A-Za-z_\-]{16,}", ["T1552.001"]),
    Rule("SEC-002", "code", "AWS access key", "critical", 35,
         "AWS access key ID detected. Rotate the key pair and audit CloudTrail for usage.",
         r"AKIA[0-9A-Z]{16}", ["T1552.001"]),
    Rule("SEC-003", "code", "Generic API secret assignment", "high", 22,
         "A high-entropy literal is assigned to a credential-named variable. Move to a secret manager.",
         r"""(?i)(?:api[_-]?key|secret|token|passwd|password)\s*[:=]\s*["'][A-Za-z0-9_\-\/+]{12,}["']"""),
    Rule("SEC-004", "code", "Stripe live secret key", "critical", 35,
         "Stripe live-mode secret key found. Rotation required; payment scope exposure.",
         r"sk_live_[0-9A-Za-z]{16,}", ["T1552.001"]),
    Rule("INJ-003", "code", "eval/exec on dynamic input", "critical", 30,
         "Dynamic execution primitive fed by external input — direct arbitrary code execution path.",
         r"""(?i)\b(?:eval|exec)\s*\(\s*(?:input|request|args|params|data|expr|payload|f["'])""",
         ["T1059.006"]),
    Rule("INJ-001", "code", "Dynamic execution primitive", "high", 16,
         "eval()/exec() present. Even with static input this is fragile; prefer ast.literal_eval or explicit dispatch.",
         r"\b(?:eval|exec)\s*\("),
    Rule("DES-001", "code", "Unsafe deserialization", "high", 20,
         "Deserialization of untrusted data (pickle / yaml.load without SafeLoader) can lead to RCE.",
         r"pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*SafeLoader)|marshal\.loads"),
    Rule("OBF-002", "exfil", "Encoded payload piped to shell", "critical", 32,
         "Base64 content is decoded and executed. Classic staged-payload delivery; human review at minimum.",
         r"base64\s+(?:-d|--decode)[^\n]*\|\s*(?:ba)?sh|echo\s+[\"'][A-Za-z0-9+\/=]{24,}[\"']\s*\|",
         ["T1140", "T1059.004"]),
    Rule("OBF-004", "exfil", "Suspicious encoded blob", "medium", 10,
         "Long base64-like literal found. Verify contents; encoded payloads are a common obfuscation vector.",
         r"""["'][A-Za-z0-9+\/]{40,}={0,2}["']"""),
    Rule("NET-002", "exfil", "Hardcoded external egress endpoint", "medium", 12,
         "Outbound endpoint on a low-reputation or unregistered TLD. Register egress domains with security review.",
         r"(?i)https?:\/\/(?!localhost|127\.0\.0\.1|(?:[a-z0-9-]+\.)*(?:example\.com|corp|internal))[a-z0-9.-]+\.(?:dev|xyz|top|io|cc|link)\b"),
    Rule("ERR-007", "code", "Silenced exception around I/O", "medium", 8,
         "Broad except/pass hides failures — frequently paired with quiet exfiltration.",
         r"except\s+(?:Exception|BaseException)?\s*:\s*\n?\s*pass"),
    Rule("SUP-014", "supply", "Remote script executed at build time", "high", 22,
         "Build fetches and executes remote content. Pin, vendor and checksum third-party install scripts.",
         r"(?i)curl[^\n|]*\|\s*(?:ba)?sh|wget[^\n|]*\|\s*(?:ba)?sh|ADD\s+https?:\/\/"),
    Rule("DOC-003", "supply", "Fragile Docker base / privileges", "medium", 10,
         "Unpinned base image, root user or world-writable permissions weaken container supply-chain integrity.",
         r"FROM\s+\S+:latest|USER\s+root|chmod\s+777|--privileged"),
    Rule("DOC-007", "exposure", "SSH exposed from container", "medium", 9,
         "Container exposes SSH — expansion of attack surface that gates should question.",
         r"EXPOSE\s+22\b"),
    Rule("CIP-005", "cipolicy", "Security job made non-blocking", "high", 20,
         "A pipeline job tolerates failure. If this is the security gate, the control is silently disabled.",
         r"allow_failure:\s*true"),
    Rule("CIP-009", "cipolicy", "Unconditional job execution", "medium", 8,
         '"when: always" runs regardless of upstream failures — verify this cannot ship unverified artifacts.',
         r"when:\s*always"),
    Rule("AGT-002", "agent", "Prompt-injection marker", "high", 18,
         "Content carries instruction-override language targeting an AI agent — indirect prompt injection vector.",
         r"(?i)ignore (?:all )?(?:previous|prior|above) instructions|disregard (?:your|the) (?:system|previous) prompt"),
    Rule("AGT-005", "agent", "Agent self-privilege language", "medium", 10,
         "Content requests weakening of agent guardrails or sandbox policy.",
         r"(?i)(?:disable|bypass|remove).{0,24}(?:guardrail|safety|policy|sandbox)"),
]

CATS = [("code", "Code risk"), ("supply", "Supply chain"), ("exfil", "Exfiltration"),
        ("exposure", "Exposure"), ("agent", "AI agent risk"), ("cipolicy", "CI policy")]

_COMPILED = [(r, re.compile(r.pattern)) for r in RULES if r.pattern]


def _env_exfil(src: str) -> bool:
    reads_env = re.search(r"os\.environ(?:\.items\(\)|\[|\.get)", src)
    sends = re.search(r"(?i)requests\.(?:post|put|get)|urllib|httpx|fetch\s*\(|curl\s+", src)
    return bool(reads_env and sends)


def _typosquat(src: str):
    hits = [sq for sq in TYPOSQUATS if re.search(r"(^|\n)\s*" + re.escape(sq) + r"\b", src, re.I)]
    return hits or None


def analyze(src: str) -> dict:
    """Deterministic pass. Returns findings + composite decision."""
    findings = []
    lines = src.split("\n")

    for rule, rx in _COMPILED:
        for i, line in enumerate(lines):
            m = rx.search(line)
            if m:
                findings.append({**asdict(rule), "line": i + 1, "snippet": m.group(0)[:90]})
                break

    if _env_exfil(src):
        findings.append({**asdict(RULES_BY_ID["EXF-004"]), "line": None, "snippet": None})
    squats = _typosquat(src)
    if squats:
        findings.append({**asdict(RULES_BY_ID["SUP-009"]), "line": None, "snippet": ", ".join(squats)})

    # INJ-001 is subsumed by INJ-003
    if any(f["id"] == "INJ-003" for f in findings):
        findings = [f for f in findings if f["id"] != "INJ-001"]

    cat_score = {c: 0 for c, _ in CATS}
    for f in findings:
        cat_score[f["cat"]] = min(100, cat_score[f["cat"]] + f["weight"] * 2.2)
    total = min(100, sum(f["weight"] for f in findings))

    n_crit = sum(1 for f in findings if f["sev"] == "critical")
    n_high = sum(1 for f in findings if f["sev"] == "high")
    has_supply_crit = any(f["cat"] == "supply" and f["sev"] == "critical" for f in findings)

    if n_crit >= 2 or (n_crit >= 1 and has_supply_crit):
        decision, why = "Quarantine", ("Multiple critical signals including supply-chain or exfiltration class — "
                                       "artifact must not enter any build until replaced and reviewed.")
    elif n_crit >= 1 or total >= 55:
        decision, why = "Block", "At least one critical finding (or composite risk >= 55) — merge blocked pending remediation."
    elif n_high >= 1 or total >= 25:
        decision, why = "Review", "High-severity or accumulated medium findings — human review required before merge."
    else:
        decision = "Allow"
        why = ("Only low-impact hygiene findings — allowed with annotations." if findings
               else "No detections across all analysis layers — allowed under fast-path policy.")

    mitre = sorted({m for f in findings for m in f.get("mitre", [])})
    return {"findings": findings, "cat_score": {k: round(v) for k, v in cat_score.items()},
            "composite": total, "decision": decision, "why": why, "mitre": mitre}


# Rules only reachable via custom logic (not regex-compiled)
RULES_BY_ID = {r.id: r for r in RULES}
RULES_BY_ID["EXF-004"] = Rule("EXF-004", "exfil", "Environment bulk-read + external send", "critical", 34,
                              "Code reads environment variables and performs outbound network calls in the same "
                              "unit — a likely secret exfiltration path.", None, ["T1552.001", "T1041"])
RULES_BY_ID["SUP-009"] = Rule("SUP-009", "supply", "Typosquatted package name", "critical", 30,
                              "Package name is lexically adjacent to a popular library — high-confidence typosquat. "
                              "Replace with the canonical package.", None, ["T1195.002"])
