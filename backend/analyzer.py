"""Deterministic multi-layer static analysis engine.

This is the fast, explainable first pass. It mirrors the DNA of the original
guard-agent-test (secrets, dependency confusion, obfuscation, exfiltration)
and extends it with CI-policy drift and AI-agent-safety layers.

OpenAI GPT-5.6 (see reasoner.py) runs as a *second* semantic pass on top of
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
    "discord-py-slash": "discord.py", "re-act": "react", "colourama": "colorama",
    "python3-dateutil": "python-dateutil", "jeIlyfish": "jellyfish", "reqests": "requests",
    "tensorflaw": "tensorflow", "opencv-pyhton": "opencv-python", "scikit-learn-": "scikit-learn",
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

    # ---- extended secret detection ----
    Rule("SEC-005", "code", "Google API key", "critical", 33,
         "A Google API key (AIza…) is embedded. Restrict, rotate, and move to Secret Manager.",
         r"AIza[0-9A-Za-z_\-]{35}", ["T1552.001"]),
    Rule("SEC-006", "code", "GitHub token", "critical", 34,
         "A GitHub access token (ghp_/gho_/ghs_/ghr_) is present. Revoke immediately in GitHub settings.",
         r"gh[posru]_[0-9A-Za-z]{36,}", ["T1552.001"]),
    Rule("SEC-007", "code", "Slack token", "high", 24,
         "A Slack token (xox…) is exposed — workspace access risk. Rotate and audit app scopes.",
         r"xox[baprs]-[0-9A-Za-z-]{10,}", ["T1552.001"]),
    Rule("SEC-008", "code", "Private key block", "critical", 36,
         "A PEM private key is committed. This is a full-credential leak; rotate the key pair now.",
         r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", ["T1552.004"]),
    Rule("SEC-009", "code", "JSON Web Token literal", "medium", 12,
         "A hardcoded JWT was found. Tokens embedded in source are frequently long-lived and over-scoped.",
         r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    Rule("SEC-010", "code", "Twilio / SendGrid key", "high", 24,
         "A Twilio (SK…) or SendGrid (SG.…) API key is present. Rotate; these carry billing and send scope.",
         r"SK[0-9a-fA-F]{32}|SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}", ["T1552.001"]),

    # ---- injection ----
    Rule("INJ-010", "code", "SQL built by string formatting", "high", 24,
         "A SQL statement is assembled with f-string/%/+ from variables — classic SQL injection. Use parameterized queries.",
         r"""(?i)(?:execute|executemany|cursor\.execute|query)\s*\(\s*(?:f["']|["'][^"']*["']\s*[%+]|["'][^"']*\{)""",
         ["T1190"]),
    Rule("INJ-012", "code", "Shell command from dynamic input", "critical", 30,
         "os.system / subprocess with shell=True built from variables — OS command injection path.",
         r"""(?i)(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen))\s*\([^)]*(?:f["']|["'][^"']*[%+]|\+\s*\w|shell\s*=\s*True[^)]*(?:f["']|\+))""",
         ["T1059"]),
    Rule("INJ-014", "exposure", "Path traversal from user input", "high", 20,
         "A file path is opened from request/args input without normalization — directory traversal risk.",
         r"""(?i)open\s*\(\s*(?:.*\+\s*)?(?:request|args|params|input|user)[\w\.\[\]'"]*\s*(?:\+|,|\))""",
         ["T1083"]),
    Rule("INJ-016", "exposure", "SSRF: outbound request to user-controlled URL", "high", 20,
         "An HTTP client is called with a user-supplied URL — server-side request forgery vector.",
         r"""(?i)requests\.(?:get|post|put)\s*\(\s*(?:request|args|params|input|user|url_param)""",
         ["T1090"]),

    # ---- crypto / transport hardening ----
    Rule("CRY-002", "code", "TLS verification disabled", "high", 22,
         "Certificate verification is turned off (verify=False / CERT_NONE) — enables man-in-the-middle.",
         r"(?i)verify\s*=\s*False|ssl\.CERT_NONE|InsecureRequestWarning|check_hostname\s*=\s*False",
         ["T1557"]),
    Rule("CRY-004", "code", "Weak hash for credentials", "medium", 12,
         "MD5/SHA1 used near password/token handling — cryptographically broken for secrets. Use bcrypt/argon2.",
         r"(?i)(?:md5|sha1)\s*\(\s*[^)]*(?:pass|pwd|secret|token|salt)"),
    Rule("CRY-006", "code", "Insecure randomness for security value", "medium", 10,
         "random.random/randint used to mint a token/secret/OTP — predictable. Use secrets / os.urandom.",
         r"(?i)(?:token|secret|otp|nonce|session[_-]?id)\s*=\s*.*random\.(?:random|randint|choice|randrange)"),

    # ---- exposure / misconfiguration ----
    Rule("EXP-011", "exposure", "Debug server bound to all interfaces", "high", 18,
         "Flask/Django debug mode with host 0.0.0.0 exposes an RCE console to the network. Never in production.",
         r"(?i)debug\s*=\s*True|run\([^)]*host\s*=\s*[\"']0\.0\.0\.0[\"']", ["T1190"]),
    Rule("EXP-013", "exposure", "Overly permissive CORS", "medium", 9,
         "Access-Control-Allow-Origin '*' with credentials exposes authenticated endpoints cross-origin.",
         r"""(?i)Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*|CORS\([^)]*origins\s*=\s*["']\*"""),
    Rule("SUP-020", "supply", "Dependency pinned to a Git URL / HTTP", "medium", 10,
         "A dependency resolves from a raw Git/HTTP URL rather than a checksummed registry release.",
         r"(?i)(?:git\+https?:\/\/|@\s*git|https?:\/\/)[^\s]+\.git|pip install[^\n]*--index-url"),

    # ---- injection / template ----
    Rule("SSTI-001", "code", "Server-side template injection", "high", 24,
         "A template is rendered from a string built with user input — server-side template injection can reach RCE.",
         r"""(?i)(?:render_template_string|Template\s*\()\s*(?:.*\+\s*)?(?:f["']|request|args|params|input|user)""",
         ["T1190"]),
    Rule("XXE-001", "code", "XML parsed with external entities enabled", "high", 20,
         "An XML parser resolves external entities (no resolve_entities=False / defusedxml) — XXE and SSRF risk.",
         r"(?i)etree\.(?:parse|fromstring)|xml\.dom\.minidom|xml\.sax\.|XMLParser\((?![^)]*resolve_entities\s*=\s*False)",
         ["T1059"]),
    Rule("SEC-011", "code", "Hardcoded signing secret", "high", 24,
         "A JWT/HMAC signing secret is hardcoded — anyone with the source can forge valid tokens. Use a secret manager.",
         r"""(?i)(?:jwt\.encode|hmac\.new|sign|secret_key|SECRET_KEY|JWT_SECRET)\s*[=(,][^\n]*["'][A-Za-z0-9_\-!@#$%^&*]{8,}["']""",
         ["T1552.001"]),

    # ---- AI-agent security (on-theme: securing agentic AI) ----
    Rule("AGT-010", "agent", "Unvalidated LLM output executed", "critical", 32,
         "Model/LLM output is passed straight into exec/eval/os.system/subprocess — the canonical agentic RCE path. "
         "Validate and sandbox model output before it can act.",
         r"""(?i)(?:eval|exec|os\.system|subprocess\.(?:run|call|Popen))\s*\([^)]*(?:response|completion|message|output|llm|model|gpt|assistant)""",
         ["T1059.006"]),
    Rule("AGT-012", "agent", "Over-broad tool/function exposure", "high", 18,
         "A tool/function schema exposes shell, file-write or delete capability to an AI agent without a policy gate.",
         r"""(?i)("?(?:name|function)"?\s*[:=]\s*["'](?:run_shell|execute_shell|exec|delete_file|write_file|rm|eval)["'])""",
         ["T1059"]),
]

CATS = [("code", "Code risk"), ("supply", "Supply chain"), ("exfil", "Exfiltration"),
        ("exposure", "Exposure"), ("agent", "AI agent risk"), ("cipolicy", "CI policy")]

_COMPILED = [(r, re.compile(r.pattern)) for r in RULES if r.pattern]


def _env_exfil(src: str) -> bool:
    # Catch both explicit reads (os.environ.items()/[…]/.get) and bare passes
    # such as `data=os.environ`, `json=dict(os.environ)`, `.env` file reads.
    reads_env = re.search(r"os\.environ\b|getenv\s*\(|open\s*\(\s*[\"'][^\"']*\.env[\"']", src)
    sends = re.search(r"(?i)requests\.(?:post|put|get)|urllib|httpx|socket\.|fetch\s*\(|curl\s+|smtplib|webhook", src)
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
