"""OpenAI GPT-5.6 reasoning layer.

This is the "cognitive engine" that reasons about the deterministic analyzer's
findings using OpenAI's GPT-5.6 model.

GPT-5.6 runs as a SECOND pass on top of the deterministic analyzer:
  1. analyzer.py finds keyword/pattern signals (fast, explainable).
  2. GPT-5.6 reasons about INTENT - is this actually malicious, is it a
     false positive, what is the developer-facing explanation and fix.

If no API key is configured the module degrades gracefully to a
deterministic "reasoning" verdict so the demo always runs offline.
"""
import json
import re
import logging

from . import llm

logger = logging.getLogger(__name__)

MODEL = llm.MODEL

SYSTEM_PROMPT = """You are GuardAgent, an autonomous DevSecOps security reviewer.
You receive: (a) a code/diff/config snippet, and (b) the deterministic findings
from a static analyzer. Reason about INTENT, not just keywords.

Return STRICT JSON with keys:
  verdict: one of "Allow" | "Review" | "Block" | "Quarantine"
  confidence: float 0..1
  threat_class: short label (e.g. "Secret exfiltration", "None detected")
  summary: 2-3 sentence developer-facing explanation of the real risk
  false_positive_risk: "low" | "medium" | "high"
  remediation: one concrete next action
Be decisive. Prefer Block/Quarantine when a credible code-execution or
data-exfiltration path exists. Do not add prose outside the JSON."""


def available() -> bool:
    return llm.available()


def _fallback(analysis: dict) -> dict:
    """Deterministic stand-in when OpenAI is not configured."""
    f = analysis["findings"]
    top = max(f, key=lambda x: x["weight"]) if f else None
    return {
        "verdict": analysis["decision"],
        "confidence": min(0.99, 0.6 + 0.05 * len(f)),
        "threat_class": top["name"] if top else "None detected",
        "summary": analysis["why"],
        "false_positive_risk": "low" if analysis["composite"] >= 40 else "medium",
        "remediation": (top["desc"] if top else "No action required."),
        "engine": "deterministic-fallback",
    }


FIX_PROMPT = """You are GuardAgent Fix Engine, an autonomous remediation engineer.
You receive a flagged code/config snippet plus the static-analyzer findings.
Produce the SAFE version of the code - semantically equivalent business logic
with every security defect remediated (secrets moved to env vars, queries
parameterized, TLS verification restored, eval removed, etc.).

Return STRICT JSON with keys:
  fixed_code: the complete remediated snippet (same language, runnable)
  changes: array of {finding_id, line, before, after, explanation} (<=8 entries)
  residual_risk: "none" | "low" | "medium" - what a human must still verify
  summary: 1-2 sentences describing the remediation
Do not add features. Do not add prose outside the JSON."""

# Deterministic auto-patches: (finding id prefix, regex, replacement, note)
_AUTOPATCHES = [
    ("SEC", r"""(?im)^(\s*)((?:api[_-]?key|secret|token|passwd|password)\s*[:=]\s*)["'][^"']{8,}["']""",
     r"\1\2os.environ[\"GUARDAGENT_SECRET\"]  # moved to env - rotate the leaked value",
     "Credential literal replaced with an environment lookup."),
    ("CRY-002", r"(?i)verify\s*=\s*False", "verify=True",
     "TLS certificate verification restored."),
    ("EXP-011", r"(?i)debug\s*=\s*True", "debug=False",
     "Debug mode disabled for production."),
    ("DES-001", r"yaml\.load\s*\(([^),]+)\)", r"yaml.safe_load(\1)",
     "yaml.load switched to safe_load."),
    ("DOC-003", r"(?i)USER\s+root\b", "USER app",
     "Container no longer runs as root."),
    ("CIP-005", r"allow_failure:\s*true", "allow_failure: false",
     "Security job made blocking again."),
]


def _fix_fallback(src: str, analysis: dict) -> dict:
    """Deterministic remediation when OpenAI is not configured."""
    fixed = src
    changes = []
    for f in analysis["findings"]:
        for prefix, rx, repl, note in _AUTOPATCHES:
            if f["id"].startswith(prefix) and re.search(rx, fixed):
                before = re.search(rx, fixed).group(0)[:90]
                fixed = re.sub(rx, repl, fixed, count=1)
                changes.append({"finding_id": f["id"], "line": f.get("line"),
                                "before": before, "after": repl[:90], "explanation": note})
                break
        else:
            if f["id"] not in {c["finding_id"] for c in changes}:
                changes.append({"finding_id": f["id"], "line": f.get("line"),
                                "before": (f.get("snippet") or "")[:90], "after": "",
                                "explanation": f["desc"]})
    auto = sum(1 for c in changes if c["after"])
    return {
        "fixed_code": fixed,
        "changes": changes[:8],
        "residual_risk": "low" if auto == len(changes) else "medium",
        "summary": f"{auto} finding(s) auto-patched deterministically; "
                   f"{len(changes) - auto} need manual remediation (guidance attached).",
        "engine": "deterministic-fallback",
    }


def propose_fix(src: str, analysis: dict) -> dict:
    """Generate a remediated version of flagged code via GPT-5.6."""
    if not available():
        return _fix_fallback(src, analysis)
    user = (
        f"CODE/DIFF:\n```\n{src[:6000]}\n```\n\n"
        f"FINDINGS: {json.dumps([{k: f[k] for k in ('id','name','sev','desc') if k in f} for f in analysis['findings']])}\n\n"
        "Return the remediated code as JSON."
    )
    try:
        return llm.complete_json(FIX_PROMPT, user)
    except Exception as e:  # network / quota / model - never break the gate
        fb = _fix_fallback(src, analysis)
        fb["engine"] = f"{MODEL} (fallback: {type(e).__name__})"
        logger.warning("Fix engine failed: %s: %s", type(e).__name__, e)
        return fb


def reason(src: str, analysis: dict) -> dict:
    """Call OpenAI GPT-5.6 to reason about the analyzer findings."""
    if not available():
        return _fallback(analysis)

    user = (
        f"CODE/DIFF:\n```\n{src[:6000]}\n```\n\n"
        f"DETERMINISTIC FINDINGS: {json.dumps([{k: f[k] for k in ('id','name','sev','cat')} for f in analysis['findings']])}\n"
        f"ANALYZER DECISION: {analysis['decision']} (composite {analysis['composite']}/100)\n\n"
        "Reason about intent and return the JSON verdict."
    )
    try:
        return llm.complete_json(SYSTEM_PROMPT, user)
    except Exception as e:  # model / network / quota - never break the gate
        fb = _fallback(analysis)
        fb["engine"] = f"{MODEL} (fallback: {type(e).__name__})"
        logger.warning("OpenAI reasoning failed: %s: %s", type(e).__name__, e)
        return fb
