"""Gemini 2.5 Flash reasoning layer (Google Cloud).

This is the "cognitive engine" the original guard-agent-test delegated to
Dialogflow CX. Here we call Gemini directly (Vertex AI or the Gemini API)
so the semantic reasoning is first-class, testable, and logged.

Gemini runs as a SECOND pass on top of the deterministic analyzer:
  1. analyzer.py finds keyword/pattern signals (fast, explainable).
  2. Gemini reasons about INTENT — is this actually malicious, is it a
     false positive, what is the developer-facing explanation and fix.

If no API key is configured the module degrades gracefully to a
deterministic "reasoning" string so the demo always runs offline.
"""
import json
import os

MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
_API_KEY = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
_USE_VERTEX = os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "").lower() in ("1", "true", "yes")

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
    return bool(_API_KEY) or _USE_VERTEX


def _fallback(analysis: dict) -> dict:
    """Deterministic stand-in when Gemini is not configured."""
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


def reason(src: str, analysis: dict) -> dict:
    """Call Gemini 2.5 Flash to reason about the analyzer findings."""
    if not available():
        return _fallback(analysis)

    user = (
        f"CODE/DIFF:\n```\n{src[:6000]}\n```\n\n"
        f"DETERMINISTIC FINDINGS: {json.dumps([{k: f[k] for k in ('id','name','sev','cat')} for f in analysis['findings']])}\n"
        f"ANALYZER DECISION: {analysis['decision']} (composite {analysis['composite']}/100)\n\n"
        "Reason about intent and return the JSON verdict."
    )
    try:
        from google import genai
        from google.genai import types

        client = (genai.Client(vertexai=True,
                               project=os.environ.get("GOOGLE_CLOUD_PROJECT"),
                               location=os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1"))
                  if _USE_VERTEX else genai.Client(api_key=_API_KEY))

        resp = client.models.generate_content(
            model=MODEL,
            contents=user,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.1,
                response_mime_type="application/json",
            ),
        )
        data = json.loads(resp.text)
        data["engine"] = MODEL
        return data
    except Exception as e:  # network / quota / parse — never break the gate
        fb = _fallback(analysis)
        fb["engine"] = f"{MODEL} (fallback: {type(e).__name__})"
        return fb
