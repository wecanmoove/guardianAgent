"""Security Posture Score - one number the CISO can watch.

Aggregates every signal the platform already produces into a 0-100 score
with a letter grade and per-pillar breakdown:

  gate effectiveness   are risky commits actually being caught and blocked
  agent containment    are agent policy denials working (denied/sandboxed ratio)
  shield coverage      prompt-injection screening activity and block rate
  exposure             live CISA KEV pressure relevant to the stack

Deterministic, computed from the SQLite store + KEV cache - no AI calls, so
it is always available and always explainable.
"""
import time

from . import store, kev


GRADES = [(90, "A"), (80, "B"), (70, "C"), (55, "D"), (0, "E")]


def _grade(score: float) -> str:
    return next(g for floor, g in GRADES if score >= floor)


def compute() -> dict:
    s = store.stats()
    scans, blocked = s["scans"], s["blocked"]
    actions, denied = s["agent_actions"], s["denied"]
    shield_total = s.get("shield_checks", 0)
    shield_blocked = s.get("shield_blocked", 0)

    # Gate effectiveness: catching something is evidence the gate works;
    # an idle gate scores neutral, a busy gate that never blocks is suspicious.
    if scans == 0:
        gate = 60.0
    else:
        block_rate = blocked / scans
        gate = 55 + 45 * min(1.0, block_rate / 0.25) if block_rate > 0 else 45.0

    # Agent containment: policy engine exercising DENY/SANDBOX proves the
    # enforcement point is live.
    if actions == 0:
        containment = 60.0
    else:
        deny_rate = denied / actions
        containment = 55 + 45 * min(1.0, deny_rate / 0.20) if deny_rate > 0 else 50.0

    # Shield coverage: any screening activity raises the pillar; blocks prove it.
    if shield_total == 0:
        shield_score = 50.0
    else:
        shield_score = 70 + 30 * min(1.0, shield_blocked / max(1, shield_total) / 0.30)

    # Exposure: ransomware-weighted KEV pressure (live feed, cached 6h).
    exposure = 70.0
    kev_note = "KEV feed unavailable - neutral exposure assumed."
    try:
        data = kev.get_kev()
        entries = data.get("entries", [])
        if entries:
            recent = [e for e in entries[:60]]
            ransom = sum(1 for e in recent if e.get("ransomware"))
            exposure = max(30.0, 90.0 - ransom * 1.5)
            kev_note = (f"{len(recent)} recent KEV entries assessed, "
                        f"{ransom} ransomware-associated.")
    except Exception:
        pass

    pillars = {
        "gate_effectiveness": round(gate, 1),
        "agent_containment": round(containment, 1),
        "shield_coverage": round(shield_score, 1),
        "exposure": round(exposure, 1),
    }
    weights = {"gate_effectiveness": 0.3, "agent_containment": 0.3,
               "shield_coverage": 0.2, "exposure": 0.2}
    score = round(sum(pillars[k] * weights[k] for k in pillars), 1)

    return {
        "score": score,
        "grade": _grade(score),
        "pillars": pillars,
        "inputs": {**s, "kev_note": kev_note},
        "computed_at": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
    }
