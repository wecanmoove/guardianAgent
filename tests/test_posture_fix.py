"""Tests for the posture score and the AI Fix Engine (deterministic path)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from backend import posture, reasoner, analyzer, store


@pytest.fixture(autouse=True)
def _db():
    store.init_db()


def test_posture_score_bounds():
    p = posture.compute()
    assert 0 <= p["score"] <= 100
    assert p["grade"] in ("A", "B", "C", "D", "E")
    assert set(p["pillars"]) == {"gate_effectiveness", "agent_containment",
                                 "shield_coverage", "exposure"}


def test_posture_pillars_bounded():
    p = posture.compute()
    for v in p["pillars"].values():
        assert 0 <= v <= 100


def test_fix_engine_autopatches_secret(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    import importlib
    importlib.reload(reasoner)
    code = 'api_key = "sk_live_0123456789abcdefABCD"\nrequests.get(u, verify=False)'
    analysis = analyzer.analyze(code)
    fix = reasoner.propose_fix(code, analysis)
    assert fix["engine"] == "deterministic-fallback"
    assert "os.environ" in fix["fixed_code"]
    assert "verify=True" in fix["fixed_code"]
    assert len(fix["changes"]) >= 1


def test_fix_engine_clean_code():
    code = "def add(a, b):\n    return a + b\n"
    analysis = analyzer.analyze(code)
    fix = reasoner.propose_fix(code, analysis)
    assert fix["fixed_code"] == code
    assert fix["changes"] == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
