"""Test OpenAI reasoner fallback (deterministic mode without API key)."""
import sys
import os
from pathlib import Path

# Ensure backend is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from backend import reasoner, analyzer


@pytest.fixture
def sample_analysis():
    """A minimal analyzer output fixture."""
    return {
        "decision": "Review",
        "why": "Potential credential exposure detected.",
        "composite": 45,
        "findings": [
            {
                "id": "SEC-001",
                "name": "Hardcoded secret",
                "weight": 70,
                "sev": "high",
                "cat": "credentials",
                "desc": "Remove hardcoded API key from source.",
            }
        ],
        "mitre": ["T1552.001"],
    }


def test_reasoner_fallback_no_api_key(sample_analysis, monkeypatch):
    """With no OPENAI_API_KEY, reasoner should return deterministic fallback."""
    # Ensure no API key is set
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    # Reload the module to pick up the env change
    import importlib
    importlib.reload(reasoner)

    # Call reasoner with no key set
    result = reasoner.reason("print('secret_key')", sample_analysis)

    # Should return deterministic fallback
    assert result["engine"] == "deterministic-fallback"
    assert result["verdict"] == "Review"
    assert result["threat_class"] == "Hardcoded secret"
    assert "confidence" in result
    assert 0.0 <= result["confidence"] <= 1.0
    assert result["false_positive_risk"] in ("low", "medium", "high")
    assert "summary" in result
    assert "remediation" in result


def test_reasoner_structure_no_api_key(sample_analysis, monkeypatch):
    """Fallback verdict should always have required JSON keys."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    import importlib
    importlib.reload(reasoner)

    result = reasoner.reason("some code", sample_analysis)

    required_keys = {
        "verdict",
        "confidence",
        "threat_class",
        "summary",
        "false_positive_risk",
        "remediation",
        "engine",
    }
    assert required_keys.issubset(result.keys()), f"Missing keys: {required_keys - result.keys()}"


def test_reasoner_available():
    """available() should return False when no API key is configured."""
    import importlib
    # This test assumes OPENAI_API_KEY is not set in test environment
    importlib.reload(reasoner)
    if os.environ.get("OPENAI_API_KEY"):
        pytest.skip("OPENAI_API_KEY is set; skipping fallback test")
    assert reasoner.available() == False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
