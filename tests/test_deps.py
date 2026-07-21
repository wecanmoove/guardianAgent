"""Tests for the supply-chain dependency scanner."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from backend import deps


def test_detects_known_typosquat():
    r = deps.scan("reqeusts==2.31.0\n")
    assert r["decision"] == "Quarantine"
    assert r["findings"][0]["id"] == "DEP-001"


def test_detects_near_miss():
    r = deps.scan("nunpy\n")
    ids = [f["id"] for f in r["findings"]]
    assert "DEP-002" in ids or "DEP-001" in ids


def test_flags_git_url_dependency():
    r = deps.scan("mypkg @ git+https://github.com/a/b.git\n")
    assert any(f["id"] == "DEP-010" for f in r["findings"])


def test_flags_unpinned():
    r = deps.scan("requests\n")
    assert any(f["id"] == "DEP-020" for f in r["findings"])


def test_clean_manifest_allows():
    r = deps.scan("requests==2.31.0\nnumpy==1.26.0\n")
    assert r["decision"] == "Allow"
    assert r["findings"] == []


def test_parses_package_json():
    manifest = '{"dependencies": {"lodahs": "^4.0.0", "express": "4.18.2"}}'
    r = deps.scan(manifest)
    assert r["packages"] == 2
    assert any(f["name"] == "lodahs" for f in r["findings"])


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
