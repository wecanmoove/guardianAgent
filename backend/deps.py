"""Supply-chain dependency scanner.

Parses a dependency manifest (requirements.txt / package.json / pyproject
snippets) and flags:
 - exact typosquats from the analyzer's known-bad list
 - lexical near-misses of the most-installed packages (edit distance 1-2)
 - unpinned versions, git/HTTP direct references, wildcard ranges

Pure stdlib, deterministic, offline - the same explainability contract as
analyzer.py.
"""
import json
import re

from .analyzer import TYPOSQUATS

# Most-installed package names (squat targets). Compact but high-coverage.
POPULAR = [
    "requests", "urllib3", "numpy", "pandas", "django", "flask", "fastapi",
    "cryptography", "boto3", "botocore", "setuptools", "pydantic", "pytest",
    "pillow", "sqlalchemy", "scikit-learn", "matplotlib", "beautifulsoup4",
    "python-dateutil", "colorama", "openai", "httpx", "aiohttp", "jinja2",
    "click", "rich", "uvicorn", "tensorflow", "torch", "opencv-python",
    "react", "lodash", "express", "axios", "chalk", "commander", "webpack",
    "typescript", "eslint", "vite", "next", "vue",
]
_POPULAR_SET = set(POPULAR)


def _edit_distance(a: str, b: str, cap: int = 3) -> int:
    """Bounded Levenshtein - early-exits above `cap`."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[-1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]


def _parse(manifest: str) -> list[dict]:
    """Extract (name, spec) pairs from requirements.txt or package.json text."""
    pkgs = []
    txt = manifest.strip()
    if txt.startswith("{"):  # package.json
        try:
            data = json.loads(txt)
            for section in ("dependencies", "devDependencies"):
                for name, spec in (data.get(section) or {}).items():
                    pkgs.append({"name": name.lower(), "spec": str(spec), "eco": "npm"})
            return pkgs
        except json.JSONDecodeError:
            pass
    for line in txt.splitlines():  # requirements.txt style
        line = line.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9._\[\]-]+)\s*(.*)$", line)
        if m:
            pkgs.append({"name": m.group(1).split("[")[0].lower(),
                         "spec": m.group(2).strip(), "eco": "pypi"})
    return pkgs


def scan(manifest: str) -> dict:
    """Scan a manifest. Returns per-package findings + composite risk."""
    pkgs = _parse(manifest)
    findings = []
    for p in pkgs:
        name, spec = p["name"], p["spec"]
        if name in TYPOSQUATS:
            findings.append({**p, "id": "DEP-001", "sev": "critical",
                             "issue": f"Known typosquat of '{TYPOSQUATS[name]}'",
                             "fix": f"Replace with the canonical package '{TYPOSQUATS[name]}'."})
            continue
        if name not in _POPULAR_SET:
            near = [t for t in POPULAR if _edit_distance(name, t, 2) <= (1 if len(t) <= 6 else 2)]
            if near:
                findings.append({**p, "id": "DEP-002", "sev": "high",
                                 "issue": f"Lexically adjacent to popular package '{near[0]}'",
                                 "fix": f"Verify intent - did you mean '{near[0]}'?"})
                continue
        if re.search(r"git\+|https?://", spec):
            findings.append({**p, "id": "DEP-010", "sev": "high",
                             "issue": "Resolves from a raw Git/HTTP URL, not a registry release",
                             "fix": "Pin to a checksummed registry version."})
        elif spec in ("", "*", "latest") or spec.startswith("^") or spec.startswith("~"):
            findings.append({**p, "id": "DEP-020", "sev": "medium",
                             "issue": "Unpinned or floating version range",
                             "fix": "Pin an exact version and manage upgrades explicitly."})
    n_crit = sum(1 for f in findings if f["sev"] == "critical")
    n_high = sum(1 for f in findings if f["sev"] == "high")
    composite = min(100, n_crit * 40 + n_high * 20 +
                    sum(8 for f in findings if f["sev"] == "medium"))
    decision = ("Quarantine" if n_crit else "Block" if n_high >= 2
                else "Review" if findings else "Allow")
    return {"packages": len(pkgs), "findings": findings,
            "composite": composite, "decision": decision}
