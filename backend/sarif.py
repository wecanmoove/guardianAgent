"""SARIF 2.1.0 export.

Converts analyzer findings into the OASIS SARIF 2.1.0 format so GuardAgent
results drop straight into GitHub code scanning (the Security tab), VS Code's
SARIF viewer, or any SARIF-aware pipeline. This is what makes GuardAgent a
first-class developer tool rather than a bespoke dashboard.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""
from .analyzer import RULES, RULES_BY_ID

SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
VERSION = "2.1.0"
TOOL_VERSION = "3.0.0"
INFO_URI = "https://github.com/aleobois-arch/guardagent-control-plane"

# SARIF severity levels: error | warning | note (+ security-severity 0-10)
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_SECURITY_SEVERITY = {"critical": "9.5", "high": "7.5", "medium": "5.0", "low": "2.0"}


def _rules_catalog() -> list[dict]:
    """Every known rule as a SARIF reportingDescriptor (stable rule metadata)."""
    catalog = []
    seen = set()
    for r in list(RULES) + list(RULES_BY_ID.values()):
        if r.id in seen:
            continue
        seen.add(r.id)
        catalog.append({
            "id": r.id,
            "name": "".join(w.capitalize() for w in r.name.split()),
            "shortDescription": {"text": r.name},
            "fullDescription": {"text": r.desc},
            "defaultConfiguration": {"level": _LEVEL.get(r.sev, "warning")},
            "properties": {
                "category": r.cat,
                "severity": r.sev,
                "security-severity": _SECURITY_SEVERITY.get(r.sev, "5.0"),
                "tags": ["security", r.cat] + (r.mitre or []),
            },
        })
    return catalog


def _result(finding: dict, artifact_uri: str) -> dict:
    region = {}
    if finding.get("line"):
        region = {"startLine": finding["line"]}
        if finding.get("snippet"):
            region["snippet"] = {"text": finding["snippet"]}
    location = {"physicalLocation": {
        "artifactLocation": {"uri": artifact_uri},
        **({"region": region} if region else {})}}
    return {
        "ruleId": finding["id"],
        "level": _LEVEL.get(finding.get("sev", "medium"), "warning"),
        "message": {"text": finding.get("desc", finding.get("name", ""))},
        "locations": [location],
        "properties": {
            "security-severity": _SECURITY_SEVERITY.get(finding.get("sev", "medium"), "5.0"),
            "category": finding.get("cat", "code"),
            "mitre": finding.get("mitre", []),
        },
    }


def to_sarif(analysis: dict, artifact_uri: str = "input.snippet") -> dict:
    """Wrap one analyzer result as a complete SARIF 2.1.0 log."""
    results = [_result(f, artifact_uri) for f in analysis.get("findings", [])]
    return {
        "$schema": SCHEMA,
        "version": VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": "GuardAgent",
                "informationUri": INFO_URI,
                "version": TOOL_VERSION,
                "rules": _rules_catalog(),
            }},
            "results": results,
            "properties": {
                "decision": analysis.get("decision"),
                "composite": analysis.get("composite"),
                "summary": analysis.get("why"),
            },
        }],
    }
