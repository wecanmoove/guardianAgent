"""GuardAgent Control Plane — FastAPI backend.

Evolution of guard-agent-test's webhook bridge into a full control plane:
  - keeps the signed GitLab webhook DNA (HMAC-SHA256 verification)
  - adds a real /api/scan analysis endpoint (deterministic + OpenAI GPT-5.6)
  - adds an AI-agent policy enforcement endpoint (/api/agent/act)
  - persists everything to SQLite for the audit trail / judge evidence
  - serves the single-file dashboard UI

Run:  uvicorn backend.main:app --reload --port 8080
"""
import base64
import hashlib
import hmac
import json
import os

import asyncio

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from . import store, analyzer, reasoner, agent_policy, kev, shield, deps, posture, sarif

app = FastAPI(title="GuardAgent Control Plane", version="3.0.0")
store.init_db()

GITLAB_WEBHOOK_SECRET = os.environ.get("GITLAB_WEBHOOK_SECRET")
UI_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "guardagent-control-plane.html")


# ----------------------------------------------------------------- webhook DNA
def verify_gitlab_signature(signing_token, message_id, timestamp, body, signature_header) -> bool:
    try:
        raw_key = base64.b64decode(signing_token.removeprefix("whsec_"))
        message = f"{message_id}.{timestamp}.{body}".encode()
        digest = hmac.new(raw_key, message, hashlib.sha256).digest()
        expected = "v1," + base64.b64encode(digest).decode()
        return any(hmac.compare_digest(expected, sig) for sig in signature_header.split(" "))
    except Exception:
        return False


# --------------------------------------------------------------------- models
class ScanRequest(BaseModel):
    code: str
    repo: str = "adhoc"
    branch: str = "-"
    author: str = "inspector"
    sha: str = "adhoc"


class AgentActRequest(BaseModel):
    agent: str
    action: str
    tool: str


class ShieldRequest(BaseModel):
    content: str
    source: str = "user-prompt"   # user-prompt | retrieved-doc | tool-output


class FixRequest(BaseModel):
    code: str


class DepsRequest(BaseModel):
    manifest: str


# -------------------------------------------------------------- core pipeline
def run_scan(code: str, meta: dict) -> dict:
    """Deterministic analysis + OpenAI reasoning + persistence."""
    analysis = analyzer.analyze(code)
    verdict = reasoner.reason(code, analysis)

    decision = verdict.get("verdict", analysis["decision"])
    sev = ("critical" if decision in ("Block", "Quarantine")
           else "medium" if decision == "Review" else "low")

    scan_id = store.record_scan(
        sha=meta.get("sha"), repo=meta.get("repo"), branch=meta.get("branch"),
        author=meta.get("author"), threat=verdict.get("threat_class", "Unknown"),
        sev=sev, conf=verdict.get("confidence", 0.8), decision=decision,
        engine=verdict.get("engine", "deterministic"), files=meta.get("files", []),
        summary=verdict.get("summary", analysis["why"]),
        rules=[f"{f['id']} {f['name']}" for f in analysis["findings"]],
        mitre=analysis["mitre"], diff=code[:2000], composite=analysis["composite"])

    ev = store.record_audit(
        trigger_kind=meta.get("trigger", "manual scan"),
        subject=f"{meta.get('repo')} @ {meta.get('sha')}",
        policy=", ".join(f["id"] for f in analysis["findings"][:3]) or "FP-002",
        decision=decision)

    return {"scan_id": scan_id, "evidence": ev, "decision": decision,
            "analysis": analysis, "reasoning": verdict}


# ------------------------------------------------------------------- endpoints
@app.get("/")
async def root():
    return FileResponse(UI_PATH) if os.path.exists(UI_PATH) else {"status": "ok"}


@app.get("/health")
async def health():
    return {"status": "ok", "openai": reasoner.available(), "model": reasoner.MODEL,
            "modules": ["scan", "fix", "shield", "deps", "posture", "kev", "events"],
            **store.stats()}


@app.post("/api/scan")
async def api_scan(req: ScanRequest):
    """Ad-hoc analysis (used by the AI Code Inspection studio)."""
    return run_scan(req.code, {"repo": req.repo, "branch": req.branch,
                               "author": req.author, "sha": req.sha,
                               "trigger": "code inspection"})


@app.post("/api/agent/act")
async def api_agent_act(req: AgentActRequest):
    """Evaluate an AI agent tool call against execution policy BEFORE it runs."""
    r = agent_policy.evaluate(req.agent, req.action, req.tool)
    store.record_agent_action(req.agent, req.action, req.tool, r.risk, r.policy, r.outcome)
    store.record_audit("agent tool call", f"{req.agent} · {req.tool}",
                       r.policy.split(" ")[1] if " " in r.policy else "POL-AGT",
                       r.outcome)
    return {"outcome": r.outcome, "policy": r.policy, "risk": r.risk, "cls": r.cls}


@app.get("/api/scans")
async def api_scans(limit: int = 50):
    return store.list_scans(limit)


@app.get("/api/agent/actions")
async def api_agent_actions(limit: int = 100):
    return store.list_agent_actions(limit)


@app.get("/api/audit")
async def api_audit(limit: int = 200):
    return store.list_audit(limit)


@app.get("/api/stats")
async def api_stats():
    return store.stats()


@app.post("/api/shield")
async def api_shield(req: ShieldRequest):
    """Prompt-Injection Shield: screen content BEFORE it reaches an AI agent.

    Verdicts: PASS | SANITIZE (sanitized copy returned) | BLOCK."""
    result = shield.inspect(req.content, req.source)
    store.record_shield_check(
        source=req.source, verdict=result["verdict"],
        attack_class=result["reasoning"].get("attack_class", "Unknown"),
        composite=result["screen"]["composite"],
        engine=result["reasoning"].get("engine", "deterministic"),
        detectors=[h["id"] for h in result["screen"]["hits"]],
        excerpt=req.content)
    store.record_audit("shield check", f"{req.source} ({len(req.content)} chars)",
                       ", ".join(h["id"] for h in result["screen"]["hits"][:3]) or "PIS-000",
                       result["verdict"])
    return result


@app.get("/api/shield/checks")
async def api_shield_checks(limit: int = 100):
    return store.list_shield_checks(limit)


@app.post("/api/fix")
async def api_fix(req: FixRequest):
    """AI Fix Engine: analyze then generate the remediated version of the code."""
    analysis = analyzer.analyze(req.code)
    fix = reasoner.propose_fix(req.code, analysis)
    store.record_audit("fix proposal", f"{len(analysis['findings'])} finding(s)",
                       ", ".join(f["id"] for f in analysis["findings"][:3]) or "FP-000",
                       f"remediation ({fix.get('residual_risk', '?')} residual)")
    return {"analysis": analysis, "fix": fix}


@app.post("/api/scan/sarif")
async def api_scan_sarif(req: ScanRequest):
    """Analyze and return findings as SARIF 2.1.0 — drops into GitHub code
    scanning, VS Code's SARIF viewer, or any SARIF-aware CI pipeline."""
    analysis = analyzer.analyze(req.code)
    return JSONResponse(sarif.to_sarif(analysis, artifact_uri=req.repo or "input.snippet"))


@app.post("/api/deps")
async def api_deps(req: DepsRequest):
    """Supply-chain scan of a dependency manifest (requirements.txt / package.json)."""
    result = deps.scan(req.manifest)
    store.record_audit("dependency scan", f"{result['packages']} package(s)",
                       ", ".join(f["id"] for f in result["findings"][:3]) or "DEP-000",
                       result["decision"])
    return result


@app.get("/api/posture")
async def api_posture():
    """Aggregate 0-100 security posture score with per-pillar breakdown."""
    return posture.compute()


@app.get("/api/events")
async def api_events():
    """Server-sent events: pushes new scans / agent actions / shield checks /
    audit entries as they land, so every dashboard module updates live."""
    async def stream():
        last = {"scan": 0, "action": 0, "audit": 0, "shield": 0}
        for kind, rows in (("scan", store.list_scans(1)), ("action", store.list_agent_actions(1)),
                           ("audit", store.list_audit(1)), ("shield", store.list_shield_checks(1))):
            last[kind] = rows[0]["id"] if rows else 0
        yield "event: hello\ndata: {}\n\n"
        while True:
            await asyncio.sleep(2)
            batches = (("scan", store.list_scans(10)), ("action", store.list_agent_actions(10)),
                       ("audit", store.list_audit(10)), ("shield", store.list_shield_checks(10)))
            for kind, rows in batches:
                fresh = [r for r in rows if r["id"] > last[kind]]
                for r in reversed(fresh):
                    yield f"event: {kind}\ndata: {json.dumps(r)}\n\n"
                if fresh:
                    last[kind] = max(r["id"] for r in fresh)
    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/kev")
async def api_kev(limit: int = 40, cat: str | None = None, ransomware: bool = False):
    """Live CISA KEV catalog, classified by DB engine / OS layer.

    Powers the Threat & Exposure Watch module. Cached server-side (6h)."""
    data = kev.get_kev()
    entries = data.get("entries", [])
    if cat:
        entries = [e for e in entries if e["cat"] == cat]
    if ransomware:
        entries = [e for e in entries if e["ransomware"]]
    return {**{k: data[k] for k in ("ok", "error", "total", "catalogVersion", "counts")},
            "dateReleased": data.get("dateReleased"),
            "stale": data.get("stale", False),
            "entries": entries[:max(1, min(limit, 200))]}


@app.post("/scan")
async def scan(request: Request, background_tasks: BackgroundTasks):
    """GitLab webhook entry point (HMAC-verified) — the original DNA, now
    routed through the full control-plane pipeline."""
    secret = GITLAB_WEBHOOK_SECRET
    if not secret:
        raise HTTPException(status_code=500, detail="Webhook secret not set")

    sig_header = request.headers.get("webhook-signature")
    raw_body = await request.body()

    if sig_header:
        if not verify_gitlab_signature(secret, request.headers.get("webhook-id"),
                                       request.headers.get("webhook-timestamp"),
                                       raw_body.decode(), sig_header):
            raise HTTPException(status_code=401, detail="Invalid Signature")
    elif request.headers.get("X-Gitlab-Token") != secret:
        raise HTTPException(status_code=401, detail="Unauthorized")

    payload = json.loads(raw_body)
    if payload.get("object_kind") != "push":
        return {"status": "ignored"}

    commit_sha = payload.get("after")
    if not commit_sha or commit_sha == "0" * 40:
        return {"status": "no_commit"}

    repo_name = payload.get("repository", {}).get("name", "unknown")
    changed = []
    for c in payload.get("commits", []):
        changed.extend(c.get("added", []))
        changed.extend(c.get("modified", []))
    changed = list(set(changed))
    if not changed:
        return {"status": "no_files_to_scan"}

    # In production the agent fetches file content via GitLab MCP; here we scan
    # the commit message + file list as the available signal, then hand off.
    signal = payload.get("commits", [{}])[0].get("message", "") + "\n" + "\n".join(changed)
    background_tasks.add_task(run_scan, signal, {
        "repo": repo_name, "sha": commit_sha[:8], "branch": payload.get("ref", "").split("/")[-1],
        "author": payload.get("user_username", "unknown"), "files": changed, "trigger": "webhook push"})

    return {"status": "analysis_started", "commit": commit_sha[:8], "files": len(changed)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
