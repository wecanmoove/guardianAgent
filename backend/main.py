"""GuardAgent Control Plane — FastAPI backend.

Evolution of guard-agent-test's webhook bridge into a full control plane:
  - keeps the signed GitLab webhook DNA (HMAC-SHA256 verification)
  - adds a real /api/scan analysis endpoint (deterministic + Gemini 2.5 Flash)
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

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from . import store, analyzer, gemini, agent_policy, kev

app = FastAPI(title="GuardAgent Control Plane", version="2.0.0")
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


# -------------------------------------------------------------- core pipeline
def run_scan(code: str, meta: dict) -> dict:
    """Deterministic analysis + Gemini reasoning + persistence."""
    analysis = analyzer.analyze(code)
    verdict = gemini.reason(code, analysis)

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
    return {"status": "ok", "gemini": gemini.available(), "model": gemini.MODEL, **store.stats()}


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
