<p align="center"><b>GuardAgent Control Plane</b></p>

# GuardAgent Control Plane

**AI Security Control Plane — from risky commit to understood risk to remediation, operated by AI agents on Google Cloud.**

GuardAgent Control Plane is the product evolution of [`guard-agent-test`](https://gitlab.com/syntaxsecure-group/guard-agent-test) — a GitLab-webhook DevSecOps bridge — rebuilt as a full **SOC + AppSec + AI Security Gate platform**: a real FastAPI backend with **Gemini 2.5 Flash** reasoning, an AI-agent execution-policy engine, an immutable audit trail, and a premium single-file dashboard. Built for the **XPRIZE Digital Learning / Devpost "AI business" hackathon** (category: *Small Business Services*) — see [`submission/DEVPOST.md`](submission/DEVPOST.md).

> ⚠️ For **defensive security testing and product development only**. Dashboard demo data is simulated; the analysis engine, Gemini reasoning, agent policy enforcement and audit persistence are real.

## Architecture — original vs. this repo

| | `guard-agent-test` (origin) | **GuardAgent Control Plane** |
|---|---|---|
| Webhook bridge (HMAC-verified `/scan`) | ✅ FastAPI on Cloud Run | ✅ kept, same dual verification |
| AI reasoning | Dialogflow CX agent (logic lives in GCP console, not in repo) | ✅ **Gemini 2.5 Flash in-repo** (`backend/gemini.py`) — auditable, testable |
| Deterministic analysis | ❌ (delegated to agent prompt) | ✅ 18-rule multi-layer engine (`backend/analyzer.py`) |
| Persistence / audit trail | ❌ | ✅ SQLite: scans, agent actions, evidence IDs |
| AI-agent guardrails | ❌ | ✅ execution-policy engine (`backend/agent_policy.py`) |
| Autonomous business operations | ❌ | ✅ agent loop: triage, remediation, onboarding, billing, support (`backend/agent_runner.py`) |
| UI | ❌ | ✅ 8-module SOC dashboard (single HTML file) |
| Google Cloud | Cloud Run, Agent Builder, Secret Manager | Cloud Run, **Vertex AI (Gemini)**, Secret Manager, Cloud Build |

## Quick start

**Static demo (no backend):** open `guardagent-control-plane.html` in a browser. The inspection studio falls back to the in-browser analyzer.

**Full platform (Gemini live):**
```bash
pip install -r requirements.txt
cp .env.example .env           # add GEMINI_API_KEY (or use Vertex AI mode)
uvicorn backend.main:app --port 8080
# open http://localhost:8080  — the same UI, now wired to the live engine
```

**Autonomous agent loop (the AI that operates the business):**
```bash
python -m backend.agent_runner --cycles 0 --interval 3
```

**Deploy to Google Cloud Run:**
```bash
GOOGLE_CLOUD_PROJECT=your-project bash deploy/cloudrun.sh
```

## API

| Endpoint | What it does |
|---|---|
| `POST /scan` | GitLab webhook (HMAC / token verified) → full analysis pipeline |
| `POST /api/scan` | Ad-hoc scan: deterministic analyzer + Gemini intent reasoning → Allow / Review / Block / Quarantine + evidence ID |
| `POST /api/agent/act` | Evaluate an AI-agent tool call against execution policy **before** it runs |
| `GET /api/scans` · `/api/agent/actions` · `/api/audit` · `/api/stats` | Persisted evidence for dashboards & judges |
| `GET /health` | Liveness + Gemini availability + counters |

## Dashboard modules

Executive Dashboard · Commit Risk Triage · AI Code Inspection (live Gemini verdicts) · Pipeline Gate Center · Agent Security Console · Threat & Exposure Watch · NIST CSF 2.0 Governance Center · Evidence & Audit Trail (JSON/CSV export).

## Detection layers

Hardcoded secrets (GitLab PAT, AWS, Stripe, generic) · typosquatted dependencies · `eval`/`exec` on dynamic input · unsafe deserialization · encoded payloads piped to shell · env-var bulk-read + external send (exfiltration) · fragile Dockerfiles · CI policy drift (`allow_failure`, `when: always`) · prompt-injection markers · agent self-privilege language — each mapped to MITRE ATT&CK where applicable, feeding a composite score and an explained decision.

## Hackathon submission (XPRIZE / Devpost)

Everything the rules require lives in [`submission/`](submission/):
[`DEVPOST.md`](submission/DEVPOST.md) (checklist + category) · [`NARRATIVE.md`](submission/NARRATIVE.md) (500–1000-word draft) · [`VIDEO_SCRIPT.md`](submission/VIDEO_SCRIPT.md) (3-min shot list) · [`EVIDENCE.md`](submission/EVIDENCE.md) (agent logs & API-usage proof) · [`PL_TEMPLATE.md`](submission/PL_TEMPLATE.md) · [`REVENUE_EVIDENCE.md`](submission/REVENUE_EVIDENCE.md) · [`EXPENSES.md`](submission/EXPENSES.md) · [`CUSTOMERS.md`](submission/CUSTOMERS.md).

**Rules compliance:** business operated by AI agents ✅ (policy-gated triage / remediation / onboarding / billing / support agents) · at least one Google Cloud product ✅ (Vertex AI Gemini 2.5 Flash, Cloud Run, Secret Manager, Cloud Build).

## License

MIT.

---

*GuardAgent Control Plane — policy pack v2026.07 · Gemini 2.5 Flash reasoning core with deterministic fallback.*
