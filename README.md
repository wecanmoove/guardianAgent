<p align="center"><b>GuardAgent Control Plane</b></p>

# GuardAgent Control Plane

**The AI security control plane for the agentic era - code gate, prompt firewall, auto-remediation and audit, powered by OpenAI GPT-5.6.**

GuardAgent Control Plane is the product evolution of [`guard-agent-test`](https://gitlab.com/syntaxsecure-group/guard-agent-test) - a GitLab-webhook DevSecOps bridge - rebuilt as a full **SOC + AppSec + AI Security Gate platform**. Built for the **OpenAI Build Week hackathon** (track: *Developer tools*) - see [`submission/DEVPOST.md`](submission/DEVPOST.md) and [`submission/CODEX_WORK.md`](submission/CODEX_WORK.md) for the new-vs-prior work log.

> For **defensive security testing and product development only**. Dashboard demo data is simulated; the analysis engine, GPT-5.6 reasoning, Prompt Shield, agent policy enforcement and audit persistence are real.

## What makes it different

Five engines, one control plane, one audit trail:

| Engine | What it does |
|---|---|
| **Code Gate** | 43-rule deterministic analyzer + GPT-5.6 intent reasoning -> Allow / Review / Block / Quarantine, mapped to MITRE ATT&CK |
| **Prompt-Injection Shield** | Runtime **AI firewall for agents**: screens every prompt, RAG document and tool output *before* the model sees it - 14 detectors (hijack, exfil, smuggling, tool-abuse, persona, recon) + GPT-5.6 intent pass -> PASS / SANITIZE / BLOCK, with a sanitized copy on SANITIZE |
| **AI Fix Engine** | GPT-5.6 rewrites flagged code with defects remediated (secrets -> env, TLS restored, queries parameterized) + change-by-change explanations; deterministic auto-patches offline |
| **Agent Execution Policy** | Every AI-agent tool call is evaluated before it runs: Executed / Sandboxed / Awaiting approval / Denied |
| **Posture Score** | Live 0-100 grade computed from gate, containment, shield and CISA-KEV exposure pillars |

Everything lands in the same SQLite audit trail with evidence IDs, streams to the dashboard over **SSE**, and exports as **SARIF 2.1.0** for GitHub code scanning.

## Quick start

**Static demo (no backend):** open `guardagent-control-plane.html` in a browser.

**Full platform (OpenAI GPT-5.6 live):**
```bash
pip install -r requirements.txt
cp .env.example .env # add OPENAI_API_KEY (optional - deterministic fallback without it)
uvicorn backend.main:app --port 8080
# open http://localhost:8080
```

**CLI - the security gate in your terminal or CI:**
```bash
python -m backend.cli scan app.py # code gate (exit 0/1/2/3 = Allow/Review/Block/Quarantine)
python -m backend.cli scan app.py --ai # + GPT-5.6 intent reasoning
python -m backend.cli scan app.py --sarif > r.sarif # SARIF 2.1.0 for GitHub code scanning
python -m backend.cli shield prompt.txt --source retrieved-doc # prompt-injection screen
python -m backend.cli deps requirements.txt # supply-chain / typosquat scan
```

**Tests:**
```bash
python -m pytest tests/ -v # runs fully offline (deterministic fallbacks)
```

**Autonomous agent loop:** `python -m backend.agent_runner --cycles 0 --interval 3`

**Deploy to Cloud Run:** `GOOGLE_CLOUD_PROJECT=your-project OPENAI_API_KEY=sk-... bash deploy/cloudrun.sh`

Platform support: Windows, macOS, Linux (Python 3.11+). On Windows, `truststore` is included for corporate TLS interception.

## API

| Endpoint | What it does |
|---|---|
| `POST /api/scan` | Code gate: deterministic analyzer + GPT-5.6 intent reasoning + evidence ID |
| `POST /api/scan/sarif` | Same analysis, emitted as **SARIF 2.1.0** |
| `POST /api/shield` | **Prompt-Injection Shield**: PASS / SANITIZE / BLOCK + sanitized copy |
| `POST /api/fix` | **AI Fix Engine**: remediated code + per-change explanations |
| `POST /api/deps` | Supply-chain scan: typosquats, near-miss names, unpinned / Git deps |
| `POST /api/agent/act` | Evaluate an AI-agent tool call against execution policy **before** it runs |
| `GET /api/posture` | Live 0-100 posture score with pillar breakdown |
| `GET /api/events` | **SSE stream** - scans, shield checks, agent actions, audit entries |
| `GET /api/kev` | Live CISA KEV threat feed (cached 6h) |
| `POST /scan` | GitLab webhook (HMAC verified) -> full pipeline |
| `GET /api/scans` - `/api/shield/checks` - `/api/agent/actions` - `/api/audit` - `/api/stats` - `/health` | Persisted evidence + liveness |

## OpenAI integration

All reasoning surfaces share one hardened client (`backend/llm.py`): strict-JSON completions on **`gpt-5.6`**, automatic degradation through the GPT-5 family if a model id is unavailable, one retry on transient errors, and a deterministic fallback so **the security gate never goes dark** - no key, no network, still a verdict.

## Dashboard modules

Executive Dashboard (live posture) - Commit Risk Triage - AI Code Inspection (GPT-5.6 verdicts + Fix Engine) - **Prompt-Injection Shield studio** - Pipeline Gate Center - Agent Security Console - Threat & Exposure Watch (live KEV) - NIST CSF 2.0 Governance - Resilience Maturity (ORMA) - Evidence & Audit Trail - all updating live over SSE.

## Detection layers

Hardcoded secrets (GitLab/AWS/Google/GitHub/Stripe/Slack/Twilio/JWT/PEM/signing keys) - typosquat + near-miss dependencies - eval/exec on input - SQL/OS-command/template injection (SSTI) - XXE - unsafe deserialization - encoded payloads piped to shell - env-read + egress exfiltration - TLS verification disabled - weak hashing / insecure randomness - debug servers exposed - permissive CORS - fragile Dockerfiles - CI policy drift - **prompt-injection markers - unvalidated LLM output executed - over-broad agent tool schemas** - mapped to MITRE ATT&CK, feeding one composite, explained decision.

## License

MIT.

---

*GuardAgent Control Plane v3.0 - policy pack v2026.07 - OpenAI GPT-5.6 reasoning core with deterministic fallback.*
