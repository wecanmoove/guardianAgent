# New work vs. prior work — OpenAI Build Week Hackathon

Per the hackathon rules for pre-existing projects, this document distinguishes
what existed before the Submission Period from what was built during it, and
where Codex / GPT-5.6 was used. Judges should evaluate the **new work** section.

## Prior work (before the Submission Period)

Built originally around a Gemini reasoning layer for a different event:

- `backend/main.py` — FastAPI app, GitLab webhook (HMAC), `/api/scan`, agent-act endpoint
- `backend/analyzer.py` — deterministic static-analysis engine (36 rules at the time)
- `backend/agent_policy.py` — agent execution-policy engine
- `backend/agent_runner.py` — autonomous agent loop
- `backend/store.py` — SQLite persistence (scans, agent actions, audit)
- `backend/kev.py` — CISA KEV feed
- `guardagent-control-plane.html` — single-file dashboard (8 modules)

## New work (Submission Period — July 2026)

**Full migration to the OpenAI stack, then a major capability expansion.**
See dated commit history for timestamps; each bullet lists the new files.

1. **OpenAI GPT-5.6 reasoning core** — replaced the previous provider entirely.
   - `backend/llm.py` (new): shared client, strict-JSON completions on `gpt-5.6`,
     model-fallback chain, retry, offline deterministic fallback.
   - `backend/reasoner.py` (new): intent reasoning + **AI Fix Engine**
     (`propose_fix` — remediated code + per-change explanations).
2. **Prompt-Injection Shield** — `backend/shield.py` (new): runtime AI firewall
   for agentic traffic; 14 detectors (hijack / exfil / smuggling / tool-abuse /
   persona / recon) + GPT-5.6 intent pass; PASS / SANITIZE / BLOCK; sanitizer
   strips fake delimiter blocks and invisible characters. `/api/shield`,
   `/api/shield/checks`, new `shield_checks` table + dashboard studio module.
3. **SARIF 2.1.0 export** — `backend/sarif.py` (new) + `POST /api/scan/sarif`:
   findings drop into GitHub code scanning / VS Code SARIF viewers.
4. **GuardAgent CLI** — `backend/cli.py` (new): `scan | shield | deps`
   subcommands, `--sarif`, `--ai`, `--strict`, CI-grade exit codes (0/1/2/3/4).
5. **Supply-chain scanner** — `backend/deps.py` (new): known typosquats,
   edit-distance near-miss detection against popular packages, unpinned/Git
   deps; `POST /api/deps`.
6. **Security Posture Score** — `backend/posture.py` (new): live 0–100 grade
   from gate / containment / shield / KEV-exposure pillars; `GET /api/posture`;
   live ring on the Executive Dashboard.
7. **SSE live event stream** — `GET /api/events`: scans, shield checks, agent
   actions and audit entries push to the dashboard in real time.
8. **Analyzer expansion** — 36 → 43 rules, including agentic-AI classes new
   this period: unvalidated LLM output executed (AGT-010), over-broad agent
   tool schemas (AGT-012), SSTI, XXE, hardcoded signing secrets.
9. **Test suite** — `tests/` (new): 30+ pytest cases covering the reasoner,
   shield, fix engine, deps scanner, posture, SARIF and CLI — all runnable
   offline via the deterministic fallbacks.
10. **Docs / deploy** — README rewritten around the OpenAI stack; Cloud Run
    deploy script migrated to `OPENAI_API_KEY` via Secret Manager.

## How Codex + GPT-5.6 were used

- **Codex** drove the migration and the new modules end-to-end in agentic
  sessions: multi-file refactors (Gemini → OpenAI), new module scaffolding,
  test generation, and iterative fix loops against the running server.
  Codex session ID: *(paste `/feedback` session ID here before submitting)*.
- **GPT-5.6 at runtime** is the product's reasoning engine: code-intent
  verdicts, prompt-injection intent analysis, and code remediation — all with
  strict-JSON contracts and deterministic fallbacks.

## Third-party integrations

- **OpenAI API** — commercial API, used under OpenAI's terms.
- **CISA KEV** — public U.S. government feed (no license restrictions).
- **FastAPI / uvicorn / pydantic / pytest / truststore** — OSS (MIT/BSD/Apache).

## Defensive-only boundary

GuardAgent analyzes code its operators are authorized to scan, screens content
destined for their own agents, and enforces policy on their own automation. It
contains no scanning, exploitation or offensive capability.
