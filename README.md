# GuardAgent Control Plane

**AI Security Control Plane — from risky commit to understood risk to remediation.**

GuardAgent Control Plane is the product evolution of [`guard-agent-test`](https://gitlab.com/syntaxsecure-group/guard-agent-test) — a GitLab-webhook DevSecOps bridge (FastAPI `/scan` endpoint, HMAC webhook verification, diff collection, AI security reasoning) — rebuilt as a full SOC + AppSec + AI Security Gate platform prototype for 2026.

> ⚠️ Demo / prototype for **defensive security testing and product design only**. All data is simulated. The code inspector runs real client-side static heuristics, but no backend is required.

## Try it

Open **`guardagent-control-plane.html`** in any modern browser. No build step, no dependencies, no backend.

## Modules

| Module | Purpose |
|---|---|
| **Executive Dashboard** | Posture score, scan volume, blocked pipelines, SLA debt, live critical events |
| **Commit Risk Triage** | Webhook-scanned commits ranked by composite risk, with full AI reasoning trace, diff excerpt, rules and MITRE ATT&CK mapping |
| **AI Code Inspection** | Paste code / diff / Dockerfile / CI YAML / requirements.txt — a real client-side multi-layer analyzer (secrets, typosquats, injection, obfuscation, exfiltration paths, CI policy drift, prompt injection) produces an Allow / Review / Block / Quarantine verdict |
| **Pipeline Gate Center** | Policy-as-code meets AI reasoning: every stage decision is explained, with the unblock path |
| **Agent Security Console** | AI agents as monitored actors: tool-call policy evaluation, sandbox status, denied operations, decision timeline |
| **Threat & Exposure Watch** | Internet exposure, KEV / ransomware-linked alerts, patch debt, backup & restore assurance |
| **NIST Governance Center** | Every finding mapped to NIST CSF 2.0 (Govern / Identify / Protect / Detect / Respond / Recover) with owner, SLA and evidence |
| **Evidence & Audit Trail** | Immutable decision log with JSON / CSV export, built for internal audit and CISO reporting |

## DNA kept from `guard-agent-test`

- Push-triggered scan via signed webhook (HMAC verification)
- Project / commit SHA / changed-files extraction
- Diff analysis: hardcoded secrets, suspicious packages, obfuscation (`eval`/`exec`, encoded payloads), env-var exfiltration
- Actionable report back into the developer flow

## What the Control Plane adds

- Composite scoring engine (code, supply chain, exfiltration, exposure, AI-agent, business urgency) with explainable **Allow / Review / Block / Quarantine** decisions
- AI-agent guardrails: tool-call validation, execution policy, sandboxing, human-approval escalation
- NIST CSF 2.0 governance view with owners, SLAs, exceptions and evidence
- Premium SOC-grade UI: dark/light themes, fixed sidebar, sortable tables, detail drawers, sparklines, live feed

## Tech

Single-file static web app — HTML + CSS + vanilla JS. Dark mode by default with light-mode toggle, responsive desktop/mobile, accessible components, simulated but credible data.

---

*GuardAgent Control Plane — policy pack v2026.07 · Fable-5 reasoning core (simulated).*
