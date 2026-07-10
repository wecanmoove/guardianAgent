# 3-Minute Demo Video Script

Goal per the rules: *demonstrate the extent to which AI is live in production
and executes key decisions.* Show real endpoints returning real verdicts and
real agent-policy denials — not slides.

**Setup before recording:**
```bash
export GEMINI_API_KEY=...            # or GOOGLE_GENAI_USE_VERTEXAI=true on GCP
uvicorn backend.main:app --port 8080 &
python -m backend.agent_runner --cycles 0 --interval 2   # in a 2nd terminal, on-screen
```

---

### 0:00–0:20 — The problem (talking head + terminal)
> "Small software teams can't afford a security engineer, but they ship secrets,
> bad dependencies and injection bugs every day. GuardAgent is an AI security
> team that runs their pipeline for them — and the business itself is run by AI
> agents on Google Cloud."

### 0:20–0:55 — Live scan, live Gemini decision (screen: the dashboard)
- Open the deployed Cloud Run URL. Show **AI Code Inspection**.
- Paste the `env exfiltration` sample. Click **Run deep analysis**.
- Point at: the **QUARANTINE** verdict, the **Gemini reasoning** panel
  (threat class, confidence, remediation), and the toast: *"Scan EV-90xxx
  recorded in audit trail."*
- Say: "That verdict came from **Gemini 2.5 Flash on Vertex AI**, reasoning about
  intent — and it was just written to an immutable audit record."

### 0:55–1:30 — Prove it's the real backend (screen: terminal)
```bash
curl -s $URL/health | jq          # gemini:true, model gemini-2.5-flash
curl -s -X POST $URL/api/scan -H 'content-type: application/json' \
  -d '{"code":"python-dateutils==2.9.1\neval(input())","repo":"acme","sha":"a1b2c3"}' | jq
```
- Show the JSON: `decision`, `evidence`, `reasoning.engine = gemini-2.5-flash`.
- "No mock. That's the production endpoint a customer's GitLab webhook hits."

### 1:30–2:10 — Agents run the business, guardrails hold (screen: agent_runner terminal + console)
- Show the autonomous loop printing lines: onboarding, billing, remediation…
- Then the key moment — an agent tries a shell:
```bash
curl -s -X POST $URL/api/agent/act -H 'content-type: application/json' \
  -d '{"agent":"deploy-agent-02","action":"shell","tool":"run_shell(bash -i)"}' | jq
```
- Show `"outcome":"Denied","policy":"DENIED · POL-AGT-011 …","risk":0.96`.
- "Our own agents are policed by the same platform. An agent overreaching is a
  security event — denied, logged, escalated."

### 2:10–2:40 — The business: revenue + governance (screen: dashboard)
- Show **NIST Governance Center** (findings mapped to CSF 2.0, owners, SLAs).
- Show **Evidence & Audit Trail**, click **Export CSV** — real file downloads.
- Show Stripe dashboard / usage (your real screenshot).
- "Every scan is metered to Stripe. Onboarding, triage, billing — all agent-run."

### 2:40–3:00 — Close (talking head)
> "GuardAgent lets a two-person shop pass a security bar that used to need a
> hire they couldn't make. The scanning, the triage, the billing, the
> support — run by AI, gated by policy, on Google Cloud. That's a security
> company that scales without scaling headcount."

---
**On-screen lower-thirds to include:** the Cloud Run URL, `gemini-2.5-flash`,
a visible evidence ID, and the Stripe revenue number.
