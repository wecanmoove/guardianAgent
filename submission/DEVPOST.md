# GuardAgent Control Plane — XPRIZE / Devpost Submission

> **Category:** Small Business Services *(primary)* — with strong overlap into
> Entrepreneurship & Job Creation and Professional Services Access.
>
> **One-liner:** An AI Security Control Plane that lets small software teams
> ship code safely without a security engineer — the business itself is run by
> AI agents, gated by policy, reasoning with **Gemini 2.5 Flash on Google Cloud**.

---

## Why this fits the category

Small software businesses, agencies and solo founders cannot afford a $180k/yr
application-security engineer, yet they push code that leaks secrets, pulls
typosquatted dependencies and ships injection bugs. GuardAgent gives them an
**AI security team on tap**: every commit is scanned, reasoned about, and gated
in seconds, with a governance trail their enterprise customers demand.

## How AI runs the business (AI-Native Operations)

| Function | Who does it | Evidence |
|---|---|---|
| Scan & reason about every commit | **Gemini 2.5 Flash** + deterministic analyzer | `/api/scan` → audit trail, evidence IDs |
| Classify findings, close false positives | `triage-agent` (shadow-mode first) | `agent_actions` table, policy `POL-AGT-050` |
| Rotate leaked secrets, open fix MRs | `remediation-agent` | audit `POL-AGT-045` |
| Onboard new customers (repo + webhook) | `onboarding-agent` | audit log |
| Meter usage → Stripe billing | `billing-agent` | Stripe usage records |
| First-response customer support | `support-agent` | drafted replies |
| **Enforce guardrails on all of the above** | `agent_policy.py` engine | denied ops log |

Humans do: approve escalated actions, sign enterprise contracts, and set policy.
Everything else runs continuously via `backend/agent_runner.py` (Cloud Run job).

## Google Cloud products used

- **Vertex AI — Gemini 2.5 Flash** — the reasoning core (intent analysis, verdicts).
- **Cloud Run** — hosts the FastAPI control plane and the autonomous agent loop.
- **Secret Manager** — stores the HMAC webhook secret (cryptographic GitLab verification).
- **Cloud Build** — container build on deploy (`gcloud run deploy --source`).

## Business viability

- **Pricing:** $0 Free (1 repo) · $49/mo Team (10 repos) · $199/mo Business (unlimited + governance export) · Enterprise custom.
- **Revenue model:** metered SaaS subscription + usage (scans) billed through Stripe.
- **Unit economics:** near-zero marginal cost — Gemini 2.5 Flash is cheap per scan; Cloud Run scales to zero.
- See [`PL_TEMPLATE.md`](PL_TEMPLATE.md) and [`REVENUE_EVIDENCE.md`](REVENUE_EVIDENCE.md).

## Category impact

If a two-person dev shop can pass a SOC-2-style security gate without hiring,
the number of businesses that can credibly sell software to regulated customers
goes up. That is job creation at the edge: the founder keeps building, and the
"security hire" they could never afford is replaced by an agent they can.

---

## Submission checklist (Devpost)

- [x] **GitHub repo** — https://github.com/wecanmoove/guardagent-control-plane
  - [ ] Shared with `testing@devpost.com` and `judging@hacker.fund` *(action for owner — see below)*
- [ ] **3-min video** — script in [`VIDEO_SCRIPT.md`](VIDEO_SCRIPT.md), record & upload
- [ ] **Written narrative (500–1000 words)** — [`NARRATIVE.md`](NARRATIVE.md)
- [ ] **Revenue evidence + P&L** — [`REVENUE_EVIDENCE.md`](REVENUE_EVIDENCE.md), [`PL_TEMPLATE.md`](PL_TEMPLATE.md)
- [ ] **Hackathon expenses (incl. marketing spend, even if $0)** — [`EXPENSES.md`](EXPENSES.md)
- [ ] **Product evidence (agent logs, API usage, dashboards)** — [`EVIDENCE.md`](EVIDENCE.md)
- [ ] **Customer evidence (names, emails, testimonials)** — [`CUSTOMERS.md`](CUSTOMERS.md)
- [ ] **Corporate ID** (if available) — add to [`REVENUE_EVIDENCE.md`](REVENUE_EVIDENCE.md)

### How to share the repo with the judges
The repo is currently public, which already satisfies access. If you make it
private, add the two judge emails as collaborators:
```
gh api -X PUT repos/wecanmoove/guardagent-control-plane/collaborators/<n/a> # (emails can't be added directly)
```
For email-based access, invite them from **GitHub → repo → Settings →
Collaborators**, or simply keep the repo **public** (judges accept public repos).
