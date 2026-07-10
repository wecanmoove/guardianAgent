# Written Narrative — GuardAgent Control Plane

*Category: Small Business Services. Target length 500–1000 words. Draft below is
~720 words; edit the bracketed facts to match your real numbers before submitting.*

---

## The business

GuardAgent Control Plane is an AI-run application-security service for small
software teams. The premise is simple: the businesses that most need a security
engineer are the ones that can least afford one. A two- or three-person shop
shipping a SaaS product handles secrets, third-party dependencies and customer
data, but a dedicated AppSec hire costs more than their entire runway. We
replace that hire with a system of AI agents that scan every commit, reason
about the real risk, block what is dangerous, and keep an audit trail their own
customers can trust.

## What the AI does versus what humans do

The product is not "AI-assisted." The day-to-day operation of the company runs
on agents, each one constrained by a policy engine that decides — before any
action executes — whether it is allowed, must run in a sandbox, needs human
approval, or is denied outright.

When a developer pushes code, a signed GitLab webhook hits our Cloud Run
endpoint. A deterministic analyzer flags pattern-level signals (hardcoded
tokens, typosquatted packages, `eval` on user input, environment-variable
exfiltration). Then **Gemini 2.5 Flash on Vertex AI** reasons about intent: is
this actually malicious, or a false positive, and what is the concrete fix? The
verdict — Allow, Review, Block or Quarantine — is written to an immutable audit
log with an evidence ID.

Around that core, agents run the business. The `triage-agent` classifies new
findings and closes false positives, but only after running in shadow mode so a
mistake never touches a customer. The `remediation-agent` rotates leaked
secrets and opens fix merge requests. The `onboarding-agent` provisions a new
customer's repository and webhook — the revenue-generating path — without a
human. The `billing-agent` meters scan usage and reports it to Stripe. The
`support-agent` drafts first responses to customer questions.

Humans do three things: approve the actions the policy engine escalates (for
example, any cross-boundary data egress), sign enterprise contracts, and set the
policy itself. Everything a human touches is logged as an approval on the audit
trail, which is exactly the artifact our enterprise customers need to satisfy
their own vendor-security reviews.

The guardrails matter as much as the automation. The same platform that watches
customer code also watches our own agents. When an agent requests an
interactive shell on a production node, policy `POL-AGT-011` denies it and
raises the session risk — an AI trying to over-reach is treated as a security
event, not a convenience.

## Jobs and economic opportunity

The direct effect is that a small business can pass a security bar that used to
require a hire they could not make. That keeps the founders building instead of
either taking on unmanaged risk or spending months in manual review.

The second-order effect is broader. Every small software vendor that can now
credibly answer "how do you secure your pipeline?" becomes eligible to sell to
larger, regulated customers. That is market access that did not exist for them
before. As we grow, the roles the business creates are not junior security
analysts doing repetitive triage — the agents do that — but higher-value work:
policy authors who encode security judgment, customer-success engineers who
onboard regulated accounts, and partners who resell the platform to their own
client bases. [Describe any contractors, part-time reviewers, or design/marketing
help you actually paid during the hackathon window here.]

## Building it this way

We built GuardAgent as the product evolution of an earlier prototype
(`guard-agent-test`), which was a bare webhook bridge to a hosted agent. The
insight during the hackathon was that the interesting business is not the
scanner — it is the *control plane*: the layer that turns scans into governed
decisions, meters them into revenue, and proves to a buyer that the whole thing
runs safely without a human in every loop.

Doing it agent-first changed the shape of the company. Onboarding, triage,
remediation and billing are code paths, not headcount. The marginal cost of one
more customer is a few Gemini 2.5 Flash calls and some Cloud Run seconds, which
is why the free tier is sustainable and the paid tiers have software margins.

The hardest part was trust: a security company whose own automation is a
liability is worthless. That is why the agent-policy engine and the immutable
audit trail are not features bolted on for the demo — they are the core of both
the product we sell and the way we run.

---

### Facts to verify before submitting
- [ ] Real revenue figure and the 90-day window dates
- [ ] Real customer count and any names/testimonials (with consent)
- [ ] Any real money paid to people beyond the founders (contractors, reviewers)
- [ ] Corporate ID / entity status, if the business is registered
