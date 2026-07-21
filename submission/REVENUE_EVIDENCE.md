# Revenue Evidence

*Attach real exports here. Judges accept a Stripe dashboard export or a bank
statement plus the simple P&L ([PL_TEMPLATE.md](PL_TEMPLATE.md)).*

## What to attach in `submission/evidence/`

- [ ] `stripe-export.csv` - Stripe -> Payments -> Export (filter to the 90-day window)
- [ ] `stripe-dashboard.png` - screenshot of gross volume for the window
- [ ] `bank-statement.pdf` - alternative/complement to Stripe (redact unrelated lines)
- [ ] Completed [PL_TEMPLATE.md](PL_TEMPLATE.md)

## Stripe setup for GuardAgent (if not done yet)

1. Create products: **Team $49/mo**, **Business $199/mo**, metered price
 `scan_overage` per 100 scans.
2. Payment links -> paste the checkout URLs into the dashboard footer / README.
3. The `billing-agent` reports usage via `stripe.report_usage` (see
 `backend/agent_runner.py`); wire your real Stripe secret key via env
 `STRIPE_API_KEY` when moving past the demo loop.

## Corporate ID

| Field | Value |
|---|---|
| Legal entity | [name or "pre-incorporation"] |
| Corporate ID (SIREN/SIRET/EIN) | [id or "n/a"] |
| Country | |
