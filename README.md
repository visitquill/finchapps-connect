# FinchApps production connection service

Shared server for VisitQuill, DoseFolio, LabPrism, PulseTrellis, CareThread Atlas, AllergyFolio, VaxLedger, ConsentLoom, FHIR Trail SourceWeave and WhenWillIDie. Patient-authorized connectivity is powered by **FinchNode**.

## Run
Node 22 or newer; no third-party runtime dependencies. Run `npm ci`, `npm test`, then `npm start`. Render uses `PORT`; otherwise port 3000.

Configure `FINCHNODE_API_KEY` (a production `ck_live_` key) and `FINCHNODE_WEBHOOK_SECRET` **only in the server's secret environment**. Never place these in frontend variables, Git, URLs, or logs. Missing or sandbox configuration fails closed. `GET /health` reports configuration presence, not credential validity.

Register FinchNode app **FinchApps Personal Health Tools**, with a purpose explicitly naming all eleven sites, read-only one-time transfers, a one-day requested sharing duration, and the matching privacy notice. Configure the lifecycle webhook as `https://finchapps-connect.onrender.com/webhooks/finchnode`. The eight category allowlist is narrowed per site and per visitor selection.

## Security and lifecycle

- `POST /session` verifies `/app` is production/live, creates an opaque external ID and real Hosted Connect link, and returns a random 256-bit visitor bearer token. Only its hash is held in server memory.
- Tokens are tied to one exact site origin and expire after 30 minutes. The browser keeps the token in tab sessionStorage; records are kept only in React memory. Neither API keys nor patient IDs are accepted from clients.
- `GET /records` verifies the server-owned Connect session and requests only categories granted to that session. FinchNode enforces current consent on every read. No user-list endpoint or arbitrary proxy exists.
- No record persistence, analytics, PHI logs, third-party frontend scripts, or browser agent tools. Downloads occur only on the visitor's explicit click.
- Signed lifecycle webhooks verify timestamp and raw-body HMAC, deduplicate events, and remove active sessions on revocation, expiry, or deletion. Record reads also fail closed independently of webhook delivery. Event deduplication and sessions are in memory; a restart ends all sessions. Webhook metadata is not logged.
- Static clients clear records on hiding the tab and revalidate while visible every 30 seconds. In-flight reads also check that the session was not invalidated by a webhook.
- `DELETE /session` invalidates local access and cancels incomplete Connect sessions. Revoking completed sharing is done by the patient at https://finchnode.com/me. Copies a patient downloads are outside server control.
- Origin restrictions, per-session and global rate limits reduce abuse. CORS is not authentication; the bearer token binds access. An open Connect entry point can still consume quota; monitor FinchNode and Render usage before broad promotion.

## Hosting
Use the provided Render Blueprint or create a **free Node web service** from this public repo. Free Render instances can sleep/restart; reconnect after lost sessions. No disk or database is required. The static clients are separately hosted.

Tests use injected mock HTTP responses to verify access boundaries and lifecycle behavior; no fixtures are shipped to users and no real medical records are needed for testing. Actual patient EHR sign-in and sharing must be completed by the patient.

Production contract: https://finchnode.com/openapi.yaml. Supported source availability is determined by FinchNode and the healthcare organization; a configured live key alone does not prove a successful patient connection.

WhenWillIDie is limited to the demographics category; its entertainment calculation uses only age derived from birth date. It must be named in the shared app purpose before enabling production. Hosted Connect returns to each site’s `/#/import` route.
