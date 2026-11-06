# Production readiness and Phase 7 gate

**No deployment is authorized by Phase 7.** This checklist is an operator/reviewer release gate,
not a statement that a production environment was inspected. Phase 6 PR #6 is a prerequisite;
neither it nor the Phase 7 PR is merged automatically.

## Measurable security and test gates

- [x] Source review covers auth/session/CSRF/CORS/RBAC/provisioning/scans/URLs/AI/DB/history/PDF/CSV/config/CI.
- [x] Verified high dependency/privacy issues remediated; no unresolved critical finding identified in reviewed code.
- [x] All 67 synthetic cases have stable risk levels; all 67 neutral mocked hybrid cases preserve rule scores.
- [x] Known synthetic misses and language limits documented rather than hidden by threshold tuning.
- [x] Go race/integration, frontend lint/types/21 unit tests and production build pass locally.
- [x] URL fuzz test completes its bounded five-second budget without panic or risk invariant failure.
- [x] Source/history secret scan passes with exactly one historical prose fingerprint exception.
- [ ] Final hosted PR CI run passes all three configured jobs and independent review approves remaining risk.
- [ ] Review real-model quality separately under an approved privacy/budget protocol if hybrid AI will launch.
- [ ] Agree quality targets using a representative, independently labeled hold-out corpus; current synthetic
      precision/recall do not justify a production accuracy claim or a fabricated acceptance threshold.

Configured branch-protection check display names (defined jobs, not invented required checks):

| Display name | Job ID | Required evidence |
| --- | --- | --- |
| Backend checks | backend | Formatting, vet, race tests, disposable PostgreSQL, migrations, corpus/fuzz, Chrome journeys |
| Frontend checks | frontend | Lint, typecheck, unit tests, production build |
| Security checks | security | govulncheck, npm audit, redacted source/history Gitleaks scans |

Only configure these as required checks after observing these exact names succeed on the PR
in your repository. No branch-protection rules were changed by this phase. Prefer PR checks,
not a pull_request_target job running untrusted code with secrets. Scanner download/advisory
network failures are visible failures, not silently successful skips.

## Environment and transport checklist (manual, not verified in production)

- [ ] APP_ENV=production; valid PORT and current supported Go/Node runtime patches.
- [ ] DATABASE_URL supplied from secret manager, not command history or repository; sslmode=verify-full,
      correct CA and hostname verification on remote PostgreSQL connections.
- [ ] CORS_ALLOWED_ORIGINS contains exact HTTPS frontend origins only; no wildcard, userinfo, paths or null.
- [ ] HTTPS termination, trusted certificates, HSTS at ingress, and backend network restrictions verified.
- [ ] Browser checks confirm __Host- cookie name, Secure, HttpOnly, SameSite=Lax, Path=/, no Domain.
- [ ] Exact Origin CSRF policy works behind chosen ingress; do not bypass it to fix deployment CORS errors.
- [ ] Configure any proxy trust explicitly before using forwarded client addresses; default distrust is retained.
- [ ] AI_ENABLED is intentionally false or explicitly approved; key/model/timeout/token settings valid.
      OPENAI_API_KEY stays in server secret management, never NEXT_PUBLIC_* or browser bundles.
- [ ] Explain AI transmission and heuristic redaction limits to users. Do not promise comprehensive DLP.
- [ ] Rotate DB, AI and operator credentials through a tested runbook. Rotate immediately if a real leak is found.

## Database, operations and privacy checklist

- [ ] Separate least-privilege runtime/operator/migration identities; runtime cannot assign roles or modify audit events.
- [ ] Administrator identity is verified out of band; provision via authenticated operator CLI and inspect its audit event.
- [ ] Backups encrypted, access-controlled and restore-tested; record restore duration and recovery objectives.
- [ ] Retention approved for scans, sessions, account metadata and immutable-trigger-protected audit logs.
- [ ] Confirm deletion removes records from history/statistics/export; account for backup retention separately.
- [ ] Logs redact sensitive content; restrict access and configure actionable error monitoring/alerts.
- [ ] Minimal liveness/readiness endpoints checked from intended network locations. DB outage fails closed.
- [ ] Distributed/edge rate policy established for multi-instance operation; per-process limits alone do not form a global quota.
- [ ] Request timeout, AI fallback, shutdown/draining and ingress response limits tested in the actual release topology.
- [ ] Load test modest authorized staging traffic; record HTTP p50/p95/p99, resource use and DB query timings.
      The local engine micro-measurement is not a production capacity estimate.
- [ ] PDF/CSV exports stay private and bounded; no shared/public temporary download directory is introduced.
- [ ] Monitoring describes only actual metrics. No provider-verification, reputation or uninstrumented latency claims.
- [ ] Manual keyboard/screen-reader and supported mobile/browser checks completed; nonce-CSP design evaluated separately.
- [ ] Account ownership/recovery policy approved; email verification and password recovery are not implemented.

## Rollback and release blockers

- [ ] Record released source SHA and reproducible build inputs; keep a tested previous artifact.
- [ ] Review migration state before deploying. Phase 7 introduces no migration; Phase 6 requires 006.
- [ ] Back up required audit records before any schema rollback; rollback of 006 removes audit/status state.
      Do not restore an older application in a way that re-enables suspended accounts without operator review.
- [ ] Verify session invalidation and security settings after rollback; perform a disposable restore/rollback rehearsal.

Release is blocked by a failing security/CI gate, any undisposed high/critical finding, unreviewed
module advisory with an applicable execution path, or missing mandatory production configuration.
Use current PR check results to assess hosted CI; production-only manual checks are unverified by this phase.
This phase does not deploy, approve production, or proceed to Phase 8 automatically.
