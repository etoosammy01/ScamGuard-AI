# Phase 6 implementation and verification

Implemented on `feature/phase-6-admin-reports` for review against `main`. No merge or Phase 7 work is authorized by this change.

## Delivered behavior

- Private, owner-scoped PDF reports and authenticated frontend blob downloads.
- Database-backed role authorization on every admin API, with no public role promotion endpoint.
- Transactional suspension/reactivation, session revocation, live account status checks, self-suspension prevention and serialized administrator lifecycle operations.
- Real aggregate overview, UTC daily/weekly analytics, distributions, AI status/fallback ratios, and registrations.
- Paginated account search and audit views; responsive administrative navigation and accessible confirmation dialogs.
- Append-only audit events, immutable-DML trigger, and an operator-only audited provisioning command.
- Minimal readiness/uptime monitoring and read-only deployment policy settings.

## Migration

`006_admin.up.sql` adds `users.status`, `audit_logs`, its immutability trigger/function,
and creation-time indexes on users/scans/audit events. The down migration removes these
objects. Both directions and reapplication were executed against disposable PostgreSQL 16.15.
Production migration was not run. Rollback removes suspension state and audit history;
coordinate any rollback with account/session security operations and required audit backups.

## API inventory

- `GET /api/v1/scans/:id/report`
- `GET /api/v1/admin/overview`
- `GET /api/v1/admin/users`
- `GET /api/v1/admin/users/:id`
- `PATCH /api/v1/admin/users/:id/status`
- `GET /api/v1/admin/analytics`
- `GET /api/v1/admin/audit-logs`
- `GET /api/v1/admin/settings` (read-only)

## Security and provisioning

Existing cookie authentication, exact trusted-Origin CSRF checks, scanner safety and AI
privacy behavior are preserved. Report ownership is enforced in SQL. Admin identity comes
from the live database, never request roles. Unknown status fields, role elevation attempts,
invalid ranges and unbounded pagination are rejected. Reports have concurrency/text/page/output
limits and no public storage. Admin APIs never select private scan contents, hashes or tokens.

Use a trusted operator host and authenticated operator PostgreSQL identity, apply migrations,
verify the intended existing active account owner, then run from `backend`:

```sh
go run ./cmd/admin existing-account@example.com CHANGE-1234
```

Supply `DATABASE_URL` securely; use verified TLS for remote production databases. The command
records the operator reference and database session identity in the same transaction as promotion.
Production must use separately restricted runtime/operator/schema-owner database roles. Full
privilege, retention and exceptional role-removal instructions are in the README.

## Actual verification results

Verified locally on 2026-11-06. PostgreSQL ran in a disposable loopback cluster, not production.
Node.js 22.22.0 was downloaded to `/tmp` because the environment had no Node/npm on PATH.
Docker was unavailable, so PostgreSQL 16.15 binaries were also extracted into `/tmp`.

| Command/check | Actual result |
| --- | --- |
| `go test ./...` with `TEST_DATABASE_URL` | Passed, including database/authentication/Phase 6 integration tests |
| `go test -race ./...` with `TEST_DATABASE_URL` | Passed, including concurrent reciprocal administrator suspension |
| `go vet ./...` | Passed |
| `gofmt` check and `git diff --check` | Passed |
| `go build` server and admin commands | Passed |
| Migration up, down, up | Passed against disposable PostgreSQL |
| `npm ci --ignore-scripts` | Completed; existing ESLint peer-range warnings, audit reported zero vulnerabilities |
| `npm run lint` | Passed without warnings on final sources |
| `npm run typecheck` | Passed |
| `npm test` | 18 passed, zero failures/skips |
| `npm run build` | Passed; all five admin routes generated |
| `npm run test:admin-browser` with fixture pagination enabled | Passed in real headless Chrome |
| `npm run test:browser` | Existing authentication/scanner/profile/session/browser regression suite passed |

The admin browser test checked regular-user rejection, genuine report success and visible report
failure, overview rendering, real user pagination, self-suspension button protection, confirmation
cancellation, suspension/reactivation, aggregate charts, audit pagination and all five admin pages
at 390px width. Database tests checked authorization, ownership, active-session rejection,
re-login after reactivation, strict mutation bodies, CSRF, read-only settings, exact fixture
aggregates, audit creation, audit DML rejection and administrator concurrency safety.
Initial checks found a content-type compile error and a pagination timing issue; both were fixed
before the final passing checks. No failing tests remain from the executed suites.

## Known limitations

- Settings are intentionally read-only; there is no persisted settings mutation API.
- Historical full AI assessments were not retained; reports explicitly say no AI summary is available.
- Analytics count retained scans, not lifetime usage; deleted histories reduce totals.
- Uptime/rate limits are per process. API latency and provider error counters are not instrumented.
- Suspension rejects the next authorization check; already-running requests are not cancelled.
- Anonymous denied-access audit writes are best-effort. Audit retention needs operator policy.
- Database owners can bypass integrity controls; there are no cryptographic signatures/external immutable audit storage.
- Embedded font coverage and complex-script shaping are limited; unsupported glyphs show `[?]`.
- Live paid AI provider calls were not made; existing mocked AI/privacy/fallback tests passed.
- GitHub-hosted CI is separate from these local results.

## Files created

- `backend/cmd/admin/main.go`
- `backend/internal/handlers/admin.go`
- `backend/internal/handlers/reports.go`
- `backend/internal/handlers/reports_test.go`
- `backend/internal/reports/FONT-LICENSE.txt`
- `backend/internal/reports/NotoSans-Regular.ttf`
- `backend/internal/reports/pdf.go`
- `backend/internal/reports/pdf_test.go`
- `backend/internal/repository/admin.go`
- `backend/internal/router/admin_integration_test.go`
- `backend/migrations/006_admin.down.sql`
- `backend/migrations/006_admin.up.sql`
- `frontend/scripts/admin-smoke.mjs`
- `frontend/src/app/admin.css`
- `frontend/src/app/admin/analytics/page.tsx`
- `frontend/src/app/admin/audit-logs/page.tsx`
- `frontend/src/app/admin/page.tsx`
- `frontend/src/app/admin/settings/page.tsx`
- `frontend/src/app/admin/users/page.tsx`
- `frontend/src/components/admin-console.tsx`
- `frontend/tests/admin.test.tsx`
- `frontend/tests/reports.test.tsx`
- `docs/PHASE6-IMPLEMENTATION.md`

## Files modified

- `.github/workflows/ci.yml`
- `README.md`
- `backend/go.mod`
- `backend/go.sum`
- `backend/internal/repository/auth.go`
- `backend/internal/router/router.go`
- `frontend/package.json`
- `frontend/src/app/layout.tsx`
- `frontend/src/components/account-nav.tsx`
- `frontend/src/components/scan-detail.tsx`
- `frontend/src/lib/history-api.ts`
