# ScamGuard AI

ScamGuard AI is a scam and phishing awareness platform in development. It aims to help people understand suspicious messages, emails, and links before they trust, click, or share. Scams exploit urgency and uncertainty; the planned product will provide understandable assessments that support informed decisions.

## Current status: Phase 1

Implemented: Go HTTP API, PostgreSQL connection pool and readiness checks, versioned schema and migration runner, responsive Next.js homepage, reusable UI components, dashboard demo, scanner interface preview, live API connectivity indicator, automated tests, and CI.

**Scanning is unavailable until Phase 3.** Scanner fields remain in browser memory and are never submitted or persisted. Dashboard numbers and activity are fictional and visibly labeled. Authentication, AI analysis, email processing, URL fetching, scan storage endpoints, and real history are not implemented.

## Architecture and stack

```text
Browser → Next.js App Router (port 3000)
       → Go / Gin API (port 8080) → pgx/v5 pool → PostgreSQL
```

The browser calls `GET /api/v1/health` every 30 seconds with a five-second client timeout. Only configured origins can read API responses. The connectivity badge reports API liveness, not database readiness. `GET /api/v1/health/ready` checks the database with a two-second deadline and returns 503 when unavailable. Liveness deliberately stays healthy during a database outage.

- Backend: Go 1.25+ (see `backend/go.mod` for the precise toolchain minimum), Gin, pgx/v5, standard `slog` logging.
- Frontend: Node.js 24 LTS, Next.js 16 App Router, React 19, TypeScript, Tailwind CSS 4, Lucide icons. Exact dependencies are locked in `package-lock.json` and `go.sum`.
- Database: PostgreSQL 17 in Docker Compose; schema supports PostgreSQL 16+.
- CI: GitHub Actions with PostgreSQL service, Go race tests/vet, ESLint, TypeScript, component checks, and production build.

`backend/cmd/server` owns startup/shutdown. Internal packages separate configuration, HTTP handlers, middleware, routing, and database infrastructure. `cmd/migrate` applies embedded SQL transactionally. Services, repositories, and domain models will be introduced when business operations exist; no empty placeholder packages are included. Frontend components separate navigation, dashboard, scanner, shared states, and connectivity; `lib/api.ts` handles HTTP response validation.

## Run from a fresh clone

Prerequisites: Git, Go matching `backend/go.mod` (automatic Go toolchain download is supported), Node.js 24 with npm, Docker with Compose v2 and permission to use its daemon. Ports 3000, 8080, and 5432 must be free.

### 1. Start PostgreSQL

From the repository root:

```sh
export POSTGRES_PASSWORD=local_dev_password
docker compose up -d --wait
```

This is an example **local-only** password, not a production credential. Compose requires a password from your environment and binds PostgreSQL to loopback. Use a unique secret outside local development.

### 2. Configure and start the backend

In a new terminal:

```sh
cd backend
cp .env.example .env
# Edit .env if you changed the database password, host, or port.
set -a
. ./.env
set +a
go mod download
go run ./cmd/migrate up
go run ./cmd/server
```

Go does not automatically read `.env`; source it as shown. For multiple CORS origins, quote the value if needed and use a comma-separated list of exact origins without trailing slashes or paths.

Expected checks from another terminal:

```sh
curl -f http://localhost:8080/api/v1/health
# {"service":"scamguard-api","status":"ok","version":"1.0.0"}
curl -f http://localhost:8080/api/v1/health/ready
# {"status":"ready"}
```

### 3. Start the frontend

In another terminal:

```sh
cd frontend
cp .env.example .env.local
npm ci
npm run dev
```

Open <http://localhost:3000>. The status indicator should show **API connected** when the backend is running and its CORS allowlist includes this exact frontend origin. The scanner buttons navigate to a preview; they do not perform scans.

### 4. Stop services

Use Ctrl+C for each application, then from the repository root:

```sh
docker compose down
```

The named PostgreSQL volume persists between runs. `docker compose down --volumes` permanently deletes the local database; use it only when intentionally discarding local data.

## Environment configuration

| Variable | Purpose |
| --- | --- |
| `APP_ENV` | `development` (default), `test`, or `production` |
| `PORT` | Backend HTTP port, defaults to 8080; valid range 1–65535 |
| `DATABASE_URL` | Required PostgreSQL URL; never logged |
| `CORS_ALLOWED_ORIGINS` | Required comma-separated exact frontend origins; wildcards rejected |
| `NEXT_PUBLIC_API_URL` | Browser-visible backend base URL; example `http://localhost:8080` |
| `POSTGRES_PASSWORD` | Required by local Compose; must match `DATABASE_URL` |
| `TEST_DATABASE_URL` | Enables database-dependent Go tests against a migrated test database |

Production must use separately injected secrets, `APP_ENV=production`, a PostgreSQL URL with `sslmode=verify-full` and a trusted database certificate, and HTTPS-only frontend origins. Terminate TLS at a trusted reverse proxy, enforce HSTS there, and expose readiness only to intended infrastructure. Set `NEXT_PUBLIC_API_URL` **before building** the frontend: Next.js embeds it in the browser bundle. Never place secrets in `NEXT_PUBLIC_*` variables. Use a distinct migration database role with DDL privileges and a least-privileged runtime role. The API disables forwarded proxy trust by default.

## Migrations and schema

From `backend`, after sourcing the environment:

```sh
go run ./cmd/migrate up
# Roll back the initial schema (destructive; local/test databases only):
go run ./cmd/migrate down
# Reapply:
go run ./cmd/migrate up
```

The Phase 1 runner supports the single `001_initial` migration. It records version 1 in `schema_migrations`, uses an advisory transaction lock to serialize runners, and makes repeated up/down calls idempotent. A failed migration rolls back completely. Extend version discovery before introducing additional migrations; do not edit applied migrations in deployed environments. Back up data before rollback. Down drops users and scans; it retains the migration bookkeeping table.

`users` has UUID IDs, case-insensitive unique email indexing, role constraints, timestamps, and an update timestamp trigger. `scans` has UUID IDs, a nullable user foreign key with `ON DELETE SET NULL`, bounded input size and score, scan type/risk constraints, score-to-level consistency, and indexes for history and retention queries. Risk thresholds (low 0–29, medium 30–69, high 70–100) are schema conventions for future implementation, not a functioning detection model. No accounts or example scan rows are seeded.

## Testing

Backend (from `backend`, with the environment loaded and migrations applied):

```sh
go vet ./...
TEST_DATABASE_URL="$DATABASE_URL" go test -race ./...
go build -o /tmp/scamguard-api ./cmd/server
```

Without `TEST_DATABASE_URL`, integration tests explicitly skip; unit tests still run. Use a disposable test database: schema tests use synthetic fixtures and roll back their transaction. Integration checks exercise actual pooled connectivity, readiness after pool closure, foreign keys, and constraints. HTTP tests cover the health contract, readiness success/failure, CORS allow/deny/preflight behavior, security headers, and panic redaction. Configuration tests reject unsafe and invalid settings.

Frontend (from `frontend`):

```sh
npm run lint
npm run typecheck
npm test
npm run build
npm start
```

Component tests render the scanner and dashboard to verify preview safety and demo labels. The production server runs at <http://localhost:3000>. GitHub Actions runs these checks and applies migrations up/up/down/up against a PostgreSQL service. It does not deploy the application. A scoped npm override upgrades minimatch 7–11.0.0 to the patched 11.x line for development tooling; older unaffected 3.x consumers retain their compatible API. Remove this override once upstream tooling updates its dependency ranges. ESLint 10 currently produces peer-range warnings from several Next.js lint plugins; linting and clean installation are verified with the locked versions.

### Phase 1 verification

Executed locally on 2026-11-05: Go race tests (including PostgreSQL integration and readiness deadlines), `go vet`, server build/start, migration up/up/down/down/up, live health/readiness/CORS checks, frontend lint (zero warnings), TypeScript validation, four component/API-client tests, and the production build/start all passed. `actionlint` accepted the workflow. The finalized dependency installation reported zero npm vulnerabilities.

A real headless Chrome check verified API connected/unavailable states, scanner tab switching without submissions, no JavaScript exceptions, and no horizontal overflow at 1440, 768, 390, and 320 pixels. Local database checks used isolated PostgreSQL 16.15 because this account cannot access the Docker daemon and lacks the Compose plugin. Compose YAML was parsed; container startup itself was not executed here. CI is configured to exercise PostgreSQL 17. Hosted CI results should be reviewed on the pull request.

## Security and privacy

- Configuration is validated at startup. Passwords, database URLs, request bodies, raw query strings, and panic details are excluded from application request logs and client errors. Database failures return generic structured errors.
- API requests have a five-second response timeout, HTTP read/write/header limits, a 1 MiB body limit, bounded connection counts, and graceful shutdown. Database checks also inherit request cancellation. Future handlers must honor request contexts; a timeout response cannot forcibly terminate arbitrary application work.
- Exact CORS allowlists, `nosniff`, frame restrictions, referrer policy, and frontend permissions policy are configured. CORS is a browser control, not authentication. Add rate limiting and endpoint authorization before accepting submissions.
- No unsafe HTML rendering or external URL fetching exists. Runtime SQL values use pgx parameters; migration SQL is trusted, version-controlled code. No real passwords, tokens, or submissions are stored in Phase 1.
- Scan text can include personal, financial, or confidential material. **Future phases must implement data minimization and configurable retention before accepting real submissions.** Plan redaction, consent, encrypted storage/backups, restricted access, deletion/export, and log exclusion. User deletion currently anonymizes only the foreign key; it does not scrub scan text. Implement explicit deletion policies before storing sensitive content.
- Before fetching URLs, implement SSRF controls: permit HTTP(S) only; reject embedded credentials and unexpected ports; resolve and block loopback/private/link-local/reserved IPv4/IPv6 addresses; protect against DNS rebinding; validate every redirect; use restricted outbound networking; never forward ambient credentials; enforce time, size, and redirect limits. Recheck resolved addresses at connection time. Treat fetched content as untrusted and isolate fetch workers.
- AI assessments will be advisory and can be wrong; never promise a link is safe based only on a low score. Dependency and deployment security reviews remain ongoing work.

## Roadmap and contribution workflow

1. **Phase 1 (this PR):** application foundation and honest interface previews.
2. **Phase 2 (after review and merge):** design authentication and authorization, password hashing, account/session lifecycle, abuse controls, and privacy/retention policies with security tests.
3. **Phase 3:** implement scan services, threat analysis, safe URL handling, and real risk explanations only after the data and SSRF safeguards are ready.
4. Later: persisted scan history and awareness resources with appropriate access controls.

Branch from `main`, use a descriptive feature branch, keep commits focused, run the checks above, and open a pull request documenting behavior, validation, and limitations. Never commit `.env` files or real user data. Phase 1 work is on `feature/phase-1-foundation`; review and merge it before starting authentication or detection work.

Licensed under the [MIT License](LICENSE).
