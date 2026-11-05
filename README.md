# ScamGuard AI

ScamGuard AI is a scam and phishing awareness platform in development. It helps people prepare to assess suspicious messages, emails, and links before they trust, click, or share. Scams exploit urgency and uncertainty; the planned analysis will offer understandable assessments that support informed decisions.

## Current status: Phase 2

Implemented:

- Phase 1 Go/Gin API, PostgreSQL pooling and readiness, responsive landing page, dashboard demo, scanner interface preview, and real API connectivity indicator.
- Registration with validation and Argon2id password hashing; login with generic failure responses and rate limits.
- Opaque server-side sessions, HTTP-only cookies, logout/revocation, expiry checks, reusable authentication and separate admin authorization middleware.
- Protected dashboard and profile pages, refresh-persistent authentication state, editable name/bio, and cross-tab logout notification.
- Versioned migrations, automated backend/frontend tests, browser authentication smoke tests, and GitHub Actions.

**Scanning remains unavailable until Phase 3.** Scanner fields stay in browser memory and are never submitted or saved. The homepage demo is explicitly fictional. The authenticated dashboard shows unavailable placeholders and an empty history, not simulated scan results. AI analysis, phishing detection, external URL fetching, email verification, password reset, and MFA are not implemented.

## Architecture and stack

```text
Browser → Next.js App Router (3000)
        → Go / Gin API (8080) → pgx/v5 pool → PostgreSQL
          authentication middleware → services → repository
```

Go 1.25+ is the source minimum (`backend/go.mod`); use a maintained Go release, as CI does. Frontend uses Node.js 24 LTS, Next.js 16, React 19, TypeScript, Tailwind CSS 4, and Lucide. Compose and CI use PostgreSQL 17; SQL is compatible with PostgreSQL 16+. Dependencies are locked in `go.sum` and `package-lock.json`.

`cmd/server` owns startup/shutdown; internal packages separate configuration, handlers, middleware, models, services, repositories, and database infrastructure. `cmd/migrate` applies embedded SQL. The frontend retains the Phase 1 components and adds account pages, an authentication context, API client, and route guards. Protected pages are static shells: account information is fetched from the authenticated API and is not embedded in cached HTML. Browser guards provide navigation behavior; the API remains the authorization boundary.

## Local setup

Prerequisites: Git, a maintained Go toolchain compatible with `go.mod`, Node.js 24/npm, Docker and Compose v2 with daemon access. Ports 3000, 8080, and 5432 must be available.

From the repository root:

```sh
export POSTGRES_PASSWORD=local_dev_password
docker compose up -d --wait
```

This is a local example password, not a production secret. PostgreSQL binds only to loopback. Configure a unique production secret through your deployment secret manager.

In a backend terminal:

```sh
cd backend
cp .env.example .env
# Update DATABASE_URL if you changed the database password, host, or port.
set -a
. ./.env
set +a
go mod download
go run ./cmd/migrate up
go run ./cmd/server
```

Go does not automatically read `.env`; source it as above. Existing Phase 1 databases only need migration `002`. New databases receive both migrations. The server can expose liveness while PostgreSQL is unavailable; readiness and authentication report database failures safely.

In a frontend terminal:

```sh
cd frontend
cp .env.example .env.local
npm ci
npm run dev
```

Open <http://localhost:3000/register>, create an account, and continue to <http://localhost:3000/login>. Sign in, refresh <http://localhost:3000/dashboard>, edit your name/bio at <http://localhost:3000/profile>, and sign out. The dashboard must redirect to login after logout. Use `localhost` consistently rather than mixing it with `127.0.0.1`; cookie host and Origin matching are exact.

Health checks:

```sh
curl -f http://localhost:8080/api/v1/health
# {"service":"scamguard-api","status":"ok","version":"1.0.0"}
curl -f http://localhost:8080/api/v1/health/ready
# {"status":"ready"}
```

The homepage connectivity indicator checks API liveness every 30 seconds, not database readiness. Stop each application with Ctrl+C, then run `docker compose down` from the root. The named volume persists. `docker compose down --volumes` permanently deletes the local database; use only when intentionally discarding local data.

## Environment

| Variable | Purpose |
| --- | --- |
| `APP_ENV` | `development` (default), `test`, or `production`; production enforces database TLS and HTTPS frontend origins |
| `PORT` | Backend port, defaults to 8080; range 1–65535 |
| `DATABASE_URL` | Required PostgreSQL connection URL; never logged |
| `CORS_ALLOWED_ORIGINS` | Required comma-separated exact frontend origins, with no trailing slash/path or wildcards |
| `SESSION_TTL_HOURS` | Absolute session lifetime, 1–24 hours; defaults to 12; no sliding renewal |
| `NEXT_PUBLIC_API_URL` | Browser-visible API base URL; local value `http://localhost:8080` |
| `POSTGRES_PASSWORD` | Required by local Compose; must match `DATABASE_URL` |
| `TEST_DATABASE_URL` | Enables PostgreSQL-backed Go tests against a migrated, disposable test database |

`NEXT_PUBLIC_API_URL` is embedded at build time; set it before a production build. Never place secrets in `NEXT_PUBLIC_*`. Local environment files and generated artifacts are ignored by Git.

## Authentication and session flow

1. Registration validates and trims the name (1–200 Unicode characters), normalizes ASCII email by trimming/lowercasing (up to 254 bytes), validates syntax, and checks password confirmation. Passwords require 12 Unicode characters and allow up to 1,024 UTF-8 bytes. Password whitespace/content is preserved exactly. International domains can be supplied as punycode; non-ASCII email addresses are currently rejected.
2. Passwords use a fresh 16-byte cryptographic salt and Argon2id with 64 MiB memory, three iterations, one lane, and a 32-byte key. Verification uses constant-time comparison. Two concurrent password operations per process cap memory/CPU work; excess requests return 429. These parameters exceed the [OWASP minimum](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
3. New and duplicate addresses receive identical HTTP 202 JSON and no session. The service hashes before attempting the unique insert; database uniqueness handles concurrent registration safely. New accounts always use the database-backed `user` role. Unknown request fields, including client-controlled roles, are rejected.
4. Login uses parameterized queries and a dummy Argon2id hash for an unknown address, returning the same 401 response for incorrect credentials. The API generates a random 32-byte token, sends it only in a session cookie, and stores only its SHA-256 digest in PostgreSQL.
5. Each successful login creates a fresh token and revokes a presented previous session. Account row locking enforces a maximum of five active sessions per user, revoking the oldest excess sessions. Expired/revoked sessions belonging to the logging-in user are pruned.
6. Protected requests verify the digest, database expiry/revocation, and current user identity/role. Password hashes and token digests are never included in the public user JSON. Roles are loaded from PostgreSQL on each request; `AdminOnly` is a separate check, with no public admin-creation route.
7. Logout revokes the current token and clears the cookie. It is idempotent for missing/invalid tokens. Database failure returns 503; the client does not claim successful logout. Other sessions remain independent.
8. The frontend calls `/auth/me` on initial load, focus, and every minute. It handles loading, authenticated, unauthenticated, and unavailable states; protected API 401s immediately invalidate cached identity. Refreshes recover identity from the cookie, and BroadcastChannel propagates successful logout to other tabs without persisting tokens. In-flight identity checks are canceled/versioned to avoid stale responses restoring a logged-out user.

Email ownership is not verified in this phase. There is no email-change endpoint, password-change/reset endpoint, or administrator promotion endpoint.

## Cookies, CSRF, CORS, and deployment

| Property | Local HTTP development | HTTPS production (`APP_ENV=production`) |
| --- | --- | --- |
| Name | `scamguard_session` | `__Host-scamguard_session` |
| HttpOnly | true | true |
| Secure | false | true |
| SameSite | Lax | Lax |
| Path / Domain | `/`, no Domain attribute (host-only) | `/`, no Domain attribute (host-only) |
| Expiry | Explicit Max-Age and Expires, matching session lifetime | Same |

No authentication tokens enter localStorage, sessionStorage, response JSON, URLs, or application logs.

Every state-changing request—including registration, login, logout, and profile updates—must carry exactly one **Origin** matching the configured frontend allowlist. Missing, `null`, duplicate, and untrusted Origins are rejected with 403; there is no permissive Referer fallback. This is an explicit [CSRF defense](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html), independent of CORS. Non-browser API clients must supply the intended trusted Origin too; Origin validation is not a substitute for session authentication.

Credentialed CORS permits only exact configured origins and GET/POST/PATCH preflights; the frontend uses `credentials: "include"`. JSON mutation endpoints require `application/json`, reject unknown fields and trailing JSON, and limit bodies to 16 KiB. Logout needs no request body. Cookies are always SameSite=Lax; arbitrary cross-site frontend/API arrangements are intentionally unsupported.

For production, deploy either:

- **Same origin:** `https://scamguard.example.com` serves Next.js, with `/api/` reverse-proxied to the private Go server. Build with `NEXT_PUBLIC_API_URL=https://scamguard.example.com` and configure that exact frontend Origin.
- **Same site:** frontend at `https://app.example.com`, API at `https://api.example.com`. Configure the frontend HTTPS Origin and use the API HTTPS URL. Cookies belong only to the API host; credentialed fetch works because the origins are different but the site is the same.

Keep both endpoints HTTPS. Avoid unrelated registrable domains and third-party cookie reliance. There is no SameSite=None escape hatch. Use `sslmode=verify-full` and a trusted database certificate in the production database URL. Terminate TLS and enforce HSTS at a trusted proxy; preserve Origin headers. The API distrusts forwarded IP headers by default, so a reverse proxy requires deliberate trusted-proxy configuration before forwarding-based client IP rate limiting is enabled.

Registration and login share a per-IP limit of 10 attempts per 15 minutes, counting successful attempts too. The limiter holds at most 10,000 entries and fails closed at capacity. It is in-process, resets on restart, and treats clients behind one NAT/proxy as one source. Before multi-instance or high-traffic deployment, add a shared/edge limiter and carefully configured trusted proxies. Password concurrency limiting is also per process.

Use separate least-privileged runtime and migration database roles in production. The runtime needs account/session operations but no DDL. Schedule periodic cleanup of expired/revoked sessions (the `sessions_expiry` index supports this); login-time cleanup alone does not remove stale rows for inactive users. Keep clocks synchronized and tune Argon2 capacity with realistic load tests.

## API

| Method / path | Authentication | Response / behavior |
| --- | --- | --- |
| `GET /api/v1/health` | Public | 200 with status, service, version |
| `GET /api/v1/health/ready` | Public | 200 ready, or 503 after a bounded database check |
| `POST /api/v1/auth/register` | Trusted Origin | `full_name`, `email`, `password`, `confirm_password`; generic 202 message |
| `POST /api/v1/auth/login` | Trusted Origin | `email`, `password`; 200 `{ "user": ... }` and Set-Cookie |
| `POST /api/v1/auth/logout` | Trusted Origin; current cookie if present | 204, revokes session and clears cookie |
| `GET /api/v1/auth/me` | Session | 200 `{ "user": ... }` |
| `GET /api/v1/users/me` | Session | 200 `{ "user": ... }` |
| `PATCH /api/v1/users/me` | Session + trusted Origin | Optional `full_name` and/or `bio` (500 characters); returns updated user |

Public user fields: `id`, `full_name`, `email`, `bio`, `role`, `created_at`. Profile identity comes from the session; client-supplied account IDs, email, role, hash, and timestamp changes are rejected. Errors use `{ "error": { "code": "...", "message": "..." } }`. Common statuses: 400 invalid fields/body, 401 invalid credentials/session, 403 Origin/authorization failure, 415 unsupported media type, 429 throttled (with Retry-After), 503 temporarily unavailable. Error responses never include SQL, stack traces, or secret values.

Manual API example, using a synthetic account only:

```sh
curl -i -H 'Origin: http://localhost:3000' -H 'Content-Type: application/json' \
  -d '{"full_name":"Local Test","email":"local-test@example.invalid","password":"a synthetic long passphrase","confirm_password":"a synthetic long passphrase"}' \
  http://localhost:8080/api/v1/auth/register
curl -i -c /tmp/scamguard-local-cookies -H 'Origin: http://localhost:3000' \
  -H 'Content-Type: application/json' \
  -d '{"email":"local-test@example.invalid","password":"a synthetic long passphrase"}' \
  http://localhost:8080/api/v1/auth/login
curl -b /tmp/scamguard-local-cookies http://localhost:8080/api/v1/users/me
curl -i -X POST -b /tmp/scamguard-local-cookies \
  -H 'Origin: http://localhost:3000' http://localhost:8080/api/v1/auth/logout
```

The temporary curl cookie jar contains a live credential. Restrict its permissions and delete it after use; never commit or share it. Avoid putting real passwords into shell history.

## Migrations

From `backend`, with the environment loaded:

```sh
go run ./cmd/migrate up     # apply all pending versions; repeat safely
go run ./cmd/migrate down   # roll back ONE latest version
go run ./cmd/migrate up     # reapply pending versions
```

The runner discovers embedded SQL versions, uses the existing `schema_migrations` table and advisory transaction lock, and applies changes transactionally. **`down` now rolls back one version**, extending Phase 1's single-version behavior. It refuses unknown database versions. Do not edit deployed migrations; create the next numbered pair. Back up data before rollback.

- `001_initial`: preserved unchanged; users, scans, original constraints/indexes, update timestamp trigger.
- `002_authentication`: adds optional bio (default empty), a unique index on `lower(btrim(email))`, and sessions with user foreign key/cascade deletion, unique 32-byte token hash, creation/expiry/revocation timestamps, and user/expiry indexes. Existing users/scans remain intact. Conflicting legacy emails must be resolved before migration; the migration fails atomically rather than silently deleting/merging accounts.
- Rolling back `002` invalidates all sessions and removes bio values and the additional normalized-email index, while retaining Phase 1 users/scans. A second `down` removes the initial schema and is destructive.

## Testing and verification

Use a **disposable, migrated test database**, not production. After sourcing backend configuration:

```sh
cd backend
TEST_DATABASE_URL="$DATABASE_URL" go test ./...
TEST_DATABASE_URL="$DATABASE_URL" go test -race ./...
go vet ./...
go build -o /tmp/scamguard-api ./cmd/server
```

Without `TEST_DATABASE_URL`, database tests explicitly skip. Authentication integration tests create an isolated temporary schema and remove it afterward; the test role needs schema creation privileges. They cover normalized registration, generic duplicates, validation, hashes, credentials, hashed sessions, rotation, expiry, revocation, protected profiles, safe updates, role escalation, CSRF, CORS, rate limits, production cookie flags, session caps, and rollback preserving users. Existing Phase 1 tests remain active. Rate limiter and Argon2 tests verify resource bounds and cancellation.

Frontend:

```sh
cd frontend
npm ci
npm run lint
npm run typecheck
npm test
npm run build
npm start
```

Type checking generates Next.js route types first, so it works on fresh clones. Unit/component tests cover form validation, login error handling, credentialed logout requests, session loading, redirect decisions, and the existing demo/scanner safeguards. The scoped minimatch override addresses development-tooling advisories; remove it when upstream dependency ranges catch up. Some Next.js plugins still emit ESLint 10 peer-range warnings, but clean installation and lint are validated with the lockfile.

For the browser flow, start the API and production frontend against a disposable database, then launch a separate Chrome profile:

```sh
google-chrome --headless --no-sandbox --disable-gpu --disable-dev-shm-usage \
  --remote-debugging-port=9224 --user-data-dir=/tmp/scamguard-test-chrome about:blank
# In another terminal, from frontend:
npm run test:browser
```

The Chrome profile/debug port are for automated local/CI testing only; keep them loopback-bound and stop Chrome afterward. The browser test uses Node's built-in WebSocket client, creates a unique synthetic account, and tests registration validation, login errors, dashboard authentication, cookie flags, refresh persistence, guest redirects, responsive layout, persisted profile edits, logout/token revocation, and invalidated-session redirects. Configure `SMOKE_APP_URL`, `SMOKE_API_URL`, or `CHROME_DEBUG_URL` if needed. Synthetic test accounts remain in the disposable database until it is discarded.

CI runs Go tests with PostgreSQL 17, migration up/up/down/up, race detection, vet, backend build, frontend lint/types/tests/build, and the real Chrome authentication flow. It does not deploy or merge changes.

## Security, privacy, and future scope

Request logs contain method, registered route, status, and timing; they exclude payloads, passwords, cookie/token values, raw query strings, database URLs, and panic details. HTTP limits/timeouts, bounded database connections, two-second readiness checks, graceful shutdown, `nosniff`, framing restrictions, referrer policy, frontend permissions policy, React text escaping, and parameterized SQL remain in place. Future work must preserve these controls and honor request cancellation. Argon2 computations themselves cannot be interrupted mid-hash; bounded concurrency limits their resource use.

Names, emails, bios, password hashes, and session metadata are now stored. Treat them as personal data: protect database/backups, limit access, document retention/deletion, and avoid sensitive bios. Password reset, email verification, MFA, account deletion/export, distributed throttling, and session-list/revoke-all UX are future work, not hidden capabilities.

Before accepting real scan submissions in Phase 3, implement data minimization, redaction, explicit consent where appropriate, encryption/access controls, configurable retention, and deletion/export. Scan text may contain confidential or financial information. Phase 1's `ON DELETE SET NULL` only removes a scan's user link; it does not scrub the text. No real scan inputs are stored by Phase 2.

Before external URL fetching, implement SSRF protection: HTTP(S) only; reject credentials/unexpected ports; block loopback/private/link-local/reserved IPv4/IPv6 destinations; defend against DNS rebinding; validate each redirect and the actual connection address; restrict outbound networking; isolate workers; never forward credentials; enforce timeout, response-size, and redirect limits. Fetched content is untrusted. Future AI assessments will be advisory and cannot guarantee safety.

## Roadmap and contributions

Phase 1 foundation is merged. Phase 2 implements account/session/profile management and must be reviewed before merging. Phase 3 scanning, AI integration, and phishing classification remain blocked on Phase 2 review and the privacy/SSRF safeguards above.

Branch from current `main`, use focused commits, run the checks above, and document behavior, tests, and limitations in a pull request. Never commit real credentials, environment files, browser profiles, or user data. Do not merge automatically.

Licensed under the [MIT License](LICENSE).
