# Phase 7 security audit

## Scope, baseline and methodology

Reviewed 2026-11-06. Latest fetched `main` was `dbda5cd` (Phase 5). Phase 6 remained in
PR #6; this feature branch retains `7ca5127` as a prerequisite without merging main or
that PR. Review scope includes its report/admin implementation. Phase 6 subsequently merged
into main as `e719e2b` through a separate action before PR #7 opened, so its diff contains
only Phase 7 changes. No deployment or Phase 8 work was performed.

Evidence came from source inspection, synthetic adversarial regressions, a 67-case versioned
corpus compared with the unchanged Phase 6 baseline, disposable PostgreSQL integration tests,
local HTTP/browser tests, modest concurrency/fuzz checks, and dependency/history scanners.
No intrusive testing targeted third parties. The scanner does not fetch submitted URLs.
All AI tests use deterministic mocks; no paid subscription or live provider calls were used.
Public advisory databases and package registries were queried for dependency checks.

This is a code-focused review, not penetration-test certification or a claim that the
application is completely secure. Severity is contextual engineering assessment, not CVSS.
Static call graphs can overapproximate interface dispatch; dependency findings are not
proof that an exploit is reachable through this deployed HTTP configuration.

## Findings register

| ID | Component / severity | Evidence and impact | Recommended remediation / status | Regression evidence |
| --- | --- | --- | --- | --- |
| SG7-001 | Dependencies — High (availability; deployment-dependent) | `govulncheck` reported five symbol-level advisories in x/net 0.57.0 and quic-go 0.59.0: GO-2026-6617, 6612, 6611, 6603, 5676. HTTP/2 crash/flow-control/CPU/trailer and HTTP/3 trailer-exhaustion issues; no exploit traffic was sent. | **Fixed**: x/net 0.62.0, quic-go 0.59.1 and compatible x/* dependencies. Go minimum updated from 1.25.0 to supported 1.26.10. Final symbol/package scan reports zero affected vulnerabilities; module-only findings are reviewed separately below. | `govulncheck ./...`, full race/integration suite; CI security gate. |
| SG7-002 | HTTP and AI JSON parsing — Medium | Standard Go decoding accepted repeated keys, escaped/case-equivalent duplicate keys and missing AI schema fields. Downstream components could interpret ambiguous payloads differently; no role-elevation exploit was demonstrated. | **Fixed**: shared bounded-depth UTF-8/duplicate-key validation, object-only API decoding, unknown-field rejection, one object only; AI required fields cannot be missing/null. | `TestRejectsAmbiguousJSON`, `TestRequestDecoderRejectsDuplicateAndUnexpectedFields`, AI malformed/duplicate tests. |
| SG7-003 | AI privacy redaction — High | Common synthetic forms such as JSON password values, “OTP is 123456”, URL userinfo and encoded query names survived the old redactor before provider transmission. | **Fixed for verified formats**: redact quoted/assignment credentials, short numeric codes, URL userinfo, entire URL queries and fragments. Rules run on local content first. Redaction remains heuristic, not comprehensive DLP; arbitrary secrets in paths/prose remain a residual risk. | `TestCredentialRedactionRegression`; request-body privacy tests. |
| SG7-004 | AI transport — Medium | Default redirect following could forward untrusted scan request bodies away from the fixed provider endpoint; per-attempt timeout allowed a longer total retry budget. | **Fixed**: do not follow redirects; one total analysis deadline includes retries. API key/model/endpoint remain server-controlled and no tools are supplied. | `TestProviderRejectsRedirectsAndOversizedOrTrailingJSON`, `TestProviderTotalTimeoutIncludesRetryBudget`. |
| SG7-005 | AI provider response limits — Medium | A decoder over LimitReader could accept a valid early object while ignoring trailing data; envelope duplicate keys also went unchecked. | **Fixed**: read at most 1 MiB plus one sentinel byte, reject oversize and ambiguous/trailing JSON, then decode. Assessment text is separately bounded to 16 KB and normalized/redacted. | Oversized, duplicate, trailing envelope tests and assessment schema tests. |
| SG7-006 | Credential detection evasion — Medium | A safety notice anywhere in a message disabled all sensitive-information request detection, including a separate explicit OTP request. | **Fixed**: sentence/clause-local notice handling; word-bounded credential/BVN/NIN vocabulary. Not a general semantic negation solver. | `TestSafetyNoticeDoesNotSuppressSeparateTheftRequest`, word-boundary tests, corpus `credentials-03/04`. |
| SG7-007 | Detection determinism / false positives — Low | Map iteration selected the first mentioned brand, so multi-brand official links could receive inconsistent scores. Negated “do not send money” advice was classified as a prize payment request. | **Fixed**: check all mentioned brand domains before deciding mismatch; clause-scoped negated-payment advice. No scoring weights/thresholds were tuned. | Repeated multi-brand checks, negative advice regression, measured corpus comparison. |
| SG7-008 | URL parsing — Low | The lexical engine accepted oversized direct inputs, malformed DNS labels, out-of-range ports and confusing backslash/format-control text. There was no SSRF because URLs are never fetched. | **Fixed**: parser-level byte/UTF-8/label/port/control constraints before classification. IDNA/public suffix boundaries retained. | URL edge-case table, IP/IDN/userinfo/encoding controls, fuzz test and no-network transport guard. |
| SG7-009 | CORS header ambiguity — Low | Read/preflight CORS handling selected one Origin header although CSRF rejected repeated Origins on mutations. | **Fixed**: reject repeated Origin headers consistently; retain exact allowlist and credentialed CORS. API responses add default-none/frame-ancestor CSP as defense in depth. | `TestDuplicateOriginsRejectedOnReadsAndMutations`; existing CORS/CSRF suites. |
| SG7-010 | CI supply chain / scanning — Medium | Action tags were mutable and no automated dependency/secret checks existed. | **Fixed**: immutable release commit pins, pinned scanner versions, source/history scans, dependency checks, fuzzing and local-only browser tests. | Configured `Backend checks`, `Frontend checks`, `Security checks`; hosted status must be verified on PR. |
| SG7-011 | Secret scan result — Informational | A generic-key rule matched the historical README phrase describing session storage. Inspection confirmed prose, not a credential. Initial directory scan also saw generated Next cache keys outside source. | **Reviewed**: one exact commit/path/rule/line fingerprint in `.gitleaksignore`; wording changed. Source snapshot excludes ignored build/local files without broad detection-rule exceptions. No real committed credential was identified by these scans. | Final redacted history and source snapshot scans. |

## Component review and preserved controls

| Area | Observed control and verification |
| --- | --- |
| Passwords / registration | Argon2id 64 MiB, 3 iterations, one lane; random 16-byte salt and 32-byte output. Two concurrent hashing slots bound memory. Fixed permitted stored hash parameters, constant-time key comparison, UTF-8/byte/name/email validation; public registration always assigns user. Duplicate and unknown account responses remain generic. |
| Sessions / cookies | Cryptographic 32-byte random opaque tokens; only SHA-256 digests stored. Session expiry/revocation and live user role/status queried server-side. Login rotation, logout revocation, five-session cap under row locks. Production host-only Secure/HttpOnly/SameSite=Lax cookies; strict Origin checks supplement SameSite. Expired, revoked, forged/tampered and concurrent scenarios tested. |
| Authorization / ownership | Every protected group requires authentication; every admin handler requires server-derived admin role. Owner predicates protect scan read/delete/report/export/statistics. Status bodies cannot set roles; self/last-admin protections and transactional session revocation retained. Ordinary users never receive private scan content through admin analytics. |
| Provisioning | Authenticated operator DB/OS boundary, active-account-only promotion with transactional audit and DB session identity. No public promotion route. Production must restrict operator/runtime/schema-owner privileges as described in README. |
| HTTP / errors | 16 KB API body cap, scan input limits, strict decoding, bounded pagination and query allowlists, trusted-Origin mutation requirement, exact credentialed CORS, bounded per-process limiters, no trusted forwarded IPs. Recovery/error handlers log safe static messages, routes and status without body/token/stack dumps. |
| Server lifecycle | Header/read/write/idle and application timeouts exist; graceful SIGTERM shutdown has a ten-second context. Existing operational behavior inspected; production signal/ingress behavior still requires deployment-environment verification. |
| URL scanning | HTTP(S) only; no URL fetch, DNS lookup, redirects, reputation requests or URL-controlled transport. Private/link-local/IP examples are parsed lexically, not contacted. IDNA Lookup and publicsuffix identify host/domain boundaries; these patterns are not reputation verification. |
| AI integration | Key stays server-side, fixed endpoint/model/instructions, inert quoted data, no tools, store=false, bounded input/output/retry/cost controls, rules cannot be lowered by AI. Mock tests prove application configuration/score invariants, not general model obedience or semantic truth. |
| Database / deletion | Parameterized SQL, risk/role/status constraints, separate sessions/scans, no submitted-content column, no persistence of raw OTP/password fields by default. Deleted scans disappear from list/stats/export. Closed-pool failures reject authentication with safe 503 responses. Disposable migrations remain compatible; no Phase 7 migration was required. |
| Reports / CSV | Owner-scoped saved fields, no public report storage, fixed attachment names, correct content types, no-store/nosniff. PDF concurrency/text/page/output caps and glyph replacement retained; injection/Unicode/long text tested as inert data. CSV formula prefixes escaped and >10,000-row exports rejected. |
| Frontend | No unsafe HTML rendering or credential localStorage/sessionStorage found in src. React text escaping, advisory labels, score text alongside colors, server-backed auth invalidation, hidden regular-user admin nav and backend checks. Browser test verifies an HTML-shaped profile value remains text. |
| Accessibility | Existing skip link/labels/status/error semantics, keyboard-contained admin confirmation, accessible meters and responsive tables retained. Real Chrome mobile checks cover admin pages. A complete manual assistive-technology audit remains outstanding. |
| CI / Compose | Least-privilege contents:read; no deployment jobs. Local Compose DB binds loopback and requires supplied password. CI-only test credentials are synthetic; production credentials must never reuse them. Immutable Actions SHAs resolved from official v6 tags. |

## Dependency and secret review

Sources: [Go vulnerability tooling](https://go.dev/doc/security/vuln/),
[Go supported downloads](https://go.dev/dl/),
[Gitleaks v8.30.1](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1), and the
[Go advisory database](https://pkg.go.dev/vuln/). Tests did not probe affected third-party services.
`npm audit` reported zero advisories for the lockfile. No risky npm major-version upgrade
was performed. Go dependencies were advanced only to compatible fixed versions; full tests
were rerun. The old govulncheck binary built with the machine's Go 1.22 could not analyze the
newer dependency graph; rebuilding the pinned scanner with supported Go resolved the tool error.

Verbose scanning after the first compatible fixes also identified module-only GO-2026-6866
and GO-2026-6860 in the unimported HTML package, and GO-2026-5932 in unimported OpenPGP.
These were not reachable package findings. Rather than suppress them, x/net was advanced to
0.62.0 and x/crypto to the exact fixed revision
`v0.58.1-0.20261009181718-2f1f834330b2` cited by the advisory (no later 0.59.0 tag exists).
The application uses Argon2, not OpenPGP. Full compatibility tests and verbose scanning were
rerun; the final verbose scan reports no vulnerabilities at symbol, package or module level. Pseudo-version selection is intentional and
pinned in go.mod/go.sum; revisit when an equivalent stable tag is available.

The secret scanner reads all git history and a private snapshot from `git ls-files` including
non-ignored new files. It does not publish raw findings or scan ignored runtime .env/build caches.
`.gitleaksignore` excludes exactly one reviewed historical prose finding; future matches remain
blocking. Ignored deployment secrets, external secret stores and operator machines are outside
this repository scan. No known real-secret rotation was required by the observed findings.

## Verification and measured results

- `go test -race ./...` with disposable PostgreSQL: passed after dependency updates.
- `go vet ./...` and server/operator builds: passed.
- Frontend lint and TypeScript validation: passed. `npm test`: **21 passed**, no failures/skips.
- Frontend production build: passed; report/admin routes remain generated.
- Final five-second-budget URL fuzz run with two workers (6.064 seconds including shutdown): **33,896 executions**, no panic/invariant failure.
- Modest local scanner load: **200 messages / eight goroutines in 4.300513 ms** on this machine.
  This is an engine-only micro-measurement, not an HTTP throughput, p95 latency or capacity SLO.
- Corpus: 67 cases; 34 TP / 25 TN / 0 FP / 4 FN, with 4 ambiguous excluded. See
  [detection evaluation](detection-evaluation.md) for denominators and caveats.
- Report output/limits, CSV formula prefixes/row limit, no-network URL safety, AI unavailable,
  strict retry budget, closed database pool, rate limits, and session concurrency are tested.
- All three local Chrome suites passed: existing authentication/scanner/profile/session journey, new real PDF/CSV download and cross-user security journey, and admin/pagination/confirmation/mobile journey.
- The duplicate-key and JSON credential redaction gaps were also reproduced on the unchanged baseline with synthetic local tests.
- The browser helpers now correctly handle bodyless 204 responses and download completion. Responsive assertions wait for ResizeObserver layout settlement; a local 768px probe showed no persistent overflow (scroll width 753px), and the unchanged width assertions pass.
- Hosted CI is a separate gate: use the PR Checks tab for the current head SHA. This source document does not assert hosted success from local checks.

No intrusive load testing, external URL crawling, live AI evaluation, production migration,
production data deletion, deployment, or automated PR merge was performed.

## Residual risks and release position

No verified unresolved high/critical application defect may be accepted silently. Keep deployment
gated on a green PR run, independent review, module-advisory disposition and the
[production checklist](production-readiness.md). Existing limitations remain: distributed rate
limits are not implemented, account email ownership is not verified, regex redaction is not DLP,
audit owners can bypass triggers, retention/backups are operator responsibilities, and original
AI summaries were not retained. Email verification/password recovery are absent features, not
new claims of protection; operators must approve account-lifecycle risk before public launch.

Detection still misses two delivery scams under the unchanged score threshold and two non-English
credential requests in this corpus. Prompt injection tests do not establish universal semantic
resistance. No frontend nonce-based CSP or deployment HSTS policy was added; HTTPS/ingress policy
must be verified without breaking Next hydration. Local readiness is not production approval.

## Phase 7 file inventory

This inventory is relative to the Phase 6 baseline. Phase 6 merged into main during the
review, before PR #7 was opened; the PR diff contains these Phase 7 changes only.

- `.github/workflows/ci.yml`
- `.gitleaksignore`
- `README.md`
- `backend/cmd/evaluate/main.go`
- `backend/go.mod`
- `backend/go.sum`
- `backend/internal/ai/assessment.go`
- `backend/internal/ai/openai.go`
- `backend/internal/ai/redact.go`
- `backend/internal/ai/security_test.go`
- `backend/internal/detection/message.go`
- `backend/internal/detection/security_test.go`
- `backend/internal/detection/url.go`
- `backend/internal/evaluation/evaluate.go`
- `backend/internal/evaluation/evaluate_test.go`
- `backend/internal/evaluation/testdata/synthetic.json`
- `backend/internal/handlers/admin.go`
- `backend/internal/handlers/auth.go`
- `backend/internal/handlers/history_test.go`
- `backend/internal/handlers/security_test.go`
- `backend/internal/middleware/middleware.go`
- `backend/internal/middleware/security_test.go`
- `backend/internal/reports/security_test.go`
- `backend/internal/router/auth_integration_test.go`
- `backend/internal/strictjson/json.go`
- `backend/internal/strictjson/json_test.go`
- `docs/detection-evaluation-results.json`
- `docs/detection-evaluation.md`
- `docs/production-readiness.md`
- `docs/security-audit.md`
- `frontend/package.json`
- `frontend/scripts/admin-smoke.mjs`
- `frontend/scripts/auth-smoke.mjs`
- `frontend/scripts/local-targets.d.mts`
- `frontend/scripts/local-targets.mjs`
- `frontend/scripts/security-smoke.mjs`
- `frontend/tests/security.test.tsx`
- `scripts/scan-secrets.py`
