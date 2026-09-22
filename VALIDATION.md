# Validation

Validated on 2026-09-16 with Go 1.27.1, PostgreSQL 16.2, and Chromium.

- `go test -race -p 1 ./...` with a real PostgreSQL test database: passed.
- `go vet -p 1 ./...`: passed.
- Concurrent startup test: 24 instances share one logical pending approval; each receives only its own requested paths.
- Lifecycle tests: approval, denial, persistent restart grants, revocation under load, disabled applications, token rotation, permission changes, and cross-application polling isolation passed.
- Secret tests: envelope encryption, authenticated path/version binding, tamper rejection, immutable/concurrent versions, restore, archive, and unarchive passed.
- Browser test: admin login, masked editing, version creation, one-time token, four-instance SSE approval, secret retrieval, restart, revocation, denial, and mobile overflow check passed.
- Docker image build: passed. The container ran as UID 1000 with a read-only filesystem, all capabilities dropped, and no-new-privileges enabled; database health and the embedded login UI responded successfully.
- Compose configuration validation: passed.
- `govulncheck`: no findings in imported packages or reachable code. Module-level finding GO-2026-5932 concerns `golang.org/x/crypto/openpgp`, which this project does not import. LockGate uses `argon2` from that module.

An additional parallel race-test run during the Docker build exceeded test database setup/cleanup deadlines on the busy shared host. The final sequential-package run passed; concurrency within the access test remained enabled. `make integration` runs test packages sequentially to reduce peak resource use.

Tests used disposable credentials and isolated schemas. The initial validation did not deploy a persistent service. Runtime configuration and first-admin creation are documented in README.md; the subsequent deployment is recorded below.

## External database deployment

- Created database `lockgate` on the user-supplied PostgreSQL server at `213.238.180.233:5432`.
- Added `POSTGRE_DSN` support, retaining `DATABASE_URL` compatibility.
- Default Compose now uses the external database; the original bundled-database setup is retained in `compose.local.yaml`.
- Selected unused host port `18430`, mapped to container port `8080`.
- Created the file-based master key and initial admin account with a random password; credentials are excluded from build context and source archives.
- `go test -p 1 ./...` and `go vet -p 1 ./...` passed for the configuration change. PostgreSQL integration tests were not pointed at the live database.
- Docker build, migrations, health check, actual admin login, dashboard response, and logout passed.
- Container `lockgate-lockgate-1` is healthy, uses `restart: unless-stopped`, and remains running.
- Endpoint: `http://213.238.180.233:18430/admin`. TLS is not configured for this direct HTTP endpoint; the explicit HTTP-cookie option is enabled. PostgreSQL uses the requested `sslmode=disable`.
- Redis was not added: the current application uses PostgreSQL for its persistent state and sessions.

## Dark theme and browser icon

- Added a light/dark theme control to the login and authenticated admin layouts.
- The first visit follows the operating system color scheme; an explicit choice is stored in browser local storage.
- Added an embedded SVG favicon and theme color metadata.
- Verified on the public HTTPS endpoint with Chromium: toggle behavior, persistence after reload, CSP-compatible scripts, computed dark background, favicon response and content type.
- `go test -p 1 ./...` and `go vet -p 1 ./...` passed. The rebuilt Docker container is healthy.

## In-app documentation

- Added an authenticated `/admin/docs` page and Docs navigation item.
- Documented the startup flow, environment variables, Docker Compose, raw HTTP access, JavaScript, Python, the optional local Go helper, response states, and operational security.
- Examples use the configured public origin and placeholder credentials only.
- Verified on public HTTPS with Chromium: authenticated navigation, language-neutral guidance, JavaScript/Python/Go examples, visible syntax token colors, clean copied source text, mobile viewport containment, and no browser console errors.
- `go test -p 1 ./...` and `go vet -p 1 ./...` passed; the rebuilt Docker container is healthy.

- Clarified that no public `lockgate` Go package or SDK exists. LockGate integrations are language independent through its JSON/HTTP API.

## Secret JSON editor

- Added live JSON syntax highlighting to secret creation and version editing fields.
- Added one-click pretty formatting and inline validation for malformed JSON, non-object roots, empty objects, and non-string values.
- Verified on the public HTTPS endpoint with Chromium: token coloring, two-space formatting, browser validity blocking, invalid-input feedback, recovery after correction, and no page errors.
- `go test -p 1 ./...`, `go vet -p 1 ./...`, and JavaScript syntax validation passed; the rebuilt Docker container is healthy.

## Go client documentation and secret addressing

- Added `GetSecret(ctx, path)`, which returns one bundle directly as `map[string]string`; the existing multi-bundle API remains compatible.
- Moved the example secret identifier into `LOCKGATE_SECRET_PATH` and documented paths as bundle identifiers and authorization boundaries.
- Added an in-app explanation of the client's POST, approval polling, response extraction, and fail-closed behavior.
- `go test -p 1 ./...` and `go vet -p 1 ./...` passed. Chromium verified the live documentation content and syntax highlighting without page errors.

## Token-only application configuration

- Added a path-free access mode: omitting `secrets` makes LockGate resolve the application, environment, and current assigned secrets from the application token.
- Added Go `GetConfig(ctx)` for the recommended single-bundle setup and `GetConfigured(ctx)` for multiple admin-assigned bundles. Explicit path APIs remain compatible.
- Integration coverage verifies token-side path expansion, exclusion of unrelated secrets, approval contents, and delivery after approval.
- `go test -p 1 ./...` and `go vet -p 1 ./...` passed. Chromium verified the live token-only documentation without page errors; the rebuilt container is healthy.

## Tabbed language documentation

- Consolidated JavaScript, Python, and Go examples into one accessible tab interface with click and keyboard navigation.
- Added a complete, dependency-free Go client implementation covering token-only access, idempotency, approval polling, context cancellation, redirect blocking, URL validation, response limits, and fail-closed errors.
- The documented Go client compiled successfully as a standalone package.
- `go test -p 1 ./...`, `go vet -p 1 ./...`, and JavaScript syntax validation passed. Chromium verified tab state, keyboard navigation, syntax highlighting, Go implementation content, mobile containment, and no page errors on the live endpoint.

## Admin UI performance

- Found that the global `no-store` policy forced CSS, JavaScript, theme initialization, and favicon assets to be downloaded on every server-rendered navigation.
- Added SHA-256 content-versioned asset URLs and `public, max-age=31536000, immutable` caching for embedded static files. Sensitive HTML and API responses remain `no-store`.
- Live Chromium measurements on the same route sequence improved authenticated page loads from 228–361 ms to 112–205 ms. Static headers and automatic hash changes were verified over public HTTPS.
- `go test -count=1 -p 1 ./...` and `go vet -p 1 ./...` passed; the rebuilt container is healthy.
