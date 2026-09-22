# LockGate

A small, self-hosted secret manager: store encrypted secrets, give applications scoped tokens, and approve access before secrets are delivered. One Go binary serves the admin UI and application API. PostgreSQL is the only service dependency.

## Quick start with Go

Requires Go 1.26+ and PostgreSQL 16+. Use a dedicated database and database role. The role needs permission to create tables, indexes, and migration functions in its schema.

```sh
go mod download
make build
mkdir -p .local
./bin/lockgate keygen .local/master.key
export DATABASE_URL='postgres://lockgate:password@localhost:5432/lockgate?sslmode=disable'
export LOCKGATE_MASTER_KEY_FILE="$PWD/.local/master.key"
export LOCKGATE_ORIGIN='http://localhost:8080'
export LOCKGATE_INSECURE_DEV_COOKIES=true
```

Create the first admin with a password file, so the password is not a command-line argument. Use at least 12 characters. In Bash:

```sh
(umask 077; read -rsp 'Admin password: ' password; printf '\n'; printf '%s' "$password" > .local/admin-password)
LOCKGATE_ADMIN_PASSWORD_FILE="$PWD/.local/admin-password" ./bin/lockgate admin-create admin
rm .local/admin-password
./bin/lockgate serve
```

Open **http://localhost:8080/admin**. Use this exact origin, since CSRF checks compare browser origins. The server defaults to `127.0.0.1:8080`. Migrations run automatically on startup and admin creation; `lockgate migrate` is also available. There are no default admin credentials.

1. Create `apps/crypto-backend/production` with a JSON string-to-string object such as `{"DB_USER":"postgres","DB_PASSWORD":"example"}`.
2. Create `crypto-backend`, environment `production`, allowed path `apps/crypto-backend/production`.
3. Copy the token, which is displayed only once.
4. Run the example using `LOCKGATE_URL` and `LOCKGATE_TOKEN`.
5. Open Approvals and click **Approve access**.
6. Restart the example: it receives secrets without another approval.
7. Revoke access on the application page: the next retrieval waits for approval again.

```sh
export LOCKGATE_URL=http://localhost:8080
# Supply LOCKGATE_TOKEN securely through your environment; do not commit it.
go run ./examples/startup
```

## Docker Compose with an existing PostgreSQL server

The default `compose.yaml` starts only LockGate. It connects to the database specified by `POSTGRE_DSN`; it does not start PostgreSQL or Redis. Redis is not required for sessions, grants, or approval notifications.

```sh
cp .env.example .env
# Supply the real POSTGRE_DSN password in .env and keep this file private.
chmod 600 .env
# Select an unused LOCKGATE_PORT and set LOCKGATE_ORIGIN to that exact address.
docker compose build
mkdir -p .local
# Create the key before starting Compose; this never overwrites an existing key.
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/.local:/keys" lockgate:local keygen /keys/master.key
```

Set `LOCKGATE_UID` and `LOCKGATE_GID` in `.env` to your host UID/GID so the unprivileged container can read the mode-0600 key. The PostgreSQL database must already exist; LockGate applies its embedded migrations automatically.

Create `.local/admin-password` using the password-file instructions above, then:

```sh
docker compose run --rm -T \
  -e LOCKGATE_ADMIN_PASSWORD_FILE=/run/admin-password \
  -v "$PWD/.local/admin-password:/run/admin-password:ro" \
  lockgate admin-create admin
rm .local/admin-password
docker compose up -d
docker compose ps
```

The supplied external-server example uses `http://213.238.180.233:18430/admin`. Direct HTTP requires the explicit insecure-cookie opt-in. When you add a TLS proxy, update the origin to `https://...`, set `LOCKGATE_INSECURE_DEV_COOKIES=false`, and optionally bind the published port to loopback.

A bundled PostgreSQL option is preserved in `compose.local.yaml` and `.env.local.example`. To use it, copy `.env.local.example` to `.env.local`, set its password, and invoke `docker compose --env-file .env.local -f compose.local.yaml ...` instead. Choose one Compose setup per project directory. The local setup publishes port 8080 on loopback and requires that port to be free.

An application on LockGate's Compose network uses `LOCKGATE_URL=http://lockgate:8080`. Remote applications use the external origin. Authentication and client code are identical.

## Production / Linux / VPS

Deploy `bin/lockgate`, PostgreSQL, a master key file, and a TLS reverse proxy. Example systemd and Nginx configuration lives in `deploy/`; these files are examples, not automatically installed. Run the binary as a dedicated unprivileged user. Make the master key readable only by that user (`0600` or `0400`).

Set `LOCKGATE_ORIGIN=https://lockgate.internal` and **remove** `LOCKGATE_INSECURE_DEV_COOKIES` (or set it to `false`). The app serves HTTP behind your TLS proxy. Production session cookies are `Secure`, `HttpOnly`, and `SameSite=Strict`; all browser mutations also require CSRF tokens and a matching Origin/Referer. Local HTTP works only with the explicit insecure development cookie opt-in. Application token authentication is identical in all environments.

| Variable | Purpose / default |
| --- | --- |
| `POSTGRE_DSN` | PostgreSQL keyword DSN, such as `host=... user=... password=... dbname=lockgate port=5432 sslmode=disable`. Takes precedence over `DATABASE_URL`. |
| `DATABASE_URL` | Backward-compatible PostgreSQL URL when `POSTGRE_DSN` is unset. Use `sslmode=verify-full` with an appropriate CA for TLS verification. |
| `LOCKGATE_PORT` / `LOCKGATE_BIND` | Compose host port/address; defaults to `18430` / `127.0.0.1`. |
| `LOCKGATE_MASTER_KEY_FILE` | Base64 32-byte key; defaults to `/run/secrets/lockgate-master-key`. |
| `LOCKGATE_ADDR` | HTTP bind address, default `127.0.0.1:8080`. |
| `LOCKGATE_ORIGIN` | Exact external origin, default `https://localhost:8080`; no trailing slash or path. |
| `LOCKGATE_INSECURE_DEV_COOKIES` | Set exactly `true` only for local HTTP development. Default false. |
| `LOCKGATE_ADMIN_PASSWORD_FILE` | Password file consumed only by `admin-create`. |
| `LOCKGATE_TEST_DATABASE_URL` | Disposable database for integration tests. |

`GET /healthz` checks database connectivity. SIGINT/SIGTERM triggers graceful shutdown. No request bodies or credentials are logged. Audit IPs use the direct TCP peer: forwarded headers are deliberately not trusted. Behind a reverse proxy, IP audit entries and login rate limits therefore use the proxy address. Login is limited to 10 attempts per peer per 10 minutes, with at most two simultaneous Argon2id calculations. For public exposure, add a proxy-level login limit using your trusted proxy configuration. Admin sessions expire after 12 hours and are stored hashed in PostgreSQL.

## Language support and optional Go helper

LockGate is language independent. Applications use its JSON/HTTP API, so JavaScript, Python, PHP, Java, Rust, Go, and any environment with an HTTP client can request secrets. The authenticated `/admin/docs` screen contains curl, JavaScript, and Python examples.

There is no published `lockgate` Go package. This source tree includes a small optional helper in `pkg/client`; the module path `lockgate` is local to this project. To use that helper from a different repository, first publish or fork the module under a real repository import path, copy the helper into your project, or use a local `replace` directive during development.

```go
import lockgate "lockgate/pkg/client"

client := lockgate.New(lockgate.Config{
    URL:   os.Getenv("LOCKGATE_URL"),
    Token: os.Getenv("LOCKGATE_TOKEN"),
})
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
defer cancel()
values, err := client.GetConfig(ctx)
if err != nil {
    log.Fatal(err) // Errors never contain token or secret values.
}
// Configure your application directly from values["DB_PASSWORD"].
```

`GetConfig` sends only the token to `POST /api/v1/access`. LockGate resolves the application, environment, and assigned secrets from that token. If approval is pending, the client polls the returned opaque request ID every three seconds (or at the server's longer advised interval), then returns the application's single configured bundle as `map[string]string`. `GetConfigured` returns multiple assigned bundles when needed; `Get` and `WaitForSecrets` retain explicit-path access for compatibility. A context deadline bounds startup. Explicit denial returns `client.ErrDenied`. Network errors return immediately; there is no fallback to silently starting without secrets. HTTP redirects are rejected to prevent token forwarding. The client generates an instance idempotency key so POST retries can identify the same instance. Secrets are not written to disk or environment variables by the client.

Secret paths are admin-side bundle identifiers and authorization boundaries, not application configuration. Application code does not send a path or environment: its token already identifies both the application and its server-side environment record. For a small service, assign one bundle such as `apps/crypto-backend/production`; split it only when values need different access or update lifecycles.

## Application API

Browser sessions never authorize machine APIs. Use `Authorization: Bearer lg_app_...`.

`POST /api/v1/access` with `Content-Type: application/json`:

```json
{}
```

An omitted `secrets` field means “use the secrets assigned to this token.” LockGate expands the application's allowed paths against current, non-archived secrets. Explicit `{"secrets":["..."]}` requests remain supported for callers that need a subset.

An optional `Idempotency-Key` header (up to 128 characters) identifies one startup attempt. Repeating the key with the same resolved paths joins the same instance; changing its path set returns 409. Clients without this header count each POST as a new instance. Do not share an instance key across replicas.

No grant: HTTP 202, `Retry-After: 3`:

```json
{"status":"waiting_approval","request_id":"instance-handle","approval_id":"shared-approval","retry_after":3}
```

Poll `GET /api/v1/access/{request_id}` every three seconds with the same application token. The `request_id` is an opaque per-instance handle; all waiting instances share one logical `approval_id`. Each instance receives only its own requested secret set, even when the admin sees the union of all requests.

Approved requests return HTTP 200:

```json
{"status":"approved","secrets":{"projects/crypto/prod/database":{"DB_USER":"postgres","DB_PASSWORD":"..."}}}
```

Denied requests return `{"status":"denied", ...}`. Revoked polling handles return `{"status":"revoked", ...}`; POST again to request a new approval. The Go client handles this automatically. Requests revalidate application status, token, path permissions, and active grant. Unauthorized paths return 403 and never create approvals; unknown allowed secrets return 404. Invalid/disabled tokens return 401.

## Grants and concurrency

An application is unique by `(name, environment)`. Approval grants access to its **entire configured allowed path boundary**, not only the paths shown in the current request. The UI explicitly shows this. Patterns are either exact paths or descendant prefixes ending in `/*`; arbitrary glob syntax, traversal, leading/trailing slashes, and empty path segments are rejected. Paths are case-sensitive.

A PostgreSQL partial unique index permits only one pending approval per application and one active grant. Access checks, approval, denial, revocation, rotation, and permission changes serialize on the application's row in transactions. Instance joins are atomic upserts. The dashboard counts pending approvals; the approval screen shows instances seen in the last 30 seconds. Instance records and their requested paths remain available after their heartbeat expires so an approval never silently omits an earlier request. SSE sends metadata change notifications every three seconds and revalidates the admin session on each tick.

Grants default to **until revoked**. Expiring grants are represented in storage and checked on retrieval, but the MVP UI only creates indefinite grants. Disabling, rotating tokens, or editing allowed paths revokes grants and invalidates pending/approved polling handles. Re-enabling does not restore access. Denial is terminal for that request; a new explicit startup request may ask again. Revocation prevents retrievals authorized after it commits; it cannot recall responses already authorized or secret values an application has already received.

## Encryption and versioning

Every version gets a random 256-bit DEK. AES-256-GCM encrypts its JSON payload; a separate random GCM nonce wraps the DEK with the master key. Path, immutable version number, and key version are authenticated associated data, preventing ciphertext from being moved between versions or paths. The database stores ciphertext, nonce, nonce-prefixed wrapped DEK, algorithm, and key version. The master key is never stored in PostgreSQL. `secure.KeyProvider` is the small future extension point; the file provider supports `file-v1` only. Changing the master key file without rewrapping makes existing secrets unreadable; automatic key rotation is not part of this MVP.

Database triggers reject modification/deletion of secret version rows. Concurrent updates allocate monotonically increasing versions under a secret row lock. Restoring an old version decrypts and re-encrypts into a new version. Archiving removes a secret path from machine access while retaining encrypted history; restoring or saving the path unarchives it. The UI shows version metadata and visually masks current values by default. The authenticated detail page contains those values in its HTML for editing and is audited as a secret read; masking is not a separate authorization boundary. All application and admin responses use `Cache-Control: no-store`.

## Backups and trust boundaries

Back up PostgreSQL **and** the master key, separately. Losing the key means losing the secrets. Test restoring both. Database metadata (application names, paths, audit events) is not encrypted, but secret values are. Application tokens have 256 bits of entropy and only SHA-256 hashes are stored. Admin passwords use Argon2id (64 MiB, 3 iterations, parallelism 2). The application necessarily holds decrypted secrets in memory while serving authorized requests.

Keep application tokens out of Git, Docker images, shell history, and logs. Passing them through environment variables is an intentional MVP tradeoff. Use TLS for remote token/secret transport. All admins have full administrative privileges. This is a small deployment tool, with no agents, enrollment, cloud identity, SSO, dynamic credentials, HA, or other Vault-style infrastructure. Audit events are transactionally recorded for state changes and successful reads; audit retention is currently manual, and the UI displays the newest 200 events.

## Tests

```sh
go test ./... # unit tests; integration tests explicitly skip without a database
# Use an isolated disposable PostgreSQL database. Tests create/drop random schemas.
export LOCKGATE_TEST_DATABASE_URL='postgres://lockgate:password@127.0.0.1:5432/lockgate_test?sslmode=disable'
make integration
```

Integration tests exercise 24 simultaneous startups, shared approvals with different path sets, instance deduplication, database uniqueness constraints, approval/denial, restart grants, revocation under load, token rotation, disabled applications, cross-application polling rejection, changed path boundaries, concurrent secret versions, immutable versions, restore, real HTTP login/CSRF/cookie flags, UI rendering, machine/session auth separation, SSE, and the Go client. Unit tests cover encryption tampering/context binding, tokens/passwords, path boundaries, client denial/cancellation/network failure, and redirect protection.

## Layout

- `cmd/lockgate`: configuration, CLI, startup and shutdown.
- `internal/store`: small transactional PostgreSQL services.
- `internal/secure`: envelope encryption, password/token hashing, path matching.
- `internal/server`: browser and machine handlers, sessions, CSRF, SSE.
- `web`: embedded Go templates, CSS, vanilla JavaScript.
- `migrations`: embedded, ordered SQL migrations tracked in PostgreSQL.
- `pkg/client`: context-aware application integration.
- `deploy`: optional Linux deployment examples.

For the real-browser smoke test, install Playwright in your test tooling (not as an application dependency), point `LOCKGATE_BROWSER_URL` at a disposable running instance, set `LOCKGATE_BROWSER_PASSWORD` for its `admin` account, and run `node tests/browser.cjs`. It exercises the UI plus machine API, verifies SSE updates without a manual refresh, and writes screenshots under `.local/screenshots`. It creates test secrets/applications, so do not point it at a production workspace.
