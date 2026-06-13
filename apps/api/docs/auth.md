# Authentication Module

## Production Checklist

- Configure `DATABASE_URL`, `JWT_ACCESS_SECRET` for HS256 or `JWT_ALGORITHM=RS256` with `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEYS` and `JWT_KEY_ID`, `JWT_ISSUER`, `JWT_AUDIENCE`, `PASSWORD_PEPPER`, `TOKEN_HASH_SECRET`, `EMAIL_OUTBOX_ENCRYPTION_KEY`, `EMAIL_OUTBOX_ENCRYPTION_KEY_ID`, `CSRF_SECRET`, `APP_URL`, `CORS_ORIGIN`, `RATE_LIMIT_REDIS_URL`, `METRICS_TOKEN` when metrics are enabled, and email provider variables.
- Keep `PASSWORD_PEPPER` and `TOKEN_HASH_SECRET` different. Password hashes and opaque token hashes must not share the same secret.
- Keep `REFRESH_IDEMPOTENCY_SECRET` different from password/token secrets. It encrypts short-lived refresh replay responses.
- Production startup fails if `CSRF_SECRET`, `TOKEN_HASH_SECRET`, or `EMAIL_OUTBOX_ENCRYPTION_KEY` still uses a development default, `RATE_LIMIT_REDIS_URL` is missing, `APP_URL`/`CORS_ORIGIN` points to a local address, SMTP best-effort mode is not explicitly allowed, or `EXPOSE_AUTH_TOKENS=true` outside the allowed local/test contexts.
- Production also requires token cleanup to be scheduled through `TOKEN_CLEANUP_WORKER_ENABLED=true` or `TOKEN_CLEANUP_EXTERNAL_SCHEDULED=true`.
- If this API serves HTML/docs/static web content, set `SERVE_WEB_CONTENT=true` and `HELMET_CSP_ENABLED=true`; API-only deployments can keep CSP disabled while retaining other Helmet headers.
- Run Prisma migrations before starting the API.
- Before applying `20260610120000_auth_production_hardening`, make sure `20260604103000_auth_multitenant_outbox_hardening` has added nullable `Store.organizationId`, backfill every existing store with `npm run tenant:backfill-stores`, then verify with `npm run tenant:preflight`.
- Use HTTPS in production so refresh and CSRF cookies are sent with `secure: true`.
- Run integration tests against a disposable PostgreSQL database before deploy.
- Keep `EXPOSE_AUTH_TOKENS=false` outside automated tests and strict localhost development.
- Set `TRUST_PROXY=true` only when the API is behind a trusted reverse proxy or load balancer.
- Security headers are enabled through Helmet. Every response includes `x-request-id` and `x-correlation-id`.
- Keep `API_KEY_ENDPOINTS_ENABLED=false` and `MFA_ENDPOINTS_ENABLED=false` until rotation, recovery, audit, rate-limit and UX policies are fully approved.
- If operational webhook export is enabled, configure `OPERATIONAL_EVENTS_WEBHOOK_URL`, `OPERATIONAL_EVENTS_WEBHOOK_TOKEN`, `OTEL_SERVICE_NAME`, `OTEL_DEPLOYMENT_ENVIRONMENT`, and `OTEL_RESOURCE_ATTRIBUTES`.

## Prisma Migration Baseline

This repository contains the original auth baseline migration plus an incremental hardening migration:

```text
prisma/migrations/20260603120000_auth_hardening/migration.sql
prisma/migrations/20260604103000_auth_multitenant_outbox_hardening/migration.sql
prisma/migrations/20260604113000_auth_crypto_refresh_platform_hardening/migration.sql
prisma/migrations/20260610120000_auth_production_hardening/migration.sql
prisma/migrations/20260610143000_auth_operational_hardening/migration.sql
prisma/migrations/20260610160000_auth_enterprise_foundation/migration.sql
prisma/migrations/20260610170000_refresh_idempotency_key/migration.sql
prisma/migrations/20260610180000_auth_final_guardrails/migration.sql
```

If the production database is empty, apply migrations normally:

```powershell
npx prisma migrate deploy
```

If the production database already has the same tables, baseline it first so Prisma does not try to recreate existing objects:

```powershell
npx prisma migrate resolve --applied 20260603120000_auth_hardening
npx prisma migrate resolve --applied 20260604103000_auth_multitenant_outbox_hardening
npx prisma migrate resolve --applied 20260604113000_auth_crypto_refresh_platform_hardening
npx prisma migrate resolve --applied 20260610120000_auth_production_hardening
npx prisma migrate resolve --applied 20260610143000_auth_operational_hardening
npx prisma migrate resolve --applied 20260610160000_auth_enterprise_foundation
npx prisma migrate resolve --applied 20260610170000_refresh_idempotency_key
npx prisma migrate resolve --applied 20260610180000_auth_final_guardrails
npx prisma migrate deploy
```

Do not edit an already applied migration in production. Add a new migration for future schema changes.

For local development on an empty database:

```powershell
npx prisma migrate dev
```

For CI drift checks, configure a disposable shadow database:

```env
SHADOW_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/erp_saas_shadow
```

Then verify migrations against the Prisma schema:

```powershell
npx prisma migrate diff --from-migrations prisma/migrations --to-schema-datamodel prisma/schema.prisma --shadow-database-url $env:SHADOW_DATABASE_URL --exit-code
```

## Service Architecture

The auth module keeps route/controller code thin and moves stateful auth logic into focused services:

- `session.service.ts`: login orchestration, refresh rotation and logout workflows.
- `login-lock.service.ts`: DB-backed `LoginAttempt` and `LoginLock` behavior.
- `password.service.ts`: forgot/reset/change password workflows.
- `email-verification.service.ts`: verification token and resend workflows.
- `auth.repository.ts`: shared Prisma access for users, sessions, refresh tokens and password/session revocation.

Refresh rotation remains inside `session.service.ts` because it is an atomic security workflow with several policy checks. New ERP modules should avoid direct Prisma access for auth-owned state and add repository helpers instead.

## Email Delivery

Email verification and password reset use an `EmailOutbox` table and a configured email provider. Auth flows enqueue email and do not depend on the provider being available synchronously.
Register, resend verification, and forgot-password create the auth token and outbox row in the same Prisma transaction. If the outbox insert fails, the business operation rolls back instead of leaving a user without a deliverable email.
Outbox workers claim messages atomically with `PROCESSING`, `lockedAt`, and `lockedBy` before delivery to avoid duplicate sends when multiple workers run. Stale locks are recovered after `EMAIL_OUTBOX_LOCK_TIMEOUT_MS`.
While provider delivery is running, the worker refreshes `lockedAt` every `EMAIL_OUTBOX_LOCK_HEARTBEAT_MS` so a slow provider call is not recovered as stale by another worker. `EMAIL_PROVIDER_TIMEOUT_MS` must stay below `EMAIL_OUTBOX_LOCK_TIMEOUT_MS`.
Email `text` and `html` bodies are encrypted at rest with the active `EMAIL_OUTBOX_ENCRYPTION_KEY_ID`, then scrubbed after successful delivery. New encrypted values use the `enc:v1:<keyId>:<payload>` prefix. Existing legacy `enc:v1:<payload>` rows can be migrated with the maintenance job below.
Every queued email stores a stable `messageId` and `idempotencyKey`. `EMAIL_PROVIDER=resend` sends `EmailOutbox.idempotencyKey` as Resend's `Idempotency-Key` header. Resend documents idempotency for `POST /emails` and `POST /emails/batch` over a 24-hour window: https://resend.com/docs/dashboard/emails/idempotency-keys. `EMAIL_PROVIDER=http` sends the same key through the configured idempotency header to another provider API. SMTP delivery only uses `messageId` as the `Message-ID` header, which is best-effort deduplication; production requires `EMAIL_ALLOW_SMTP_BEST_EFFORT=true` if SMTP is intentionally used. If provider delivery succeeds but the database update to `SENT` fails, the row is moved to `SENT_UNKNOWN` when possible and must be reviewed before retrying.

Required production variables:

```env
APP_URL=https://your-frontend.example.com
EMAIL_PROVIDER=resend
RESEND_API_KEY=re_replace_with_provider_key
EMAIL_PROVIDER_TIMEOUT_MS=30000
SMTP_FROM=noreply@example.com
EMAIL_OUTBOX_BATCH_SIZE=20
EMAIL_OUTBOX_LOCK_TIMEOUT_MS=600000
EMAIL_OUTBOX_LOCK_HEARTBEAT_MS=60000
EMAIL_OUTBOX_ENCRYPTION_KEY_ID=key-2026-06
EMAIL_OUTBOX_ENCRYPTION_KEY=replace-with-at-least-32-characters
EMAIL_OUTBOX_ENCRYPTION_KEYS={"key-2026-06":"replace-with-at-least-32-characters","key-2026-01":"previous-key-at-least-32-characters"}
EMAIL_OUTBOX_WORKER_ENABLED=true
EMAIL_OUTBOX_WORKER_INTERVAL_MS=60000
```

Generic HTTP providers are still supported when they provide a real idempotency key:

```env
EMAIL_PROVIDER=http
EMAIL_HTTP_API_URL=https://email-provider.example.com/send
EMAIL_HTTP_API_KEY=provider-api-key
EMAIL_HTTP_IDEMPOTENCY_HEADER=Idempotency-Key
```

SMTP remains available for simple deployments:

```env
EMAIL_PROVIDER=smtp
EMAIL_ALLOW_SMTP_BEST_EFFORT=true
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your-user
SMTP_PASS=your-password
SMTP_FROM=noreply@example.com
```

In development, if `EMAIL_PROVIDER=smtp` and `SMTP_HOST` is missing, emails are not sent and the message is logged to the console.
`EXPOSE_AUTH_TOKENS=true` is accepted only in `NODE_ENV=test`, or in `NODE_ENV=development` when `APP_URL` and every `CORS_ORIGIN` entry point to localhost.

Users can request a new verification link with:

```text
POST /api/auth/resend-verification
```

To process queued email retries:

```powershell
npm run email:outbox
```

To scrub old `SENT` bodies and encrypt legacy `PENDING`/`FAILED` rows:

```powershell
npm run email:outbox:encrypt-legacy
```

To rotate pending outbox bodies to the active key:

```powershell
npm run email:outbox:rotate-key
```

To inspect messages where provider delivery probably succeeded but the final database update failed:

```powershell
npm run email:outbox:sent-unknown
```

Treat this output as an operational dashboard seed. Do not blindly retry a `SENT_UNKNOWN` row; verify the provider message id, recipient, subject and audit trail first.

If `EMAIL_OUTBOX_WORKER_ENABLED=true`, the API process also runs a supervised inline worker. Keep only one strategy active per deployment topology: inline worker for simple deployments, external scheduled worker for separated workloads.

## CSRF And Rate Limiting

State-changing auth routes require a CSRF token:

1. `GET /api/auth/csrf-token`
2. Send the returned token in `x-csrf-token`
3. Preserve the CSRF cookie returned by Fastify

Rate limiting is configured for:

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/verify-email`
- `POST /api/auth/resend-verification`
- `POST /api/auth/forgot-password`
- `POST /api/auth/reset-password`

`POST /api/auth/login` also requires CSRF because it creates a refresh-token cookie.
Rate limiting uses Redis when `RATE_LIMIT_REDIS_URL` is configured. Production requires Redis so limits work across multiple API instances. Startup fails if Redis is configured but unavailable.

Login records append-only `LoginAttempt` rows and applies DB-backed `LoginLock` state by email/IP. Successful login resets the lock state for the email/IP identities:

```env
LOGIN_ATTEMPT_WINDOW_MS=900000
LOGIN_ATTEMPT_EMAIL_MAX=5
LOGIN_ATTEMPT_IP_MAX=20
PASSWORD_HISTORY_LIMIT=5
```

`PASSWORD_HISTORY_LIMIT` prevents users from reusing the current password or recently stored password hashes during password reset and password change. Set it to `0` only for local debugging.
`PASSWORD_PEPPER_KEY_ID` and `PASSWORD_PEPPER_KEYS` allow progressive password pepper rotation. New password hashes store the active key id; verification can still test previous keys during the rotation window. On a successful login with an older or missing pepper key id, the password hash is transparently rehashed with the active pepper key using an atomic compare-and-update.

## Observability

Requests accept `x-request-id` and `x-correlation-id` only when the value is short and header-safe. The API echoes safe IDs in responses, includes `correlationId` in error payloads, and stores it in an indexed `AuditLog.correlationId` column.
Reverse proxies should pass `x-request-id` or `x-correlation-id` from trusted clients only after applying their own length/charset limits. Frontend clients should read `x-correlation-id` from failed responses and attach it to support/error reports.
Auth audit writes also create normalized `SecurityEvent` rows for SIEM-style querying by type, severity, user, correlation ID, and timestamp. Audit and security-event persistence failures are non-blocking for user auth, but they emit structured operational error logs and increment failure counters that are covered by Prometheus alerts.

Metrics are disabled by default. Enable them only for internal scraping. `METRICS_TOKEN` is required whenever `METRICS_ENABLED=true`, including non-production environments:

```env
METRICS_ENABLED=true
METRICS_TOKEN=replace-with-at-least-16-characters
METRICS_INSTANCE_ID=api-prod-1
```

Then scrape:

```text
GET /metrics
Authorization: Bearer <METRICS_TOKEN>
```

Current metrics include:

- `erp_api_instance_info`
- `erp_audit_log_write_total`
- `erp_email_outbox_claim_total`
- `erp_email_outbox_delivery_total`
- `erp_email_outbox_recovered_total`
- `erp_email_outbox_batch_size`
- `erp_email_outbox_batch_processed`
- `erp_email_outbox_processed_total`
- `erp_security_event_total`

Alert on `erp_email_outbox_delivery_total{status="sent_unknown"}`. It means the email provider reported success but the API could not persist the final `SENT` state; retrying those rows manually can send duplicates.
The Prometheus rule is provided in `apps/api/monitoring/prometheus-alerts.yml`.

Operational failures can also be exported as structured webhook events for an internal SIEM/alert bridge:

```env
OPERATIONAL_EVENTS_WEBHOOK_URL=https://siem.example.com/events
OPERATIONAL_EVENTS_WEBHOOK_TOKEN=replace-with-at-least-16-characters
OPERATIONAL_EVENTS_TIMEOUT_MS=5000
OTEL_SERVICE_NAME=erp-api
OTEL_DEPLOYMENT_ENVIRONMENT=production
OTEL_RESOURCE_ATTRIBUTES=service.namespace=erp,team=backend
```

In multi-instance deployments these metrics are process-local. Set a stable `METRICS_INSTANCE_ID` per instance, scrape every API instance, or export them to Prometheus/OpenTelemetry through the platform collector. When metrics are enabled, all emitted samples include the configured `instance` and `node_env` default labels. Do not use one instance's `/metrics` endpoint as a global source of truth.

## Tests

Unit and smoke tests:

```powershell
npm test
```

Supply-chain gate used by CI for production/runtime dependencies:

```powershell
npm run audit:ci
```

`audit:ci` runs `npm audit --omit=dev --audit-level=high`, so high/critical runtime vulnerabilities block CI while dev tooling advisories are tracked separately.

Full dependency visibility, including dev tools:

```powershell
npm run audit:full
```

`audit:full` currently reports Prisma/Hono moderate advisories and `tsx`/`esbuild` high advisories without an upstream fix. Track them through Dependabot and upgrade Prisma/Hono/tsx/esbuild when patched versions are available.
Dependabot is configured in `.github/dependabot.yml` for `/apps/api`, grouped for Prisma and API security dependencies.

Pre-deploy auth gate for a target database after any required tenant backfill:

```powershell
npm run predeploy:auth
```

If `tenant:preflight` fails, configure `STORE_ORGANIZATION_BACKFILL_MAP`, run `npm run tenant:backfill-stores`, then rerun `npm run predeploy:auth`.

If `tenant:preflight` says `Store.organizationId` does not exist, the target DB is before the nullable tenant migration. Apply `20260604103000_auth_multitenant_outbox_hardening` first, resolve it in Prisma migration history, then run the backfill/preflight sequence.

Integration test with PostgreSQL:

```powershell
$env:RUN_DB_TESTS="true"
$env:NODE_ENV="test"
$env:DATABASE_URL="postgresql://postgres:postgres@localhost:5432/erp_saas_test"
$env:TOKEN_HASH_SECRET="test_token_hash_secret_minimum_32_chars"
$env:REFRESH_IDEMPOTENCY_SECRET="test_refresh_idempotency_secret_minimum_32_chars"
$env:EMAIL_OUTBOX_ENCRYPTION_KEY="test_email_outbox_encryption_key_minimum_32_chars"
$env:EXPOSE_AUTH_TOKENS="true"
npm run test:integration
```

Use a disposable test database. The integration test creates and deletes its own user, but it should not run against production data.
`npm run test:integration` now fails if `NODE_ENV=test`, `RUN_DB_TESTS=true`, or a safe-looking test/local `DATABASE_URL` is missing. For local smoke checks where skipped DB tests are intentional, use:

```powershell
npm run test:integration:optional
```

CI can keep using the compatibility alias below:

```powershell
npm run test:integration:db
```

## Maintenance Jobs

Remove expired auth tokens, old refresh tokens, old login attempts, and stale login locks:

```powershell
npm run tokens:cleanup
```

For simple deployments, the API can run this cleanup periodically:

```env
TOKEN_CLEANUP_WORKER_ENABLED=true
TOKEN_CLEANUP_EXTERNAL_SCHEDULED=false
TOKEN_CLEANUP_WORKER_INTERVAL_MS=3600000
```

Refresh idempotency replay payloads are encrypted and short-lived. Keep `REFRESH_IDEMPOTENCY_TTL_MS` at or below `300000`; the default is `60000`.

Before applying the tenant hardening migration on an existing database:

```powershell
$env:STORE_ORGANIZATION_BACKFILL_MAP='{"storeCode":"organizationId"}'
npm run tenant:backfill-stores
npm run tenant:preflight
```

Seed base ERP permissions:

```powershell
npx prisma db seed
```

## Token Model

- Access tokens are JWTs with a short lifetime.
- JWT signing and verification explicitly restrict the configured algorithm. `HS256` is the default; `RS256` can be enabled with `JWT_ALGORITHM=RS256`, `JWT_PRIVATE_KEY`, `JWT_KEY_ID`, and either `JWT_PUBLIC_KEY` or `JWT_PUBLIC_KEYS`.
- For zero-downtime RS256 rotation, publish the active and previous public keys in `JWT_PUBLIC_KEYS` and expose `GET /.well-known/jwks.json` to internal token validators. The active signing `kid` must stay in the keyring until all older access tokens have expired.
- Access tokens include `iss`, `aud`, and `jti`; protected routes verify those claims and reload session/user state from PostgreSQL.
- Refresh tokens are opaque random tokens stored as HMAC hashes.
- Refresh/auth token hashes use `TOKEN_HASH_SECRET`; password hashing uses `PASSWORD_PEPPER`.
- New password hashes store `passwordPepperKeyId` to support controlled pepper rotation.
- Refresh token rotation is atomic and revokes the token family when reuse is detected outside the short concurrent refresh grace window.
- Each normal refresh writes a `RefreshRotation` row for observability and controlled same-context replay handling.
- Clients can send `Idempotency-Key` or `x-idempotency-key` on `POST /api/auth/refresh`. For the same old cookie, same context and same key, the API can replay the same rotated refresh cookie for `REFRESH_IDEMPOTENCY_TTL_MS`, default 60 seconds.
- Concurrent refresh requests without an idempotency key are still tolerated for the same session context during `REFRESH_TOKEN_REUSE_GRACE_MS`, default 5 seconds, and only one grace reissue is allowed.
- Legacy password/token fallback is bounded by `LEGACY_SECRET_FALLBACK_UNTIL`; plan to remove it after migration.
- Protected routes reload the user, role and store access from PostgreSQL instead of trusting mutable JWT claims.
- Auth tokens are consumed atomically so verification/reset links cannot be used twice through concurrent requests.

## Store-Level RBAC

`User.platformRole` is reserved for platform-wide privileges. Use `SUPER_ADMIN` only for platform operators.

`User.role` remains a legacy/global business role, while `Membership.role` and `UserStoreAccess.role` support tenant and store authorization for ERP workflows.

Use `requireStoreRole("storeId", ["MANAGER", "ADMIN"])` or `requireStorePermission("storeId", "stores.write")` on store-scoped routes.
When a route contains both `organizationId` and `storeId`, add `requireStoreInOrganization("storeId", "organizationId")` before the permission guard.
RBAC guards are unit-tested through dependency injection for store permission, organization role/permission and store-organization boundary scenarios.

## Organization-Level RBAC

The schema includes `Organization` and `Membership` for multi-tenant ERP boundaries. `Store.organizationId` is mandatory after `20260610120000_auth_production_hardening`. Guards reject inactive stores and inactive organizations.

Use `requireOrganizationRole("organizationId", ["ADMIN"])` or `requireOrganizationPermission("organizationId", "users.write")` on organization-scoped routes.

## Enterprise Auth Foundation

The schema includes foundational enterprise tables that are intentionally not exposed through public routes until product rules are defined:

- `SecurityEvent`: normalized auth/security event stream for SIEM, alerting and incident search.
- `PasswordHistory`: recent password hashes used to prevent password reuse.
- `ApiKey`: hashed API key storage for future machine-to-machine integrations. Exactly one owner is allowed by database constraint, either user or organization.
- `MfaFactor` and `MfaChallenge`: MFA enrollment/challenge foundation for TOTP, WebAuthn and recovery-code flows. TOTP secrets must be stored encrypted in `encryptedSecret` with `encryptionKeyId`; do not store recoverable MFA secrets as hashes.

Do not enable API key or MFA endpoints until scopes, enrollment policy, recovery policy, lockout behavior and audit requirements are defined. Startup rejects `API_KEY_ENDPOINTS_ENABLED=true` or `MFA_ENDPOINTS_ENABLED=true` unless `AUTH_ENTERPRISE_FEATURES_POLICY_ACK=rotation-recovery-audit-rate-limit-approved` is explicitly set.

## CORS

`CORS_ORIGIN` supports a comma-separated allowlist:

```env
CORS_ORIGIN=https://app.example.com,https://admin.example.com
```
