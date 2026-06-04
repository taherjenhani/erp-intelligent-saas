# Authentication Module

## Production Checklist

- Configure `DATABASE_URL`, `JWT_ACCESS_SECRET`, `PASSWORD_PEPPER`, `TOKEN_HASH_SECRET`, `CSRF_SECRET`, `APP_URL`, `RATE_LIMIT_REDIS_URL` and SMTP variables.
- Keep `PASSWORD_PEPPER` and `TOKEN_HASH_SECRET` different. Password hashes and opaque token hashes must not share the same secret.
- Production startup fails if `CSRF_SECRET` or `TOKEN_HASH_SECRET` still uses a development default, `SMTP_HOST` is missing, `RATE_LIMIT_REDIS_URL` is missing, `APP_URL` points to a local address, or `EXPOSE_AUTH_TOKENS=true` outside the allowed local/test contexts.
- Run Prisma migrations before starting the API.
- Use HTTPS in production so refresh and CSRF cookies are sent with `secure: true`.
- Run integration tests against a disposable PostgreSQL database before deploy.
- Keep `EXPOSE_AUTH_TOKENS=false` outside automated tests and strict localhost development.
- Set `TRUST_PROXY=true` only when the API is behind a trusted reverse proxy or load balancer.

## Prisma Migration Baseline

This repository contains the original auth baseline migration plus an incremental hardening migration:

```text
prisma/migrations/20260603120000_auth_hardening/migration.sql
prisma/migrations/20260604103000_auth_multitenant_outbox_hardening/migration.sql
prisma/migrations/20260604113000_auth_crypto_refresh_platform_hardening/migration.sql
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

## Email Delivery

Email verification and password reset use an `EmailOutbox` table and SMTP through `nodemailer`. Auth flows enqueue email and do not depend on SMTP being available synchronously.
Register, resend verification, and forgot-password create the auth token and outbox row in the same Prisma transaction. If the outbox insert fails, the business operation rolls back instead of leaving a user without a deliverable email.
Outbox workers claim messages atomically with `PROCESSING`, `lockedAt`, and `lockedBy` before delivery to avoid duplicate sends when multiple workers run. Stale locks are recovered after `EMAIL_OUTBOX_LOCK_TIMEOUT_MS`.

Required production variables:

```env
APP_URL=https://your-frontend.example.com
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your-user
SMTP_PASS=your-password
SMTP_FROM=noreply@example.com
EMAIL_OUTBOX_BATCH_SIZE=20
EMAIL_OUTBOX_LOCK_TIMEOUT_MS=600000
```

In development, if `SMTP_HOST` is missing, emails are not sent and the message is logged to the console.
`EXPOSE_AUTH_TOKENS=true` is accepted only in `NODE_ENV=test`, or in `NODE_ENV=development` when `APP_URL` and every `CORS_ORIGIN` entry point to localhost.

Users can request a new verification link with:

```text
POST /api/auth/resend-verification
```

To process queued email retries:

```powershell
npm run email:outbox
```

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
Rate limiting uses Redis when `RATE_LIMIT_REDIS_URL` is configured. Production requires Redis so limits work across multiple API instances.

## Tests

Unit and smoke tests:

```powershell
npm test
```

Integration test with PostgreSQL:

```powershell
$env:RUN_DB_TESTS="true"
$env:NODE_ENV="test"
$env:DATABASE_URL="postgresql://postgres:postgres@localhost:5432/erp_saas_test"
$env:TOKEN_HASH_SECRET="test_token_hash_secret_minimum_32_chars"
$env:EXPOSE_AUTH_TOKENS="true"
npm run test:integration
```

Use a disposable test database. The integration test creates and deletes its own user, but it should not run against production data.

## Maintenance Jobs

Remove expired auth tokens and old refresh tokens:

```powershell
npm run tokens:cleanup
```

Seed base ERP permissions:

```powershell
npx prisma db seed
```

## Token Model

- Access tokens are JWTs with a short lifetime.
- Refresh tokens are opaque random tokens stored as HMAC hashes.
- Refresh/auth token hashes use `TOKEN_HASH_SECRET`; password hashing uses `PASSWORD_PEPPER`.
- Refresh token rotation is atomic and revokes the token family when reuse is detected outside the short concurrent refresh grace window.
- Concurrent refresh requests with the same old cookie are treated as idempotent for the same session context during `REFRESH_TOKEN_REUSE_GRACE_MS`.
- Protected routes reload the user, role and store access from PostgreSQL instead of trusting mutable JWT claims.
- Auth tokens are consumed atomically so verification/reset links cannot be used twice through concurrent requests.

## Store-Level RBAC

`User.platformRole` is reserved for platform-wide privileges. Use `SUPER_ADMIN` only for platform operators.

`User.role` remains a legacy/global business role, while `Membership.role` and `UserStoreAccess.role` support tenant and store authorization for ERP workflows.

Use `requireStoreRole("storeId", ["MANAGER", "ADMIN"])` or `requireStorePermission("storeId", "stores.write")` on store-scoped routes.
When a route contains both `organizationId` and `storeId`, add `requireStoreInOrganization("storeId", "organizationId")` before the permission guard.

## Organization-Level RBAC

The schema includes `Organization` and `Membership` for multi-tenant ERP boundaries. `Store.organizationId` is optional for compatibility with existing data, but new tenant-aware stores should belong to an organization.

Use `requireOrganizationRole("organizationId", ["ADMIN"])` or `requireOrganizationPermission("organizationId", "users.write")` on organization-scoped routes.

## CORS

`CORS_ORIGIN` supports a comma-separated allowlist:

```env
CORS_ORIGIN=https://app.example.com,https://admin.example.com
```
