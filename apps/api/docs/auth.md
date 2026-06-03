# Authentication Module

## Production Checklist

- Configure `DATABASE_URL`, `JWT_ACCESS_SECRET`, `PASSWORD_PEPPER`, `CSRF_SECRET`, `APP_URL` and SMTP variables.
- Run Prisma migrations before starting the API.
- Use HTTPS in production so refresh and CSRF cookies are sent with `secure: true`.
- Run integration tests against a disposable PostgreSQL database before deploy.
- Keep `EXPOSE_AUTH_TOKENS=false` outside local development.

## Prisma Migration Baseline

This repository now contains a baseline migration generated from the current Prisma schema:

```text
prisma/migrations/20260603120000_auth_hardening/migration.sql
```

If the production database is empty, apply migrations normally:

```powershell
npx prisma migrate deploy
```

If the production database already has the same tables, baseline it first so Prisma does not try to recreate existing objects:

```powershell
npx prisma migrate resolve --applied 20260603120000_auth_hardening
npx prisma migrate deploy
```

For local development on an empty database:

```powershell
npx prisma migrate dev
```

## Email Delivery

Email verification and password reset use an `EmailOutbox` table and SMTP through `nodemailer`. Auth flows enqueue email and do not depend on SMTP being available synchronously.

Required production variables:

```env
APP_URL=https://your-frontend.example.com
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your-user
SMTP_PASS=your-password
SMTP_FROM=noreply@example.com
```

In development, if `SMTP_HOST` is missing, emails are not sent and the message is logged to the console. The API also returns tokens in non-production responses for easier local testing.

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

- `POST /api/auth/login`
- `POST /api/auth/verify-email`
- `POST /api/auth/forgot-password`
- `POST /api/auth/reset-password`

`POST /api/auth/login` also requires CSRF because it creates a refresh-token cookie.

## Tests

Unit and smoke tests:

```powershell
npm test
```

Integration test with PostgreSQL:

```powershell
$env:RUN_DB_TESTS="true"
$env:DATABASE_URL="postgresql://postgres:postgres@localhost:5432/erp_saas_test"
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
- Refresh token rotation is atomic and revokes the token family when reuse is detected.
- Protected routes reload the user, role and store access from PostgreSQL instead of trusting mutable JWT claims.

## CORS

`CORS_ORIGIN` supports a comma-separated allowlist:

```env
CORS_ORIGIN=https://app.example.com,https://admin.example.com
```
