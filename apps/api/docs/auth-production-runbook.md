# Auth Production Runbook

This runbook is the operational checklist for deploying the API auth module safely.

## 1. Preflight The Target Database

Run this before deploying tenant hardening migrations on an existing database:

```powershell
npm run tenant:preflight
```

If it reports stores without an organization, prepare an explicit backfill map:

```powershell
$env:STORE_ORGANIZATION_BACKFILL_MAP='{"storeCode":"organizationId"}'
npm run tenant:backfill-stores
npm run tenant:preflight
```

Do not run `npx prisma migrate deploy` on production until preflight passes.

## 2. Apply Migrations

For an empty database:

```powershell
npx prisma migrate deploy
```

For an existing aligned database, baseline already-created migrations with `npx prisma migrate resolve --applied <migration_name>`, then run deploy.

## 3. Harden Email Outbox Data

Before enabling workers on a database with legacy rows:

```powershell
npm run email:outbox:encrypt-legacy
npm run email:outbox:rotate-key
```

The legacy encryption job scrubs old `SENT` bodies and encrypts old `PENDING`/`FAILED` bodies. The rotation job re-encrypts pending operational rows with the active key id.

## 4. Configure Outbox Alerts

Install `apps/api/monitoring/prometheus-alerts.yml` in Prometheus or the platform alert manager.

`SENT_UNKNOWN` means SMTP accepted the email but the API could not persist the final `SENT` state. Review the row manually before retrying, because SMTP `Message-ID` helps deduplication but is not a hard idempotency guarantee for every provider.

## 5. Run CI-Equivalent Validation

Use a disposable PostgreSQL database and run:

```powershell
npm run audit:ci
npx prisma migrate deploy
npx prisma db seed
npm run tenant:preflight
npm run email:outbox:encrypt-legacy
npx prisma validate
npm test
npm run test:integration
npm run build
```

Set `RUN_DB_TESTS=true` and never point integration tests at production data.

## 6. Check Remaining Known Risks

- Metrics are in-memory per process. Scrape every instance or export through OpenTelemetry/Prometheus infrastructure.
- Email outbox encryption keys are env-managed. Move to KMS/Vault before enterprise production with strict key custody requirements.
- API key and MFA tables are schema foundations only. Do not expose endpoints until rotation, recovery, lockout, audit, rate-limit and UX policies are defined.
- `npm audit --audit-level=moderate` currently reports Prisma/Hono advisories without a fix. Keep Dependabot enabled and upgrade as soon as patched versions are available.
