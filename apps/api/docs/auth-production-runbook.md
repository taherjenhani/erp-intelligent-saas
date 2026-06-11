# Auth Production Runbook

This runbook is the operational checklist for deploying the API auth module safely.

## 1. Preflight The Target Database

Run this before deploying tenant hardening migrations on an existing database:

```powershell
npm run tenant:preflight
```

If it reports that `Store.organizationId` does not exist, the target database is still before the nullable tenant migration. Apply only `20260604103000_auth_multitenant_outbox_hardening` in a controlled maintenance step, then mark it as applied before continuing:

```powershell
npx prisma db execute --file prisma/migrations/20260604103000_auth_multitenant_outbox_hardening/migration.sql
npx prisma migrate resolve --applied 20260604103000_auth_multitenant_outbox_hardening
```

If it reports stores without an organization, prepare an explicit backfill map:

```powershell
$env:STORE_ORGANIZATION_BACKFILL_MAP='{"storeCode":"organizationId"}'
npm run tenant:backfill-stores
npm run tenant:preflight
```

Do not run `npx prisma migrate deploy` on production until preflight passes.

After backfill is done, run the bundled auth gate against the same target database:

```powershell
npm run predeploy:auth
```

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

`SENT_UNKNOWN` means the email provider accepted the email but the API could not persist the final `SENT` state. Review the row manually before retrying.

For enterprise production, use `EMAIL_PROVIDER=http` with a provider/API that supports a transport-level idempotency key. SMTP with a stable `Message-ID` is only a best-effort deduplication hint and must be explicitly accepted with `EMAIL_ALLOW_SMTP_BEST_EFFORT=true`.

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
npm run test:integration:db
npm run build
```

Set `NODE_ENV=test` and `RUN_DB_TESTS=true`. `npm run test:integration` and `npm run test:integration:db` both fail fast without those guards, so DB tests cannot be accidentally skipped in CI. Use `npm run test:integration:optional` only for local smoke checks where skipped DB tests are intentional. Never point integration tests at production data.

## 6. Check Remaining Known Risks

- Metrics are in-memory per process. Scrape every instance or export through OpenTelemetry/Prometheus infrastructure.
- Set a stable `METRICS_INSTANCE_ID` for each instance so dashboards and alerts can identify which process emitted a sample.
- Email outbox encryption keys are env-managed. Move to KMS/Vault before enterprise production with strict key custody requirements.
- Configure `EMAIL_OUTBOX_LOCK_HEARTBEAT_MS` and `EMAIL_PROVIDER_TIMEOUT_MS` lower than `EMAIL_OUTBOX_LOCK_TIMEOUT_MS` so slow deliveries do not get recovered by another worker.
- Enable `TOKEN_CLEANUP_WORKER_ENABLED=true` or schedule `npm run tokens:cleanup` externally and set `TOKEN_CLEANUP_EXTERNAL_SCHEDULED=true`.
- API key and MFA tables are schema foundations only. Do not expose endpoints until rotation, recovery, lockout, audit, rate-limit and UX policies are defined.
- `npm audit --audit-level=moderate` currently reports Prisma/Hono advisories without a fix. Keep Dependabot enabled and upgrade as soon as patched versions are available.
