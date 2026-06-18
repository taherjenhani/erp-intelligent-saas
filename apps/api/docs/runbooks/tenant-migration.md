# Tenant migration runbook

This runbook protects production databases during the migration from stores
without a tenant boundary to mandatory `Store.organizationId`.

## Migration sequence

For an existing database, never jump directly to the hardening migration unless
tenant preflight already passes.

Required order:

1. Apply the nullable tenant migration.
2. Backfill every existing store.
3. Run tenant preflight until it passes.
4. Deploy the remaining Prisma migrations.

## Step 1: preflight the target DB

Run against the exact target database:

```powershell
npm run tenant:preflight
```

If the command reports that `Store.organizationId` does not exist, apply only
the nullable migration in a controlled maintenance step:

```powershell
npx prisma db execute --file prisma/migrations/20260604103000_auth_multitenant_outbox_hardening/migration.sql
npx prisma migrate resolve --applied 20260604103000_auth_multitenant_outbox_hardening
```

## Step 2: inspect stores requiring backfill

Use SQL before and after the backfill:

```sql
SELECT id, code, "organizationId"
FROM "Store"
WHERE "organizationId" IS NULL;
```

Every returned store must be mapped to an existing organization.

## Step 3: backfill

Use explicit store-to-organization mapping. Keys can be store ids or store
codes. Values can be organization ids or organization codes.

PowerShell:

```powershell
$env:STORE_ORGANIZATION_BACKFILL_MAP='{"STORE_CODE":"ORG_CODE"}'
npm run tenant:backfill-stores
npm run tenant:preflight
```

Bash:

```bash
export STORE_ORGANIZATION_BACKFILL_MAP='{"STORE_CODE":"ORG_CODE"}'
npm run tenant:backfill-stores
npm run tenant:preflight
```

Expected success:

```text
Store organization backfill completed { updated: 1, remaining: 0 }
Tenant migration preflight passed: every Store has organizationId
```

## Step 4: deploy hardening migrations

Only after preflight passes:

```powershell
npx prisma migrate deploy
```

The hardening migration intentionally refuses to continue if any store still
has `organizationId IS NULL`.

## Rollback and incident procedure

If backfill maps a store to the wrong organization:

1. Stop deployment.
2. Disable write traffic for affected tenant data.
3. Identify affected rows from audit and SQL snapshots.
4. Correct the mapping manually in a maintenance transaction.
5. Rerun `npm run tenant:preflight`.
6. Continue only after a senior reviewer validates the mapping.

If `npx prisma migrate deploy` fails because of null stores:

1. Do not retry blindly.
2. Run the SQL inspection query.
3. Complete the backfill.
4. Run `npm run tenant:preflight`.
5. Retry migration only after preflight passes.

## CI and test coverage

The integration test suite simulates a nullable `Store.organizationId`, verifies
that preflight fails while a null store exists, validates invalid backfill maps,
applies a valid backfill, and verifies that preflight passes afterwards.

Run:

```powershell
$env:RUN_DB_TESTS="true"
npm run test:integration:db
```

Never run integration tests against production data.
