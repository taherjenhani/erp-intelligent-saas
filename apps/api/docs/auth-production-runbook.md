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

List pending manual cases:

```powershell
npm run email:outbox:sent-unknown
```

For each row, compare `messageId`, `idempotencyKey`, `providerMessageId`, recipient and subject with the provider dashboard before retrying. If the provider confirms delivery, mark or archive the row manually according to the incident procedure. If the provider confirms no delivery, reset it to `PENDING` in a controlled maintenance window.

For enterprise production, use `EMAIL_PROVIDER=resend` or `EMAIL_PROVIDER=http` with a provider/API that supports a transport-level idempotency key. Resend supports the `Idempotency-Key` header for `POST /emails` and `POST /emails/batch` during a 24-hour window: https://resend.com/docs/dashboard/emails/idempotency-keys. SMTP with a stable `Message-ID` is only a best-effort deduplication hint and must be explicitly accepted with `EMAIL_ALLOW_SMTP_BEST_EFFORT=true`.

Recommended Resend configuration:

```env
EMAIL_PROVIDER=resend
RESEND_API_KEY=re_replace_with_provider_key
SMTP_FROM=noreply@example.com
EMAIL_PROVIDER_TIMEOUT_MS=30000
```

## 5. Run CI-Equivalent Validation

Use a disposable PostgreSQL database and run:

```powershell
npm run audit:ci
npm run audit:full
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

`npm run audit:ci` blocks high/critical runtime vulnerabilities with `--omit=dev`. `npm run audit:full` keeps visibility on development tooling advisories, including `tsx`/`esbuild`, but may fail while upstream has no patched release.

## 6. Check Remaining Known Risks

- Metrics are in-memory per process. Scrape every instance or export through OpenTelemetry/Prometheus infrastructure.
- Set a stable `METRICS_INSTANCE_ID` for each instance; emitted samples include `instance` and `node_env` labels after the metrics plugin is enabled.
- Forward operational events to an internal alert/SIEM bridge with `OPERATIONAL_EVENTS_WEBHOOK_URL`, `OPERATIONAL_EVENTS_WEBHOOK_TOKEN`, `OTEL_SERVICE_NAME`, `OTEL_DEPLOYMENT_ENVIRONMENT`, and `OTEL_RESOURCE_ATTRIBUTES`.
- Keep the provided audit/security-event failure alerts active. Audit writes are best-effort for auth availability, so alerting is the production safety net when persistence fails.
- Email outbox encryption keys are env-managed. Move to KMS/Vault before enterprise production with strict key custody requirements.
- Configure `EMAIL_OUTBOX_LOCK_HEARTBEAT_MS` and `EMAIL_PROVIDER_TIMEOUT_MS` lower than `EMAIL_OUTBOX_LOCK_TIMEOUT_MS` so slow deliveries do not get recovered by another worker.
- Enable `TOKEN_CLEANUP_WORKER_ENABLED=true` or schedule `npm run tokens:cleanup` externally and set `TOKEN_CLEANUP_EXTERNAL_SCHEDULED=true`.
- API key and MFA tables are schema foundations only. Do not expose endpoints until rotation, recovery, lockout, audit, rate-limit and UX policies are defined.
- Keep `API_KEY_ENDPOINTS_ENABLED=false` and `MFA_ENDPOINTS_ENABLED=false` until the policy is approved. If a future release needs them, startup requires `AUTH_ENTERPRISE_FEATURES_POLICY_ACK=rotation-recovery-audit-rate-limit-approved`.
- For RS256 deployments, keep current and previous public keys in `JWT_PUBLIC_KEYS`, sign only with `JWT_KEY_ID`, and verify external validators against `GET /.well-known/jwks.json` before rotating out old keys.
- If the API serves Swagger, HTML docs or static web content, set `SERVE_WEB_CONTENT=true` and `HELMET_CSP_ENABLED=true` before deployment.
- `npm run audit:full` currently reports Prisma/Hono advisories and `tsx`/`esbuild` advisories without a fix. Keep Dependabot enabled and upgrade as soon as patched versions are available.

## 7. Enforce GitHub Branch Protection

Protect `develop` and `main` before accepting production changes:

- Require a pull request before merging.
- Require status checks to pass before merging.
- Require the API CI check from `.github/workflows/api-ci.yml` (`api`) and require branches to be up to date.
- Require conversation resolution.
- Block force pushes and branch deletion.
- Keep Dependabot alerts enabled for `/apps/api`.

The repository includes `.github/branch-protection-develop.json` as a machine-readable starting point for GitHub admins. Apply it only after confirming the exact status-check name shown by GitHub for the latest API CI run.
