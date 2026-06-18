# Email provider runbook

The auth module sends verification and password reset emails through the email
outbox. Delivery must be durable, observable and idempotent at provider level
when possible.

## Production recommendation

Prefer an API provider with a documented idempotency key contract:

```env
EMAIL_PROVIDER=resend
RESEND_API_KEY=...
SMTP_FROM=noreply@example.com
OPERATIONAL_EVENTS_WEBHOOK_URL=https://ops.example.com/auth-events
OPERATIONAL_EVENTS_WEBHOOK_TOKEN=...
```

Alternative provider:

```env
EMAIL_PROVIDER=http
EMAIL_HTTP_API_URL=https://provider.example.com/send
EMAIL_HTTP_API_KEY=...
EMAIL_HTTP_IDEMPOTENCY_HEADER=Idempotency-Key
```

The HTTP provider must guarantee that repeated requests with the same
idempotency key do not create duplicate emails.

## SMTP risk acknowledgement

SMTP is not strictly idempotent. A stable `Message-ID` helps provider-side
deduplication, but it is only a best-effort hint.

Production startup refuses SMTP unless the risk is explicitly accepted:

```env
EMAIL_PROVIDER=smtp
SMTP_HOST=smtp.example.com
EMAIL_ALLOW_SMTP_BEST_EFFORT=true
```

Do not set this flag unless the business owner accepts possible duplicate
delivery after partial failures.

## Outbox states

- `PENDING`: queued and ready.
- `PROCESSING`: claimed by a worker.
- `SENT`: provider success persisted; sensitive body scrubbed.
- `FAILED`: terminal failure after retries.
- `SENT_UNKNOWN`: provider accepted the email, but the API could not persist
  the final `SENT` state.

## SENT_UNKNOWN incident procedure

List incidents:

```powershell
npm run email:outbox:sent-unknown
```

For each row:

1. Open the provider dashboard.
2. Search by `providerMessageId`, `messageId` or idempotency key.
3. Confirm whether the provider delivered the email.
4. If delivered, do not resend. Mark the incident resolved in the operational
   tracker and archive the row according to the DB maintenance procedure.
5. If not delivered, reset the row to `PENDING` in a controlled maintenance
   window after senior approval.

Never blindly retry `SENT_UNKNOWN`.

## Timeout policy

`EMAIL_PROVIDER_TIMEOUT_MS` must be lower than
`EMAIL_OUTBOX_LOCK_TIMEOUT_MS`. The lock heartbeat must also be lower than the
lock timeout so slow provider calls are not recovered by another worker.

Required startup checks already enforce:

- `EMAIL_PROVIDER_TIMEOUT_MS < EMAIL_OUTBOX_LOCK_TIMEOUT_MS`
- `EMAIL_OUTBOX_LOCK_HEARTBEAT_MS < EMAIL_OUTBOX_LOCK_TIMEOUT_MS`

## Monitoring

Alert on:

- `email_delivery_state_persistence_failed`
- `email_sent_unknown_persistence_failed`
- `email_delivery_failed`
- `email_outbox_heartbeat_failed`
- Any non-empty output from `npm run email:outbox:sent-unknown`

Recommended operational event target:

```env
OPERATIONAL_EVENTS_WEBHOOK_URL=https://ops.example.com/auth-events
OPERATIONAL_EVENTS_WEBHOOK_TOKEN=...
```

## Validation

Before production:

```powershell
npm test
npm run test:integration:db
```

Provider contract validation:

1. Send two sandbox requests with the same idempotency key.
2. Confirm the provider returns the same message or suppresses duplicate
   delivery according to its documentation.
3. Save the evidence in the deployment ticket.
