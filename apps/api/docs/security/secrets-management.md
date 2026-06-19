# Secrets management policy

The auth module supports versioned keyrings through environment variables. This
is acceptable for MVP production when secrets are injected by the deployment
platform, but enterprise production should move key custody to KMS, Vault or a
cloud secret manager.

## Why environment variables are not enough for enterprise

Environment variables are easy to deploy, but they provide limited controls for:

- access review;
- key custody;
- rotation approval;
- emergency revocation;
- audit trails;
- separation of duties;
- envelope encryption.

Never commit secrets to Git. Never log secret values.

## MVP strategy

Use strong secrets injected by the deployment platform:

```env
PASSWORD_PEPPER_KEY_ID=2026-06-v1
PASSWORD_PEPPER=...
PASSWORD_PEPPER_KEYS={"2026-06-v1":"...","2026-05-v1":"..."}

TOKEN_HASH_SECRET_KEY_ID=2026-06-v1
TOKEN_HASH_SECRET=...
TOKEN_HASH_SECRET_KEYS={"2026-06-v1":"...","2026-05-v1":"..."}

EMAIL_OUTBOX_ENCRYPTION_KEY_ID=2026-06-v1
EMAIL_OUTBOX_ENCRYPTION_KEY=...
EMAIL_OUTBOX_ENCRYPTION_KEYS={"2026-06-v1":"...","2026-05-v1":"..."}

JWT_ALGORITHM=RS256
JWT_KEY_ID=kid-2026-06
JWT_PRIVATE_KEY=...
JWT_PUBLIC_KEYS={"kid-2026-06":"...","kid-2026-05":"..."}
```

Startup validation requires active key ids to exist in the matching keyring when
a keyring is configured.

## Enterprise strategy

Recommended providers:

- AWS Secrets Manager + KMS.
- Azure Key Vault.
- GCP Secret Manager + Cloud KMS.
- HashiCorp Vault.

The application should receive the same normalized keyring values at runtime,
but the source of truth should be the secret manager. This avoids binding the
code to one cloud provider before the infrastructure decision is made.

## Rotation principles

- New writes use only the active key.
- Old keys remain available for verification/decryption until data is migrated
  or expires.
- Rotation is performed in two phases: deploy readers first, then switch active
  writer.
- Emergency rotation revokes the compromised key as soon as dependent data is
  rehashed, re-encrypted or expired.

## Controls

- `PASSWORD_PEPPER_KEYS` allows old password hashes to remain verifiable.
- `TOKEN_HASH_SECRET_KEYS` allows existing refresh/auth tokens to remain
  verifiable during controlled token hash rotation.
- `EMAIL_OUTBOX_ENCRYPTION_KEYS` allows old queued outbox rows to be decrypted
  and re-encrypted with the active key.
- `JWT_PUBLIC_KEYS` allows zero-downtime RS256 public key rotation.

## Production checklist

| Control | Required |
| --- | --- |
| Secrets at least 32 characters | Yes |
| Active key id present in keyring | Yes |
| Active key value matches active env secret | Yes |
| Production placeholders rejected | Yes |
| Secret values absent from logs | Yes |
| Rotation runbook approved | Yes |
| Emergency rollback documented | Yes |
| KMS/Vault plan for enterprise | Yes |
