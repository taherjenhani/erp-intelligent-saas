# Key rotation runbook

This runbook covers normal and emergency rotation for auth secrets and keyrings.

## General order

1. Add the new key to the keyring.
2. Keep the old key in the keyring.
3. Deploy readers that can verify/decrypt both old and new data.
4. Switch the active key id and active secret.
5. Rehash, re-encrypt or wait for old data to expire.
6. Remove the old key only after verification.

## Password pepper rotation

Prepare:

```env
PASSWORD_PEPPER_KEY_ID=2026-07-v1
PASSWORD_PEPPER=new_secret
PASSWORD_PEPPER_KEYS={
  "2026-07-v1":"new_secret",
  "2026-06-v1":"old_secret"
}
```

Behavior:

- Existing password hashes remain verifiable with old keys.
- Successful login can transparently rehash to the active pepper.
- New password writes use `PASSWORD_PEPPER_KEY_ID`.

Validation:

```powershell
npm test
npm run test:integration:db
```

## Token hash secret rotation

Prepare:

```env
TOKEN_HASH_SECRET_KEY_ID=2026-07-v1
TOKEN_HASH_SECRET=new_secret
TOKEN_HASH_SECRET_KEYS={
  "2026-07-v1":"new_secret",
  "2026-06-v1":"old_secret"
}
```

Behavior:

- New token hashes use `TOKEN_HASH_SECRET`.
- Existing refresh/auth token hashes remain verifiable while old keys stay in
  `TOKEN_HASH_SECRET_KEYS`.
- Keep old token hash keys until all dependent tokens expire or are revoked.

Emergency option:

```powershell
npm run tokens:cleanup
```

Then revoke active sessions if the old token hash secret is suspected
compromised.

## Legacy secret fallback deadline

`LEGACY_SECRET_FALLBACK_UNTIL` is bounded and defaults to
`2026-09-30T00:00:00.000Z`.

Before that date:

1. Confirm all production password hashes and token hashes have been migrated
   to keyring-aware secrets.
2. Run `npm run tokens:cleanup`.
3. Confirm no active refresh/auth token still depends on legacy
   `PASSWORD_PEPPER` fallback behavior.
4. Open the mandatory removal ticket for the fallback code paths in
   `src/utils/hash.ts`, `src/utils/token.ts`, and `src/utils/legacySecrets.ts`.

After that date, production should treat fallback usage as an incident and
remove the old secret path instead of extending it silently.

## Email outbox encryption key rotation

Prepare:

```env
EMAIL_OUTBOX_ENCRYPTION_KEY_ID=2026-07-v1
EMAIL_OUTBOX_ENCRYPTION_KEY=new_secret
EMAIL_OUTBOX_ENCRYPTION_KEYS={
  "2026-07-v1":"new_secret",
  "2026-06-v1":"old_secret"
}
```

Re-encrypt queued operational rows:

```powershell
npm run email:outbox:rotate-key
```

Legacy hardening:

```powershell
npm run email:outbox:encrypt-legacy
```

Do not remove the old email key until `rotate-key` reports zero remaining rows
that require the old key.

## JWT RS256 rotation

Prepare:

```env
JWT_ALGORITHM=RS256
JWT_KEY_ID=kid-2026-07
JWT_PRIVATE_KEY=<new-private-key>
JWT_PUBLIC_KEYS={
  "kid-2026-07":"<new-public-key>",
  "kid-2026-06":"<old-public-key>"
}
```

Validation:

```powershell
npm test
npm run build
```

Verify:

```powershell
curl https://api.example.com/.well-known/jwks.json
```

Remove the old public key after every access token signed by the old private key
has expired and downstream validators have refreshed JWKS.

## Rollback

If deployment fails after switching the active key:

1. Restore the previous active key id and secret.
2. Keep both keys in the keyring.
3. Restart the API.
4. Verify login, refresh and email outbox processing.
5. Investigate before removing either key.

## Emergency rotation

If a secret is suspected compromised:

1. Stop non-essential auth writes if possible.
2. Add a new key and switch active key immediately.
3. Revoke affected sessions/tokens when token secrets are involved.
4. Run email outbox rotation if email encryption key is involved.
5. Record a `SecurityEvent`/incident ticket.
6. Remove compromised keys only after dependent data is safe.

## Acceptance checklist

| Check | Required |
| --- | --- |
| Active key id in keyring | Yes |
| Active secret matches keyring value | Yes |
| Old data remains readable | Yes |
| New writes use active key | Yes |
| Rollback tested | Yes |
| Incident ticket updated | Yes |
