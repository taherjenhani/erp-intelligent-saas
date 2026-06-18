# MFA and API keys activation policy

MFA and API key database foundations exist, but endpoints must stay disabled
until the complete security policy is implemented and tested.

Safe defaults:

```env
API_KEY_ENDPOINTS_ENABLED=false
MFA_ENDPOINTS_ENABLED=false
AUTH_ENTERPRISE_FEATURES_POLICY_ACK=
```

Startup accepts activation only with the exact acknowledgement:

```env
AUTH_ENTERPRISE_FEATURES_POLICY_ACK=rotation-recovery-audit-rate-limit-approved
```

This acknowledgement is not enough by itself. It only confirms that the policy
below has been approved and implemented.

## Why endpoints are disabled

Premature MFA or API key exposure can create high-risk account takeover or
tenant-isolation issues:

- MFA without recovery can lock users out.
- MFA without rate limiting can be brute-forced.
- API keys without rotation and scopes become long-lived bearer secrets.
- API keys without tenant isolation can cross organization boundaries.
- Missing audit logs make incidents hard to investigate.

## Minimum MFA requirements

- Secure TOTP enrollment with re-authentication.
- Encrypted TOTP secret using the approved keyring/KMS strategy.
- Short-lived challenge records.
- Rate limit on challenge verification.
- Recovery codes hashed at rest.
- Recovery code regeneration and revocation.
- Factor disable/revoke flow.
- Audit events for enroll, verify, fail, disable, recovery use.
- Protection against brute force and replay.
- Step-up MFA before changing MFA settings.
- Integration tests with PostgreSQL.

## Minimum API key requirements

- API key shown only once at creation.
- Key stored only as a hash.
- Non-secret prefix for lookup and support.
- Expiration date.
- Rotation endpoint.
- Revocation endpoint.
- Scopes/permissions.
- Tenant isolation by organization/user ownership.
- `lastUsedAt` update.
- Audit events for create, use, rotate, revoke, expire.
- Rate limiting.
- Suspicious usage detection.
- Integration tests with PostgreSQL.

## Security matrix

| Feature | Required before activation | Status now |
| --- | --- | --- |
| MFA TOTP enrollment | Required | Not exposed |
| MFA encrypted secret | Required | Schema ready |
| MFA recovery codes | Required | Not implemented |
| MFA verify rate-limit | Required | Not implemented |
| API key hash storage | Required | Schema ready |
| API key scopes | Required | Schema ready as JSON |
| API key rotation | Required | Not implemented |
| API key revocation | Required | Schema ready |
| Tenant isolation tests | Required | Not implemented for endpoints |
| Audit events | Required | Event enum ready |

## Tests required before activation

- App refuses startup when MFA is enabled without exact ACK.
- App refuses startup when API keys are enabled without exact ACK.
- MFA routes are not exposed by default.
- API key routes are not exposed by default.
- Enrollment, verification, recovery and revocation tests.
- API key create, authenticate, rotate, revoke and expire tests.
- Abuse tests for rate limits and brute force.

## Activation checklist

Do not enable either feature until every item is complete:

- Product recovery UX approved.
- Security review approved.
- Threat model updated.
- PostgreSQL integration tests passing.
- Audit dashboard updated.
- Rate limits configured.
- Incident runbook updated.
- Key rotation runbook updated.
