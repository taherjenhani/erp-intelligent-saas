-- Final auth guardrails: strict API key ownership, MFA encrypted-secret shape,
-- provider idempotency key storage, and password pepper key metadata.

ALTER TABLE "User"
  ADD COLUMN "passwordPepperKeyId" TEXT;

ALTER TABLE "PasswordHistory"
  ADD COLUMN "passwordPepperKeyId" TEXT;

ALTER TABLE "EmailOutbox"
  ADD COLUMN "idempotencyKey" TEXT;

UPDATE "EmailOutbox"
SET "idempotencyKey" = "messageId"
WHERE "idempotencyKey" IS NULL;

ALTER TABLE "EmailOutbox"
  ALTER COLUMN "idempotencyKey" SET NOT NULL;

CREATE UNIQUE INDEX "EmailOutbox_idempotencyKey_key"
  ON "EmailOutbox"("idempotencyKey");

ALTER TABLE "ApiKey"
  DROP CONSTRAINT IF EXISTS "ApiKey_owner_check";

ALTER TABLE "ApiKey"
  ADD CONSTRAINT "ApiKey_owner_xor_check"
  CHECK (
    ("userId" IS NOT NULL AND "organizationId" IS NULL)
    OR ("userId" IS NULL AND "organizationId" IS NOT NULL)
  );

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM "MfaFactor"
    WHERE "secretHash" IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'MfaFactor.secretHash contains data. Migrate MFA secrets to encryptedSecret before applying 20260610180000_auth_final_guardrails';
  END IF;
END $$;

ALTER TABLE "MfaFactor"
  ADD COLUMN "encryptedSecret" TEXT,
  ADD COLUMN "encryptionKeyId" TEXT;

ALTER TABLE "MfaFactor"
  DROP COLUMN "secretHash";
